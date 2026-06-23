from pathlib import Path
import pytest
from zeroclaw.scanners.auth_scanner import scan_fastapi_auth, scan_supabase_rls
from zeroclaw.models import Category, Severity


class TestAuthScanner:
    def test_detects_unprotected_endpoints(self, tmp_path):
        """Should detect endpoints that do not have Depends or Security parameters."""
        file = tmp_path / "routes.py"
        file.write_text('''
@router.post("/auth/login")
async def auth_login():
    return {"status": "ok"}

@app.get("/users/{user_id}")
def get_user(user_id: str):
    return {"user_id": user_id}
''')
        findings = scan_fastapi_auth(tmp_path)
        assert len(findings) == 2
        
        # Verify first finding
        assert findings[0].category == Category.AUTH
        assert findings[0].severity == Severity.HIGH
        assert findings[0].line_number == 2
        assert "auth_login" in findings[0].description
        
        # Verify second finding
        assert findings[1].line_number == 6
        assert "get_user" in findings[1].description

    def test_ignores_protected_endpoints(self, tmp_path):
        """Should ignore routes that contain Depends or Security in their signature or decorator."""
        file = tmp_path / "routes.py"
        file.write_text('''
@router.post("/auth/logout")
async def auth_logout(admin: AdminContext = Depends(_admin_dep)):
    return {"status": "ok"}

@router.get("/users", dependencies=[Depends(_admin_dep)])
async def users_list():
    return []

@app.get("/secure")
def secure_route(api_key: str = Security(api_key_header)):
    return {"status": "secure"}
''')
        findings = scan_fastapi_auth(tmp_path)
        assert len(findings) == 0

    def test_unreadable_file_logged(self, tmp_path, caplog):
        """Should log warning when file cannot be read due to OS error."""
        import logging
        from unittest.mock import patch
        
        bad_file = tmp_path / "unreadable.py"
        bad_file.write_text("@app.get('/unprotected')\ndef bad_route(): pass")
        
        with patch("os.open", side_effect=PermissionError("Mocked permission error")):
            with caplog.at_level(logging.WARNING):
                findings = scan_fastapi_auth(tmp_path)
                assert len(findings) == 0
                
        warnings = [rec.message for rec in caplog.records if rec.levelno == logging.WARNING]
        assert any("Could not read file" in w and "Mocked permission error" in w for w in warnings)

    def test_large_file_skipped(self, tmp_path):
        """Should skip scanning files that exceed the 5MB size limit."""
        large_file = tmp_path / "large.py"
        large_file.write_text("@app.get('/unprotected')\ndef bad(): pass" + (" " * 5 * 1024 * 1024))
        findings = scan_fastapi_auth(tmp_path)
        assert len(findings) == 0

    def test_path_traversal_prevention(self, tmp_path):
        """Should prevent scanning files resolving outside the target boundary."""
        from unittest.mock import MagicMock, patch
        from pathlib import Path
        
        file_mock = MagicMock(spec=Path)
        file_mock.is_symlink.return_value = False
        file_mock.is_file.return_value = True
        file_mock.suffix = ".py"
        file_mock.resolve.return_value = Path("C:/Windows") if Path("C:/").exists() else Path("/etc")
        file_mock.stat.return_value.st_size = 100
        
        with patch.object(Path, "rglob", return_value=[file_mock]):
            findings = scan_fastapi_auth(tmp_path)
            assert len(findings) == 0

    def test_comment_bypass_prevented(self, tmp_path):
        """Should detect unprotected endpoint even if comments or string literals contain 'Depends'."""
        file = tmp_path / "routes.py"
        file.write_text('''
@router.post("/auth/login")
async def auth_login():
    # This is a comment containing Depends() or Security()
    dummy = "Depends(auth_provider)"
    return {"status": "ok"}
''')
        findings = scan_fastapi_auth(tmp_path)
        assert len(findings) == 1
        assert findings[0].line_number == 2
        assert "auth_login" in findings[0].description

    def test_relative_target_dir_no_value_error(self, tmp_path):
        """Should support relative Path objects without raising a ValueError on relative_to."""
        file = tmp_path / "routes.py"
        file.write_text('''
@router.get("/unprotected")
def unprotected():
    pass
''')
        import os
        # Change current working directory to parent of tmp_path to make a relative path
        old_cwd = os.getcwd()
        os.chdir(tmp_path.parent)
        try:
            relative_path = Path(tmp_path.name)
            # This should not raise ValueError
            findings = scan_fastapi_auth(relative_path)
            assert len(findings) == 1
            assert findings[0].file_path == "routes.py"
        finally:
            os.chdir(old_cwd)


class TestSupabaseRLSScanner:
    def test_detects_missing_rls(self, tmp_path):
        """Should detect created tables that do not have RLS enabled."""
        file = tmp_path / "migration.sql"
        file.write_text('''
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email TEXT
);

CREATE TABLE IF EXISTS posts (
    id SERIAL PRIMARY KEY,
    title TEXT
);
''')
        findings = scan_supabase_rls(tmp_path)
        assert len(findings) == 2
        
        assert findings[0].category == Category.AUTH
        assert findings[0].severity == Severity.HIGH
        assert "users" in findings[0].description
        assert findings[0].line_number == 2

        assert "posts" in findings[1].description
        assert findings[1].line_number == 7

    def test_ignores_enabled_rls(self, tmp_path):
        """Should ignore tables that have RLS enabled in the SQL file."""
        file = tmp_path / "migration.sql"
        file.write_text('''
CREATE TABLE users (
    id UUID PRIMARY KEY
);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
''')
        findings = scan_supabase_rls(tmp_path)
        assert len(findings) == 0

    def test_supabase_rls_mixed_case_and_formatting(self, tmp_path):
        """Should correctly handle formatting changes, newlines, and case insensitivity."""
        file = tmp_path / "migration.sql"
        file.write_text('''
Create Table "Users" (
    id UUID PRIMARY KEY
);

Alter Table "users"
  Enable Row Level Security;
''')
        findings = scan_supabase_rls(tmp_path)
        assert len(findings) == 0
