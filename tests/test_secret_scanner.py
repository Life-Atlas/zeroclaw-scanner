"""Tests for secret scanner — Phase 2 gate criteria.

Kailash owns making these pass.
"""
from zeroclaw.scanners.secret_scanner import scan_secrets


class TestSecretScanner:
    def test_finds_api_key(self, vulnerable_repo):
        """Should detect hardcoded API key in config.py."""
        findings = scan_secrets(vulnerable_repo)
        secret_findings = [f for f in findings if "API" in f.title or "key" in f.title.lower()]
        assert len(secret_findings) >= 1

    def test_finds_password(self, vulnerable_repo):
        """Should detect hardcoded password."""
        findings = scan_secrets(vulnerable_repo)
        pwd_findings = [
            f for f in findings
            if "password" in f.title.lower() or "secret" in f.title.lower()
        ]
        assert len(pwd_findings) >= 1

    def test_finds_env_file(self, vulnerable_repo):
        """Should flag .env file with secrets."""
        findings = scan_secrets(vulnerable_repo)
        env_findings = [f for f in findings if ".env" in f.file_path]
        assert len(env_findings) >= 1

    def test_no_false_positives_on_clean(self, clean_repo):
        """Should NOT flag env var lookups as secrets."""
        findings = scan_secrets(clean_repo)
        assert len(findings) == 0

    def test_finding_has_remediation(self, vulnerable_repo):
        """Every finding should include remediation guidance."""
        findings = scan_secrets(vulnerable_repo)
        for f in findings:
            assert f.remediation, f"Finding {f.id} missing remediation"

    def test_finding_has_file_path(self, vulnerable_repo):
        """Every finding should reference the file where it was found."""
        findings = scan_secrets(vulnerable_repo)
        for f in findings:
            assert f.file_path, f"Finding {f.id} missing file_path"

    def test_path_traversal_prevention(self):
        """Should raise ValueError for paths outside safe directories (traversal attempt)."""
        import os
        import pytest
        from pathlib import Path
        outside_path = Path("C:/Windows/System32") if os.name == "nt" else Path("/etc")
        with pytest.raises(ValueError, match="Path traversal detected"):
            scan_secrets(outside_path)

    def test_large_file_skipped(self, tmp_path):
        """Should skip scanning files that are larger than 5MB."""
        large_file = tmp_path / "large.txt"
        large_file.write_text("A" * (5 * 1024 * 1024 + 1024))
        findings = scan_secrets(tmp_path)
        assert len(findings) == 0

    def test_comment_bypass_mitigated(self, tmp_path):
        """Should detect secrets even if they have inline comments mimicking env lookups."""
        config_file = tmp_path / "config.py"
        config_file.write_text(
            'API_KEY = "sk-ant-api03-reallyLongFakeKeyThatShouldBeDetected1234567890" # fallback to getenv\n'
            'PASSWORD = "super_secret_password_123" // os.environ.get\n'
            'DB_PASSWORD = "super_secret_password_456" -- process.env\n'
        )
        findings = scan_secrets(tmp_path)
        assert len(findings) == 3

    def test_default_fallback_token_detected(self, tmp_path):
        """Should detect high-confidence tokens even when used as default/fallback values in env lookups."""
        config_file = tmp_path / "config.py"
        config_file.write_text(
            'API_KEY = os.getenv("API_KEY", "sk-ant-api03-reallyLongFakeKeyThatShouldBeDetected1234567890")\n'
        )
        findings = scan_secrets(tmp_path)
        assert len(findings) == 1
        assert "Anthropic API key" in findings[0].title

    def test_unreadable_file_logged(self, tmp_path, capsys):
        """Should log a warning message when a file cannot be read."""
        from unittest.mock import patch
        unreadable_file = tmp_path / "unreadable.py"
        unreadable_file.write_text("API_KEY = 'sk-ant-12345678901234567890'")
        
        with patch("builtins.open", side_effect=PermissionError("Mocked permission error")):
            findings = scan_secrets(tmp_path)
            assert len(findings) == 0
            
        captured = capsys.readouterr()
        assert "WARNING: Could not read file" in captured.out
        assert "Mocked permission error" in captured.out


