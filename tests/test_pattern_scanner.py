"""Tests for code pattern scanner — Phase 2 gate criteria.

Varshit owns making these pass.
"""
from zeroclaw.scanners.pattern_scanner import scan_patterns


class TestPatternScanner:
    def test_finds_sql_injection(self, vulnerable_repo):
        """Should detect f-string in cursor.execute()."""
        findings = scan_patterns(vulnerable_repo)
        sqli = [
            f for f in findings
            if "sql" in f.title.lower() or "injection" in f.title.lower()
        ]
        assert len(sqli) >= 1

    def test_finds_xss(self, vulnerable_repo):
        """Should detect innerHTML assignment."""
        findings = scan_patterns(vulnerable_repo)
        xss = [
            f for f in findings
            if "xss" in f.title.lower() or "innerHTML" in f.title.lower()
        ]
        assert len(xss) >= 1

    def test_ignores_safe_patterns(self, clean_repo):
        """Should NOT flag parameterized queries."""
        findings = scan_patterns(clean_repo)
        assert len(findings) == 0

    def test_finding_has_line_number(self, vulnerable_repo):
        """Findings should include line number for easy fixing."""
        findings = scan_patterns(vulnerable_repo)
        for f in findings:
            assert f.line_number is not None, f"Finding {f.id} missing line number"

    def test_xss_in_frontend_templates(self, tmp_path):
        """Should detect XSS patterns in HTML, Vue, and Svelte templates."""
        html_file = tmp_path / "index.html"
        html_file.write_text("<div>element.innerHTML = 'bad'</div>")
        
        vue_file = tmp_path / "App.vue"
        vue_file.write_text("<div dangerouslySetInnerHTML={unsafe} />")
        
        svelte_file = tmp_path / "App.svelte"
        svelte_file.write_text("<script>document.write('unsafe')</script>")
        
        findings = scan_patterns(tmp_path)
        assert len(findings) >= 3

    def test_unreadable_file_logged(self, tmp_path, caplog):
        """Should log a warning message when a file cannot be read due to OS error."""
        import logging
        from unittest.mock import patch
        
        bad_file = tmp_path / "unreadable.py"
        bad_file.write_text("execute(f'SELECT *')")
        
        with patch("os.open", side_effect=PermissionError("Mocked permission error")):
            with caplog.at_level(logging.WARNING):
                findings = scan_patterns(tmp_path)
                assert len(findings) == 0
                
        warnings = [rec.message for rec in caplog.records if rec.levelno == logging.WARNING]
        assert any("Could not read file" in w and "Mocked permission error" in w for w in warnings)

    def test_large_file_skipped(self, tmp_path):
        """Should skip scanning files that exceed the 5MB size limit."""
        large_file = tmp_path / "large.py"
        large_file.write_text("execute(f'SELECT *')" + (" " * 5 * 1024 * 1024))
        findings = scan_patterns(tmp_path)
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
            findings = scan_patterns(tmp_path)
            assert len(findings) == 0

    def test_multiline_command_injection(self, tmp_path):
        """Should detect multi-line subprocess execution with shell=True."""
        cmd_file = tmp_path / "command.py"
        cmd_file.write_text(
            "subprocess.run(\n"
            "    ['ls', '-l'],\n"
            "    shell=True\n"
            ")\n"
        )
        findings = scan_patterns(tmp_path)
        assert len(findings) == 1
        assert "Command injection" in findings[0].title

    def test_is_safe_bypass_prevented(self, tmp_path):
        """Should detect dangerous patterns even if safe-looking comments are present on the same line."""
        bypass_file = tmp_path / "bypass.html"
        bypass_file.write_text("el.innerHTML = bad; // .textContent = safe\n")
        findings = scan_patterns(tmp_path)
        assert len(findings) == 1
        assert "XSS risk" in findings[0].title

    def test_long_line_bypass_prevented(self, tmp_path):
        """Should detect dangerous patterns on lines exceeding MAX_LINE_LENGTH by truncating them."""
        long_line_file = tmp_path / "long_line.js"
        payload = "element.innerHTML = bad;" + (" " * 3000) + "\n"
        long_line_file.write_text(payload)
        findings = scan_patterns(tmp_path)
        assert len(findings) == 1
        assert "XSS risk" in findings[0].title



