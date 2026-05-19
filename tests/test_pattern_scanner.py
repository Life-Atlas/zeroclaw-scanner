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
