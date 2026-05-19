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
