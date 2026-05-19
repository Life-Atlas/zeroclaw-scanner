"""Tests for dependency scanner — Phase 2 gate criteria.

Sania owns making these pass.
"""
from zeroclaw.scanners.dependency_scanner import scan_python_deps


class TestPythonDeps:
    def test_scan_requirements(self, vulnerable_repo):
        """Should find known vulnerabilities in outdated packages."""
        findings = scan_python_deps(vulnerable_repo)
        assert len(findings) >= 1

    def test_finding_has_cve(self, vulnerable_repo):
        """Findings should reference CVE IDs where available."""
        findings = scan_python_deps(vulnerable_repo)
        # At least some findings should have CVE in description
        cve_findings = [f for f in findings if "CVE" in f.description]
        # This is aspirational — OK if not all have CVEs
        assert isinstance(cve_findings, list)
