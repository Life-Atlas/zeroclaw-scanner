def test_imports():
    from zeroclaw.models import Finding, Severity

    assert Finding is not None
    assert Severity.CRITICAL == "critical"


def test_finding_model():
    from zeroclaw.models import Category, Finding, Severity

    f = Finding(
        id="TEST-001",
        severity=Severity.HIGH,
        category=Category.SECRET,
        title="Test finding",
        description="Test",
        file_path="test.py",
        remediation="Fix it",
    )
    assert f.severity == Severity.HIGH
