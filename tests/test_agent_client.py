"""Tests for the ZeroClaw Agent Client — mock-based, no Rust binary needed."""
import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from zeroclaw.agent_client import ZeroClawClient
from zeroclaw.models import Category, Finding, Severity


@pytest.fixture
def sample_finding():
    """A typical raw scanner finding for enrichment testing."""
    return Finding(
        id="PATTERN-0001",
        severity=Severity.HIGH,
        category=Category.CODE_PATTERN,
        title="Possible SQL injection (f-string in execute)",
        description="Possible SQL injection at line 3: cursor.execute(f\"SELECT...\")",
        file_path="database.py",
        remediation="Use parameterized queries or safe DOM APIs.",
        line_number=3,
    )


@pytest.fixture
def sample_file(tmp_path):
    """A dummy vulnerable file for context loading."""
    f = tmp_path / "database.py"
    f.write_text(
        'def get_user(cursor, user_id):\n'
        '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        '    return cursor.fetchone()\n',
        encoding="utf-8",
    )
    return f


class TestZeroClawClient:
    """Tests for the ZeroClawClient bridge."""

    def test_prompt_template_loads(self):
        """The client should load the remediation.txt prompt without error."""
        client = ZeroClawClient()
        assert "ZeroClaw" in client.system_prompt
        assert "reasoning_chain" in client.system_prompt

    @patch("zeroclaw.agent_client.subprocess.run")
    def test_successful_enrichment(self, mock_run, sample_finding, sample_file):
        """On success, reasoning_chain and fixed_code should be populated."""
        mock_run.return_value = MagicMock(
            stdout=json.dumps({
                "reasoning_chain": "The f-string interpolation allows SQL injection.",
                "fixed_code": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            }),
            returncode=0,
        )

        client = ZeroClawClient()
        enriched = client.enrich_finding(sample_finding, sample_file)

        assert enriched.reasoning_chain == "The f-string interpolation allows SQL injection."
        assert enriched.fixed_code == 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        mock_run.assert_called_once()

    @patch("zeroclaw.agent_client.subprocess.run")
    def test_agent_not_installed_fallback(self, mock_run, sample_finding, sample_file):
        """If zeroclaw binary is not found, should fall back gracefully."""
        mock_run.side_effect = FileNotFoundError("zeroclaw not found")

        client = ZeroClawClient()
        enriched = client.enrich_finding(sample_finding, sample_file)

        assert enriched.reasoning_chain is not None
        assert "not installed" in enriched.reasoning_chain
        # fixed_code should remain None (not set by fallback)
        assert enriched.fixed_code is None

    @patch("zeroclaw.agent_client.subprocess.run")
    def test_agent_timeout_fallback(self, mock_run, sample_finding, sample_file):
        """If agent times out, should fall back gracefully."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="zeroclaw", timeout=30)

        client = ZeroClawClient()
        enriched = client.enrich_finding(sample_finding, sample_file)

        assert enriched.reasoning_chain is not None
        assert "timed out" in enriched.reasoning_chain

    @patch("zeroclaw.agent_client.subprocess.run")
    def test_agent_error_fallback(self, mock_run, sample_finding, sample_file):
        """If agent returns non-zero exit, should fall back gracefully."""
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="zeroclaw", stderr="internal error"
        )

        client = ZeroClawClient()
        enriched = client.enrich_finding(sample_finding, sample_file)

        assert enriched.reasoning_chain is not None
        assert "non-zero" in enriched.reasoning_chain

    @patch("zeroclaw.agent_client.subprocess.run")
    def test_invalid_json_fallback(self, mock_run, sample_finding, sample_file):
        """If agent returns non-JSON output, should fall back gracefully."""
        mock_run.return_value = MagicMock(
            stdout="This is not valid JSON at all",
            returncode=0,
        )

        client = ZeroClawClient()
        enriched = client.enrich_finding(sample_finding, sample_file)

        assert enriched.reasoning_chain is not None
        assert "invalid JSON" in enriched.reasoning_chain

    def test_file_context_reading(self, tmp_path):
        """Should read file content for prompt context."""
        f = tmp_path / "test.py"
        f.write_text("print('hello')", encoding="utf-8")

        context = ZeroClawClient._read_file_context(f)
        assert "print('hello')" in context

    def test_file_context_missing_file(self, tmp_path):
        """Should return fallback when file doesn't exist."""
        missing = tmp_path / "nonexistent.py"
        context = ZeroClawClient._read_file_context(missing)
        assert "Could not load" in context

    def test_enrichment_preserves_original_fields(self, sample_finding, sample_file):
        """Enrichment should NOT modify the original scanner fields."""
        original_id = sample_finding.id
        original_title = sample_finding.title
        original_severity = sample_finding.severity

        with patch("zeroclaw.agent_client.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("not installed")
            client = ZeroClawClient()
            enriched = client.enrich_finding(sample_finding, sample_file)

        assert enriched.id == original_id
        assert enriched.title == original_title
        assert enriched.severity == original_severity


class TestFindingModelBackwardCompat:
    """Ensure the new Optional fields don't break existing Finding construction."""

    def test_finding_without_enrichment_fields(self):
        """Creating a Finding without enrichment fields should work (backward compat)."""
        f = Finding(
            id="TEST-001",
            severity=Severity.HIGH,
            category=Category.SECRET,
            title="Test finding",
            description="Test",
            file_path="test.py",
            remediation="Fix it",
        )
        assert f.reasoning_chain is None
        assert f.fixed_code is None

    def test_finding_with_enrichment_fields(self):
        """Creating a Finding WITH enrichment fields should also work."""
        f = Finding(
            id="TEST-002",
            severity=Severity.CRITICAL,
            category=Category.INJECTION,
            title="SQL Injection",
            description="Bad query",
            file_path="db.py",
            remediation="Use parameterized queries",
            reasoning_chain="The query uses string concatenation...",
            fixed_code='cursor.execute("SELECT ...", (param,))',
        )
        assert f.reasoning_chain == "The query uses string concatenation..."
        assert f.fixed_code == 'cursor.execute("SELECT ...", (param,))'
