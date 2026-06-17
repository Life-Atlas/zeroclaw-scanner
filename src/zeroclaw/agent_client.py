"""ZeroClaw Agent Client — bridge between Python scanners and the Rust agent.

Adapted from QA_Agent/auditor.py. Sends raw scanner findings to the locally-
installed ZeroClaw Rust binary for AI-powered reasoning and remediation.
Falls back gracefully when the agent is unavailable.
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from .models import Finding

logger = logging.getLogger(__name__)

# Maximum seconds to wait for the Rust agent per finding
_AGENT_TIMEOUT_SECONDS = 30

# Maximum bytes of source code context to send (prevents massive prompts)
_MAX_CONTEXT_BYTES = 50_000  # ~50 KB


class ZeroClawClient:
    """Sends findings to the ZeroClaw Rust agent for AI enrichment."""

    def __init__(self) -> None:
        prompt_path = Path(__file__).parent / "prompts" / "remediation.txt"
        try:
            self.system_prompt = prompt_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            logger.warning("Prompt template not found at %s — using inline fallback", prompt_path)
            self.system_prompt = (
                "You are a security remediation engine. Analyze the vulnerability "
                "and respond in JSON with 'reasoning_chain' and 'fixed_code' fields."
            )

    def enrich_finding(self, finding: Finding, file_path: Path) -> Finding:
        """Send a raw finding to the ZeroClaw Rust Agent for remediation.

        Args:
            finding: The raw scanner finding to enrich.
            file_path: Absolute path to the file containing the vulnerability.

        Returns:
            The same finding, enriched with reasoning_chain and fixed_code
            if the agent is available. Falls back silently on failure.
        """
        # 1. Extract code context (bounded to prevent huge prompts)
        code_context = self._read_file_context(file_path)

        # 2. Build the query
        query = (
            f"Vulnerability ID: {finding.id}\n"
            f"Severity: {finding.severity.value}\n"
            f"Category: {finding.category.value}\n"
            f"Title: {finding.title}\n"
            f"Description: {finding.description}\n"
            f"File: {file_path}\n"
            f"Line: {finding.line_number or 'N/A'}\n"
            f"\n--- Source Code ---\n{code_context}"
        )

        # 3. Call the ZeroClaw Rust Agent via CLI
        try:
            result = subprocess.run(
                ["zeroclaw", "chat", "--system", self.system_prompt, "--prompt", query],
                capture_output=True,
                text=True,
                check=True,
                timeout=_AGENT_TIMEOUT_SECONDS,
            )

            # 4. Parse the JSON response
            response_data = json.loads(result.stdout.strip())

            # 5. Enrich the finding
            finding.reasoning_chain = response_data.get(
                "reasoning_chain", "Agent returned no reasoning."
            )
            finding.fixed_code = response_data.get("fixed_code", "")

            logger.info("Enriched finding %s via ZeroClaw agent", finding.id)

        except FileNotFoundError:
            # ZeroClaw binary not installed
            finding.reasoning_chain = (
                "ZeroClaw agent not installed. Run: "
                "curl -fsSL https://raw.githubusercontent.com/zeroclaw-labs/zeroclaw/master/install.sh | bash"
            )
            logger.warning("ZeroClaw binary not found — skipping enrichment for %s", finding.id)

        except subprocess.TimeoutExpired:
            finding.reasoning_chain = (
                f"ZeroClaw agent timed out after {_AGENT_TIMEOUT_SECONDS}s. "
                "Raw scanner output only."
            )
            logger.warning("ZeroClaw agent timed out for finding %s", finding.id)

        except subprocess.CalledProcessError as e:
            finding.reasoning_chain = (
                f"ZeroClaw agent returned non-zero exit code. "
                f"stderr: {e.stderr[:200] if e.stderr else 'N/A'}"
            )
            logger.warning("ZeroClaw agent error for %s: %s", finding.id, e)

        except json.JSONDecodeError as e:
            finding.reasoning_chain = (
                f"ZeroClaw agent returned invalid JSON. Parse error: {e}"
            )
            logger.warning("Invalid JSON from ZeroClaw agent for %s: %s", finding.id, e)

        except Exception as e:
            # Catch-all: never crash the pipeline
            finding.reasoning_chain = (
                f"ZeroClaw agent unavailable. Raw scanner output only. Error: {e}"
            )
            logger.warning("Unexpected error enriching %s: %s", finding.id, e)

        return finding

    @staticmethod
    def _read_file_context(file_path: Path) -> str:
        """Read file content bounded to _MAX_CONTEXT_BYTES."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            if len(content) > _MAX_CONTEXT_BYTES:
                return content[:_MAX_CONTEXT_BYTES] + "\n... [truncated]"
            return content
        except Exception:
            return "Could not load file context."
