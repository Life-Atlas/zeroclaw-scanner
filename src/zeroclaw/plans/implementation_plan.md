# ZeroClaw Agent Enrichment Layer Integration

Integrate the ZeroClaw Rust agent as an AI-powered enrichment layer between the existing static scanners (pattern, dependency, secret, auth) and the reporter. This implements the **Sidecar Pattern**: fast regex scanners filter noise, then only meaningful findings get sent to the ZeroClaw agent for deep reasoning and remediation code generation.

## Proposed Changes

### Data Model — Enrichment Fields

#### [MODIFY] [models.py](file:///d:/Naman/Internship/Atlas/Security/zeroclaw-scanner/src/zeroclaw/models.py)

Add two `Optional` fields to the existing `Finding` model so the AI enrichment layer can attach its output without breaking existing scanner code or tests:

- `reasoning_chain: Optional[str]` — the agent's step-by-step vulnerability analysis
- `fixed_code: Optional[str]` — the agent's remediated code snippet

Both default to `None`, so all existing tests that construct `Finding(...)` without these fields continue to pass unchanged.

---

### Agent Prompt Template

#### [NEW] [remediation.txt](file:///d:/Naman/Internship/Atlas/Security/zeroclaw-scanner/src/zeroclaw/prompts/remediation.txt)

System prompt template for the ZeroClaw Rust agent, adapted from the QA_Agent's `prompt_architecture_auditor.txt`. Instructs the agent to:
- Analyze the vulnerability and its code context
- Produce a `reasoning_chain` explaining *why* the code is vulnerable
- Produce `fixed_code` with the actual patch
- Respond strictly in JSON matching the expected schema

---

### Agent Client — The Bridge

#### [NEW] [agent_client.py](file:///d:/Naman/Internship/Atlas/Security/zeroclaw-scanner/src/zeroclaw/agent_client.py)

Adapted from `auditor.py`. Core class `ZeroClawClient` with:

- `__init__()` — loads the prompt template from `prompts/remediation.txt`
- `enrich_finding(finding, file_path)` — builds context from the finding + source file, calls the ZeroClaw Rust binary via `subprocess.run(["zeroclaw", "chat", ...])`, parses JSON response, and injects `reasoning_chain` + `fixed_code` into the finding
- **Resilient fallback**: if the Rust agent is unavailable (not installed, crashes, timeout), the finding passes through with a fallback message — the pipeline never fails due to agent unavailability
- Configurable timeout (default 30s per finding)

---

### CLI Orchestrator — The Intelligence Loop

#### [MODIFY] [cli.py](file:///d:/Naman/Internship/Atlas/Security/zeroclaw-scanner/src/zeroclaw/cli.py)

Replace the placeholder `scan` command with the full 3-phase pipeline:

1. **Gathering Phase** — run all four scanners (pattern, dependency, secret, auth) against the target directory
2. **Enrichment Phase** — for `CRITICAL`, `HIGH`, and `MEDIUM` severity findings, call `ZeroClawClient.enrich_finding()` to get AI reasoning and fixed code
3. **Reporting Phase** — pass enriched findings to `generate_terminal_report()` or `generate_json_report()`

Also adds a `--no-enrich` flag to skip the AI enrichment step (useful for CI speed runs or when the Rust agent isn't installed).

Also adds a `--stream` passthrough to tag findings with the intern stream label.

---

### Reporter — Surface Enriched Data

#### [MODIFY] [reporter.py](file:///d:/Naman/Internship/Atlas/Security/zeroclaw-scanner/src/zeroclaw/reporter.py)

Implement `generate_terminal_report()` and `generate_json_report()` with support for the new enrichment fields. The terminal report uses Rich for colored output with sections for:
- Executive summary with severity counts
- Per-finding detail blocks including reasoning chain and fixed code (when available)

The JSON report serializes the full `ScanResult` model including enrichment data.

---

### Tests — Mock Agent Coverage

#### [NEW] [test_agent_client.py](file:///d:/Naman/Internship/Atlas/Security/zeroclaw-scanner/tests/test_agent_client.py)

Mock-based tests that verify:
- Prompt template loads correctly
- Successful enrichment populates `reasoning_chain` and `fixed_code`
- Agent failure (subprocess error) falls back gracefully without crashing
- `LOW`/`INFO` severity findings are not sent to the agent (tested via CLI integration)

All tests use `unittest.mock.patch` to mock `subprocess.run` — no actual Rust binary or network calls needed.

---

## Open Questions

> [!IMPORTANT]
> **ZeroClaw CLI interface**: The plan assumes `zeroclaw chat --system "..." --prompt "..."` is the correct CLI invocation for the Rust agent. Please confirm the exact command syntax, or let me know if it exposes a local HTTP API instead (in which case I'll use `httpx` which is already a dependency).

> [!NOTE]
> **Severity threshold**: The plan enriches `CRITICAL`, `HIGH`, and `MEDIUM` findings. Should `LOW` findings also be enriched, or is skipping them the right call for compute efficiency?

## Verification Plan

### Automated Tests
```bash
# From the zeroclaw-scanner root:
pytest tests/ -v --tb=short
```

All existing tests must continue to pass (the new `Optional` fields don't break them). The new `test_agent_client.py` tests verify the bridge logic with mocked subprocess calls.

### Manual Verification
1. Install the ZeroClaw Rust agent: `curl -fsSL https://raw.githubusercontent.com/zeroclaw-labs/zeroclaw/master/install.sh | bash`
2. Run a live scan: `python -m zeroclaw.cli scan --target ./tests`
3. Verify enriched findings appear with `reasoning_chain` and `fixed_code` populated
4. Run with `--no-enrich` to confirm raw scanner output still works
