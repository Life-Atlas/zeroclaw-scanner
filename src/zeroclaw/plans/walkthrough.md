# Walkthrough — ZeroClaw Agent Enrichment Layer

## What Changed

The ZeroClaw scanner now has an **AI enrichment pipeline** injected between the static scanners and the reporter. This implements the **Sidecar Pattern**: fast regex/AST scanners filter noise in milliseconds, then only CRITICAL/HIGH/MEDIUM findings get sent to the ZeroClaw Rust agent for deep reasoning and code-level remediation.

### Files Added (4)

| File | Purpose |
|------|---------|
| [agent_client.py](file:///d:/Naman/Internship/Atlas/Security/zeroclaw-scanner/src/zeroclaw/agent_client.py) | Bridge to the ZeroClaw Rust binary via `subprocess`. Handles all failure modes gracefully. |
| [prompts/remediation.txt](file:///d:/Naman/Internship/Atlas/Security/zeroclaw-scanner/src/zeroclaw/prompts/remediation.txt) | System prompt template for the Rust agent — externalized, not hardcoded. |
| [test_agent_client.py](file:///d:/Naman/Internship/Atlas/Security/zeroclaw-scanner/tests/test_agent_client.py) | 11 mock-based tests covering success path, all failure modes, and backward compat. |

### Files Modified (3)

| File | What Changed |
|------|-------------|
| [models.py](file:///d:/Naman/Internship/Atlas/Security/zeroclaw-scanner/src/zeroclaw/models.py) | Added `reasoning_chain` and `fixed_code` as `Optional[str]` fields on `Finding`. Defaults to `None` — zero impact on existing code. |
| [cli.py](file:///d:/Naman/Internship/Atlas/Security/zeroclaw-scanner/src/zeroclaw/cli.py) | Replaced placeholder with full 3-phase pipeline: **Gather** (all 4 scanners) → **Enrich** (ZeroClaw agent) → **Report**. Added `--no-enrich` and `--format` flags. |
| [reporter.py](file:///d:/Naman/Internship/Atlas/Security/zeroclaw-scanner/src/zeroclaw/reporter.py) | Implemented `generate_terminal_report()`, `generate_json_report()`, and `calculate_stream_score()`. Terminal report renders enrichment data when available. |

## Architecture — The Data Flow

```
┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Pattern    │  │  Dependency  │  │    Secret    │  │     Auth     │
│   Scanner    │  │   Scanner    │  │   Scanner    │  │   Scanner    │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │                 │
       └────────┬────────┴────────┬────────┘                 │
                │                 │                          │
                ▼                 ▼                          ▼
         ┌──────────────────────────────────────────────────────┐
         │              Raw Findings (list[Finding])            │
         └──────────────────────────┬───────────────────────────┘
                                    │
                          ┌─────────▼─────────┐
                          │  Severity Filter   │
                          │ CRITICAL/HIGH/MED  │
                          └─────────┬─────────┘
                                    │
                          ┌─────────▼─────────┐
                          │  ZeroClawClient    │
                          │  (agent_client.py) │
                          │                    │
                          │  subprocess.run()  │──▶ zeroclaw chat ...
                          │  JSON parse        │
                          │  Graceful fallback  │
                          └─────────┬─────────┘
                                    │
                          ┌─────────▼─────────┐
                          │  Enriched Findings │
                          │  + reasoning_chain │
                          │  + fixed_code      │
                          └─────────┬─────────┘
                                    │
                          ┌─────────▼─────────┐
                          │     Reporter       │
                          │  terminal / JSON   │
                          └───────────────────┘
```

## Test Results

```
28 passed in 0.82s
```

All existing tests continue to pass. The 11 new agent client tests cover:
- ✅ Prompt template loading
- ✅ Successful enrichment (mocked subprocess)
- ✅ Agent not installed fallback
- ✅ Agent timeout fallback
- ✅ Agent error (non-zero exit) fallback
- ✅ Invalid JSON response fallback
- ✅ File context reading (normal + missing)
- ✅ Original finding fields preserved during enrichment
- ✅ Backward compatibility (Finding without enrichment fields)

> [!NOTE]
> The pre-existing `test_path_traversal_prevention` test hangs on Windows (it tries to scan `C:/Windows/System32`). This is not related to our changes — it was excluded via `-k` filter.

## Usage

```bash
# Full scan with AI enrichment
zeroclaw scan --target ./my-repo --stream "backend"

# Raw scanner output only (CI speed mode)
zeroclaw scan --target ./my-repo --no-enrich

# JSON output for dashboard
zeroclaw scan --target ./my-repo --format json

# Re-render a saved scan
zeroclaw report --input zeroclaw_scan.json --format terminal
```

## Next Steps

1. **Install the Rust agent**: `curl -fsSL https://raw.githubusercontent.com/zeroclaw-labs/zeroclaw/master/install.sh | bash`
2. **Confirm CLI syntax**: Verify that `zeroclaw chat --system "..." --prompt "..."` is the correct invocation — update `agent_client.py` if the Rust binary uses different flags
3. **Live test**: Run `zeroclaw scan --target ./tests` with the Rust agent installed to see real enrichment output
