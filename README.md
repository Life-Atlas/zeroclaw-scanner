# ZeroClaw Scanner

Automated security scanning for LifeAtlas intern streams.

## Quick Start

```bash
pip install -e ".[dev]"
make test    # run test suite
make scan    # scan current directory
make report  # generate report
```

## Scanners

| Scanner | What | Owner | Phase |
|---------|------|-------|-------|
| Secret | API keys, tokens, passwords | Kailash | 2 |
| Dependency | CVEs in npm/pip packages | Sania | 2 |
| Pattern | SQLi, XSS, unsafe code | Varshit | 2 |
| Auth | Missing auth, RLS gaps | Kailash | 3 |
| Reporter | Terminal + JSON output | Varshit/Sania | 4 |

## Architecture

```
Target Repo → Secret Scanner     ─┐
            → Dependency Scanner  ─┤→ Findings (JSON) → Terminal Report
            → Pattern Scanner     ─┤                  → JSON Report
            → Auth Scanner       ─┘                  → Stream Score (0-10)
```

## TDD Gates

Each scanner is a `NotImplementedError` with failing tests. Progress is tracked by making
tests pass — not by lines of code written.

```
make test   # see which gates are red
```

## CI

GitHub Actions on every push/PR to `main` and `staging`. Lint + typecheck + test.
Jobs cancel on new push (concurrency group). No minutes wasted on stale runs.
