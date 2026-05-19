# Contributing to ZeroClaw Scanner

## Golden Rule

**Never exploit — only detect.** Report, don't break.

## Protocol

1. Read the failing test for your scanner
2. Implement the scanner to pass those tests
3. Run against test fixtures: `make test`
4. Run against real repos: `make scan`
5. Commit, push, open a PR to `staging`

## Daily Report

Create `reports/YYYY-MM-DD.md` from the template each day. Include scanner stats and blockers.

## Setup

```bash
git clone https://github.com/Life-Atlas/zeroclaw-scanner.git
cd zeroclaw-scanner
pip install -e ".[dev]"
make test
```

## Ownership Map

| Scanner | Owner | Phase |
|---------|-------|-------|
| `secret_scanner.py` | Kailash | 2 |
| `dependency_scanner.py` | Sania | 2 |
| `pattern_scanner.py` | Varshit | 2 |
| `auth_scanner.py` | Kailash | 3 |
| `reporter.py` (score) | Sania | 4 |
| `reporter.py` (output) | Varshit | 4 |

## TDD Contract

Each scanner has a test file with failing tests. Your job: make them green. No cheating with
`return []` on the `clean_repo` fixture — the tests check false positive rate too.

Red -> Green -> Refactor. In that order.
