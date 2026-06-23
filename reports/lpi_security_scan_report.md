# Security Scan Report — `LPI Platform`

**Scanners run:** Auth Scanner · Pattern Scanner · Dependency Scanner · Secret Scanner

## Findings Summary

| Scanner | High | Medium | Low | Total |
|---|---|---|---|---|
| Auth Scanner | 9 | 0 | 0 | 9 |
| Pattern Scanner | 0 | 0 | 0 | 0 |
| Dependency Scanner | 0 | 7 | 0 | 7 |
| Secret Scanner | 0 | 0 | 0 | 0 |
| **Total** | **9** | **7** | **0** | **16** |

---

## 🔴 Auth Scanner — 9 findings (High)

Unprotected FastAPI routes — no `Depends(...)` security dependency on the route, meaning the endpoint can be called without authentication.

**Where:** `src\lpi\routers\goals.py`, `src\lpi\routers\recommendations.py`, `src\lpi\routers\signals.py`, `src\lpi\main.py`

| Route | Line | Notes |
|---|---|---|
| `goals` | 32, 59, 82, 99, 160 | Handles user goal data — needs auth |
| `recommendations` | 8 | Handles user recommendations — needs auth |
| `signals` | 8, 14 | Handles user signals — needs auth |
| `main` | 16 | Review required — if health check, can stay open; otherwise needs auth |

**Why it matters:** Routes handling goals, recommendations, and signals deal with user-specific data with zero access control — anyone who can reach the API can call them.

---

## 🟢 Pattern Scanner — 0 findings

Clean — no dangerous code patterns detected.

---

## 🟡 Dependency Scanner — 7 findings (Medium)

**Where:** `pyproject.toml`

| Issue | Count | Why it's there |
|---|---|---|
| Unpinned (`>=`) dependencies | 7 | Floating version specifiers (`fastapi`, `uvicorn`, `pydantic`, `pydantic-settings`, `supabase`, `httpx`, `python-dotenv`) allow automatic updates that can silently pull in a vulnerable or malicious release without review. |

**Remediation:** Pin all deps to exact versions and regenerate the lockfile with `pip-compile --generate-hashes`.

---

## ✅ Secret Scanner — 0 findings

Clean — no hardcoded credentials, API keys, or tokens detected.

---

**Priority order for fixes:** Auth (all 8 user-data routes + review `main.py` line 16) → Dependency hardening.
