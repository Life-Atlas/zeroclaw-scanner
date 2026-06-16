# Security Scan Report — `lifeatlas/boardy-agents`

**Scanners run:** Auth Scanner · Pattern Scanner · Dependency Scanner · Secret Scanner

## Findings Summary

| Scanner | High | Medium | Low | Total |
|---|---|---|---|---|
| Auth Scanner | 5 | 0 | 0 | 5 |
| Pattern Scanner | 17 | 0 | 0 | 17 |
| Dependency Scanner | 0 | 18 | 0 | 18 |
| Secret Scanner | 0 | 0 | 0 | 0 |
| **Total** | **22** | **18** | **0** | **40** |

---

## 🔴 Auth Scanner — 5 findings (High)

Unprotected FastAPI routes — no `Depends(...)` security dependency on the route, meaning the endpoint can be called without authentication.

**Where:** `backend/main.py`

| Route | Line | Notes |
|---|---|---|
| `trigger_call` | 39 | Handles user data — needs auth |
| `webhook` | 137 | Handles user data — needs auth |
| `get_status` | 219 | Handles user data — needs auth (priority) |
| `health` | 228 | OK to leave open (standard health check) |
| `query_network` | 233 | Handles user data — needs auth (priority) |

**Why it matters:** 4 of these 5 endpoints return or accept user-specific data with zero access control — anyone who can reach the API can call them.

---

## 🟡 Pattern Scanner — 17 findings (High)

XSS risk via `innerHTML` assignment.

**Where:** `frontend/index.html` (17 occurrences)

**Why it's flagged:** Assigning to `.innerHTML` lets injected HTML/JS execute in the page context. The scanner flags every occurrence as High by default since it can't determine the data source.

**Breakdown:**
- Most occurrences are static SVG icon strings — low real risk since the content is hardcoded, not user-controlled.
- **Lines 727–733** are the standout: the error UI is built from `e.message` derived from the `/trigger-call` response (`data.message || data.detail`). If the backend ever echoes attacker-influenced text in that response, this becomes a **reflected XSS** path. Not urgent, but worth a follow-up review.

---

## ⚪ Dependency Scanner — 18 findings (Medium)

**Where:** `requirements.txt`

| Issue | Count | Why it's there |
|---|---|---|
| Unpinned (`>=`) dependencies | 17 | Floating version specifiers (e.g. `supabase`, `fastapi`, `torch`, `pipecat-ai`, etc.) allow automatic updates that can silently pull in a vulnerable or malicious release without review. |
| Missing hash verification | 1 | `requirements.txt` has no `--hash=sha256:...` entries, so there's no cryptographic guarantee the installed package matches what was reviewed — a compromised mirror/DNS hijack could substitute a malicious package. |

**Remediation:** Pin all deps to exact versions and regenerate the lockfile with `pip-compile --generate-hashes`.

---

## ✅ Secret Scanner — 0 findings

Clean — no hardcoded credentials, API keys, or tokens detected.

---

**Priority order for fixes:** Auth (`get_status` / `query_network` / `webhook` / `trigger_call`) → Pattern (lines 727–733 only) → Dependency hardening.
