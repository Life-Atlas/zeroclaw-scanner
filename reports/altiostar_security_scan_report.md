# Security Scan Report — `Altiostar`

**Scanners run:** Auth Scanner · Pattern Scanner · Dependency Scanner · Secret Scanner

## Findings Summary

| Scanner | High | Medium | Low | Total |
|---|---|---|---|---|
| Auth Scanner | 0 | 0 | 0 | 0 |
| Pattern Scanner | 0 | 0 | 0 | 0 |
| Dependency Scanner | 0 | 24 | 0 | 24 |
| Secret Scanner | 0 | 0 | 0 | 0 |
| **Total** | **0** | **24** | **0** | **24** |

---

## ✅ Auth Scanner — 0 findings

Clean — no unprotected FastAPI routes detected.

---

## 🟢 Pattern Scanner — 0 findings

Clean — no dangerous code patterns detected.

---

## 🟡 Dependency Scanner — 24 findings (Medium)

**Where:** `requirements.txt` and `pyproject.toml`

| Issue | Count | Why it's there |
|---|---|---|
| Unpinned (`>=`) dependencies in `requirements.txt` | 14 | Floating version specifiers (`gymnasium`, `stable-baselines3`, `pydantic`, `mlflow`, `optuna`, `torch`, `streamlit`, `pandas`, `numpy`, `pyarrow` etc.) allow automatic updates that can silently pull in a vulnerable or malicious release without review. |
| Missing hash verification in `requirements.txt` | 1 | No `--hash=sha256:...` entries — no cryptographic guarantee the installed package matches what was reviewed. A compromised mirror or DNS hijack could substitute a malicious package. |
| Overlapping unpinned dependencies in `pyproject.toml` | 10 | Same set of unpinned deps duplicated in `pyproject.toml`, compounding the supply-chain risk. |

**Remediation:** Pin all deps to exact versions across both files and regenerate the lockfile with `pip-compile --generate-hashes`.

---

## ✅ Secret Scanner — 0 findings

Clean — no hardcoded credentials, API keys, or tokens detected.

---

**Priority order for fixes:** Dependency hardening (`requirements.txt` hash verification first, then pin all versions in both `requirements.txt` and `pyproject.toml`).
