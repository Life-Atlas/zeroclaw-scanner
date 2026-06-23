# Deep Scan Mapping — Varshit

**Date:** 2026-05-27  
**Mapped by:** Varshit Pratap Singh  
**Source report:** SECURITY_DEEP_SCAN_REPORT.md (sent by John)  
**Repos checked:**
- github.com/LifeAtlas/zeroclaw-la-fork
- github.com/LifeAtlas/claw-auth-proxy
- github.com/Life-Atlas/zeroclaw-scanner

---

## 1. jspdf@2.5.2 (Critical)
- **Repo:** zeroclaw-la-fork
- **File checked:** package.json
- **Status:** NOT FOUND — library not used in this repo

---

## 2. pdfjs-dist@3.11.174 (Critical)
- **Repo:** zeroclaw-la-fork
- **File checked:** package.json
- **Status:** NOT FOUND — library not used in this repo

---

## 3. Docker using "latest" image tag (Medium)
- **Repo:** zeroclaw-la-fork
- **File checked:** docker-compose.yml
- **Status:** EXISTS
- **Evidence:** `image: ghcr.io/zeroclaw-labs/zeroclaw:latest`

- **Repo:** claw-auth-proxy
- **File checked:** docker-compose.yml
- **Status:** EXISTS
- **Evidence:**
  - `image: tecnativa/docker-socket-proxy:latest`
  - `image: lifeatlas/claw-proxy:latest`

---

## 4. send-feedback function — no authentication (Critical)
- **Repo:** claw-auth-proxy
- **Status:** NOT FOUND — no supabase/functions folder exists in this repo

---

## 5. upload-file — no size limit (High)
- **Repo:** claw-auth-proxy
- **Status:** NOT FOUND — no supabase/functions folder exists in this repo

---

## 6. google-maps-autocomplete — unauthenticated (High)
- **Repo:** claw-auth-proxy
- **Status:** NOT FOUND — no supabase/functions folder exists in this repo

---

## 7. Network mode — ZeroClaw containers publicly exposed (Medium)
- **Repo:** claw-auth-proxy
- **File checked:** docker-compose.yml
- **Status:** SAFE — ZEROCLAW_NETWORK_MODE is set to `shared` (internal only)

---

## 8. Vulnerable Python dependencies (Medium)
- **Repo:** zeroclaw-scanner
- **File checked:** pyproject.toml
- **Status:** NOT FOUND — all dependencies are clean

---

## Summary

| Vulnerability | Repo | Status |
|---|---|---|
| jspdf@2.5.2 | zeroclaw-la-fork | Not found |
| pdfjs-dist@3.11.174 | zeroclaw-la-fork | Not found |
| Docker latest tag | zeroclaw-la-fork | EXISTS |
| Docker latest tag | claw-auth-proxy | EXISTS |
| send-feedback no auth | claw-auth-proxy | Not found |
| upload-file no size limit | claw-auth-proxy | Not found |
| Network mode unsafe | claw-auth-proxy | Safe |
| Vulnerable Python deps | zeroclaw-scanner | Not found |

---

## Key Finding
Only one confirmed vulnerability exists across all 3 repos:
**Docker images using mutable `latest` tags** — found in both zeroclaw-la-fork and claw-auth-proxy.