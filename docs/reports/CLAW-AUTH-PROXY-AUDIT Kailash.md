# Security Audit & Code Validation Report: claw-auth-proxy

**Date:** 2026-05-26  
**Author:** Kailash  
**Stream:** Stream 5 — Security (ZeroClaw)  
**Target:** `claw-auth-proxy` codebase  

---

## 1. Executive Summary & Code Validation

This audit performs a systematic code-level validation of the findings raised in `CLAW_AUTH_PROXY_SECURITY_REPORT.md` against the actual implementation within the `claw-auth-proxy` repository. The proxy is a critical high-trust boundary service. While it implements several robust controls—such as running the proxy container as a non-root user (`USER 65534:65534`), validating Supabase JWTs on browser WS connect, and encrypting container bearer tokens at rest—several structural and architectural risks remain.

---

## 2. Admin API Exposure Validation

### Finding: Operations Control Plane & Exposure
*   **Report Claim:** The admin plane (`/claw-admin/*`) is highly powerful, managing container lifecycles, configs, workspace files, static tokens, and batch jobs. WebAuthn/passkey auth challenge encoding is broken because `options.challenge` returns as Python bytes, preventing standard WebAuthn registration/login.
*   **Code Validation:** 
    *   **CONFIRMED (Admin Endpoint Scope):** `claw_proxy/admin/routes.py` (lines 50–727) defines comprehensive endpoints for managing containers (`GET /containers`, `POST /containers/{user_id}/start`, `DELETE /containers/{user_id}`), listing orphans, retrofitting skills, managing static tokens, and scheduling batch config/restarts.
    *   **CONFIRMED (Auth Guard Middleware):** Every operations route is strictly gated by the `Depends(_admin_dep)` dependency, which invokes `require_admin` in `claw_proxy/admin/auth.py` (lines 177–194). This checks both session JWTs and static tokens hashed with `bcrypt.checkpw()`.
    *   **CONFIRMED (JWT Challenge Bytes Bug):** In `claw_proxy/admin/auth.py` (line 98), `start_registration` and `start_login` return the raw bytes challenge `options.challenge`. The REST endpoint `POST /auth/login` caches this in the in-memory dict `challenges["login"] = challenge`. However, WebAuthn standard serializations require the challenge to be a base64url-encoded string, causing client-side rejection.
    *   **🚨 CRITICAL GAP DISCOVERED (Unimplemented WebAuthn Verification):** While the report flags the challenge encoding as a bug, it missed a much larger issue: **The passkey verification and registration endpoints are entirely missing/unimplemented in `routes.py`**. There are NO endpoints (e.g., `/auth/login/complete` or `/auth/register/complete`) to verify the signature payloads returned by browsers, invoke `verify_login()`/`verify_registration()`, or issue admin session JWTs. As a result, passkey auth is 100% dead code, forcing total operational reliance on static admin tokens.

---

## 3. Container Isolation Validation

### Finding: Container Isolation Boundaries & Privileges
*   **Report Claim:** ZeroClaw containers support a safer `shared` network mode. Docker API access is proxied via a socket proxy but remains a high-value compromise path. Docker lifecycle loops lack inactive container stop logic.
*   **Code Validation:**
    *   **CONFIRMED (Network Isolation Modes):** `claw_proxy/containers/orchestrator.py` (lines 386–390) implements both modes. In `shared` mode, container DNS binds strictly to `run_kwargs["network"] = self.network_name` (internal `lifeatlas-net`). In `host` mode, it publishes ports dynamically, bypassing network boundaries.
    *   **CONFIRMED (Docker-Socket-Proxy Bounds):** In `docker-compose.yml` (lines 11–26), `docker-socket-proxy` uses the `tecnativa/docker-socket-proxy:latest` image. It mounts `/var/run/docker.sock:ro` and attaches *only* to the `internal` bridge network, isolating the Docker socket from the public interface.
    *   **CONFIRMED (Privileged Workspace Escape):** In `orchestrator.py` (lines 357–365), workspace initialization runs `busybox` as `user="root"` to execute `chown -R 65534:65534 /vol` on host paths. This bypasses the unprivileged non-root boundary by invoking root permissions inside a throwaway helper.
    *   **🚫 OUTDATED CLAIM (Pruning Loop Completed):** The security report and `remaining-work.md` claim that inactive container stoppages in `_lifecycle_loop` are missing. This is **incorrect**; the codebase has fully implemented and activated `_stop_inactive_containers()` in `claw_proxy/app.py` (lines 251–322). The routine successfully filters "ready" containers and stops those idle longer than `INACTIVE_CONTAINER_DAYS`.

---

## 4. Additional Security Findings Discovered

### A. D-14 — Proxy-to-Container Bearer Auth Bypass
The orchestrator in `orchestrator.py` (lines 376) force-injects `"ZEROCLAW_REQUIRE_PAIRING": "false"` into all containers.
*   **Impact:** ZeroClaw gateways accept all HTTP requests completely unauthenticated. Anyone on the internal `lifeatlas-net` bridge network can bypass bearer authentication entirely, call `/api/sessions`, and exfiltrate user conversations. Bearer token encryption in the database is currently decorative.

### B. JWT Retention & Memory Leak
In `claw_proxy/ws/proxy.py` (lines 947–951), browser WebSocket authentication caches the user's Supabase JWT in memory via `orchestrator.remember_user_jwt`.
*   **Impact:** While `self.user_jwt_map` stores JWTs to enable the `save_to_library` tool, there is **no deletion mechanism** inside `ws_endpoint`'s `finally` block or WebSocket disconnection hooks. JWTs accumulate and reside in process memory indefinitely, increasing the blast radius.

### C. File Upload DoS (Memory Depletion)
In `claw_proxy/files/upload.py` (lines 52–54), the upload endpoint buffers the complete payload before checking the size boundary:
```python
raw = await file.read()
if len(raw) > MAX_FILE_SIZE:
    raise HTTPException(status_code=400, detail="File too large")
```
*   **Impact:** A malicious actor can initiate multiple concurrent uploads of massive files (e.g. hundreds of megabytes), exhausting proxy process memory and causing a Denial of Service before any size rejection is issued.

---

## 5. Overall Risk Assessment

*   **Risk Rating:** **HIGH**
*   **Justification:** While sandbox boundaries (non-root runtimes and Docker networks) are structurally configured, the complete bypass of bearer auth on container ports (D-14), the memory leakage of user JWTs, the vulnerability of the file upload system to memory depletion, and the missing WebAuthn verification controllers create a severe risk posture if the outer network boundaries are breached.

---

## 6. Recommended Next Steps

1.  **Implement WebAuthn Verification Routes:** Code the missing `/auth/login/complete` and `/auth/register/complete` routes in `routes.py` to make passkeys functional.
2.  **Mitigate File Upload Buffering:** Rewrite `upload.py` to stream uploads chunk-by-chunk and reject requests exceeding 25 MB before fully reading them into memory.
3.  **Remediate JWT Memory Leak:** Add a `forget_user_jwt` method called inside `proxy.py`'s `finally` block to clear tokens from `user_jwt_map` immediately upon WebSocket disconnect.
4.  **Establish Outbound Tool Authorization Headers:** Move tool authentication tokens out of query parameters (`/tools/lifeatlas/{tool_name}?token=...`) and enforce `Authorization: Bearer <token>` in `router.py`.
5.  **Re-assess Gateway Pairing (D-14):** Configure secure token handshakes or restrict container gateway interfaces strictly to localhost mapping in shared network modes.
