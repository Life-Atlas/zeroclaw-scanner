# Security Review Report: claw-auth-proxy-main



This report is separate from the earlier LifeAtlas reports. It covers the Python/FastAPI proxy that connects LifeAtlas users to per-user ZeroClaw containers.

## Executive Summary

`claw-auth-proxy-main` is a high-trust boundary service. It authenticates Supabase users, provisions ZeroClaw Docker containers, relays WebSocket traffic, exposes LifeAtlas tools to containers, handles file movement, and stores container metadata in Supabase.

The code has several good controls already:

- Supabase JWT verification before user WebSocket access.
- Per-user container mapping.
- Non-root container user in the proxy Dockerfile.
- Path normalization helpers for workspace access.
- Container bearer tokens encrypted at rest.
- Admin routes are generally protected by admin auth.

The highest-risk areas are not simple dependency CVEs. They are architectural boundaries:

1. Docker API access from the proxy.
2. Supabase service-role access inside the proxy.
3. Per-container bearer tokens used as authorization for LifeAtlas tools.
4. Admin API exposure.
5. File upload and workspace file handling.

## Tools and Checks Run

Commands/checks used locally:

```powershell
python -m bandit -r claw-auth-proxy-main\src -f json
python -m pip_audit claw-auth-proxy-main -f json --progress-spinner off
rg security-sensitive patterns across src, Dockerfile, docker-compose.yml, .env.example
manual review of auth, websocket, Docker orchestration, file upload, LifeAtlas tool routes, admin routes
```

Notes:

- `bandit` completed.
- `pip-audit` hung without returning results and was stopped. Python dependency CVE coverage is therefore incomplete.
- This was a local static review. It did not include live dynamic testing against a deployed environment.

## Key Findings

### 1. Docker API access is a high-value compromise path

Severity: High

Relevant files:

- claw-auth-proxy-main\docker-compose.yml`
- claw-auth-proxy-main\src\claw_proxy\containers\orchestrator.py`
- claw-auth-proxy-main\src\claw_proxy\containers\workspace.py`

The proxy can create, stop, remove, inspect, and exec into containers through Docker. The compose file uses a Docker socket proxy, which is better than mounting the raw socket directly into the app, but the enabled capabilities are still powerful:

- `CONTAINERS=1`
- `EXEC=1`
- `IMAGES=1`
- `NETWORKS=1`
- `POST=1`

If the proxy or admin plane is compromised, an attacker may be able to affect containers, images, networks, or workspace volumes.

Recommended fix:

1. Keep the Docker socket proxy; do not mount `/var/run/docker.sock` directly into the app.
2. Reduce socket-proxy permissions to the minimum required for production.
3. Re-evaluate whether `EXEC=1` is required in production.
4. Run the proxy and ZeroClaw containers on an internal-only Docker network.
5. Monitor Docker API calls and admin operations.
6. Use image allowlists and pinned image digests.

### 2. Admin API is powerful and must be treated as an operations control plane

Severity: High

Relevant files:

- claw-auth-proxy-main\src\claw_proxy\admin\routes.py`
- claw-auth-proxy-main\src\claw_proxy\admin\auth.py`
- claw-auth-proxy-main\src\claw_proxy\app.py`

The admin API can list users/containers, start/stop/restart/delete containers, edit config, inspect workspace files, create static tokens, invite admins, run batch jobs, and view audit data.

Most routes require admin auth, which is good. However, because this API is so powerful, exposure or weak operational controls would be high-impact.

Recommended fix:

1. Do not expose `/claw-admin/*` publicly unless protected by strong access controls.
2. Put the admin plane behind VPN, IP allowlist, or identity-aware proxy.
3. Require WebAuthn/MFA for human admins.
4. Limit or disable static admin tokens in production where possible.
5. Add rate limiting to login, registration, token, and admin mutation endpoints.
6. Confirm audit logs include all high-risk operations and are tamper-resistant.

### 3. LifeAtlas tools use per-container bearer tokens as authorization

Severity: High

Relevant files:

- claw_proxy\tools\lifeatlas\router.py`
- claw_proxy\containers\orchestrator.py`
- claw-auth-proxy-main\src\claw_proxy\db.py`

ZeroClaw containers call LifeAtlas helper tools through the proxy. The route authorizes by checking a token against `token_map`.

This design keeps Supabase service-role credentials out of the container, which is good. The risk is that a leaked per-container token can grant access to that user's LifeAtlas tool surface.

The route currently accepts the token as a query parameter:

```text
/tools/lifeatlas/{tool_name}?token=...
```

Query tokens are easier to leak through logs, browser history, reverse proxies, referrers, and debugging tools.

Recommended fix:

1. Move tool authorization from query parameter to `Authorization: Bearer <token>`.
2. Redact tokens from all logs.
3. Give tokens short lifetimes or rotate them regularly.
4. Scope tokens by purpose, for example read-only tools versus write tools.
5. Add per-tool rate limits.
6. Consider HMAC-signed requests with timestamp/nonce to reduce replay risk.

### 4. Supabase service-role is used inside the proxy

Severity: High

Relevant files:

- claw-auth-proxy-main\src\claw_proxy\config.py`
- claw-auth-proxy-main\src\claw_proxy\db.py`
- claw-auth-proxy-main\src\claw_proxy\tools\lifeatlas`

The proxy uses `SUPABASE_SERVICE_ROLE_KEY`, which bypasses RLS. This can be appropriate for a trusted backend, but every service-role operation must derive identity from a verified user/container mapping, never from caller-controlled user IDs.

Observed good pattern:

- Many LifeAtlas tool queries filter by `user_id` and `profile_id`.
- The tool router maps token to `user_id`, instead of accepting `user_id` directly from the request.

Remaining risk:

- Any future route that accepts user/profile IDs from a request could become a cross-tenant data exposure.
- `decrypted_profiles` access is especially sensitive.

Recommended fix:

1. Keep service-role usage in a small number of reviewed modules.
2. Never accept `user_id` or `profile_id` directly from container/browser requests.
3. Add tests proving token A cannot access user B's data.
4. Add a service-role access checklist for every new tool.
5. Prefer user-scoped Supabase JWTs where writes should respect RLS.

### 5. File upload reads the full file before size enforcement

Severity: Medium/High

Relevant file:

- claw-auth-proxy-main\src\claw_proxy\files\upload.py`

The upload endpoint has a 25 MB limit and MIME allowlist, which is good. But the implementation reads the entire uploaded file first:

```python
raw = await file.read()
if len(raw) > MAX_FILE_SIZE:
    ...
```

This means oversized requests may still consume memory before rejection. It also trusts `file.content_type`, which can be spoofed by a client.

Recommended fix:

1. Enforce request/body size limits at reverse proxy and ASGI layer.
2. Stream uploads and stop reading after `MAX_FILE_SIZE + 1`.
3. Validate magic bytes for PDF/images/docx/csv/text where practical.
4. Add malware scanning or quarantine for user-uploaded documents.
5. Add tests for oversized upload and MIME spoofing.

### 6. Production network mode must avoid public ZeroClaw container ports

Severity: Medium/High

Relevant files:

- claw-auth-proxy-main\src\claw_proxy\containers\orchestrator.py`
- claw-auth-proxy-main\docker-compose.yml`

The orchestrator supports:

- `host` mode: publish random host ports.
- `shared` mode: internal Docker DNS on `lifeatlas-net`.

The `shared` mode is safer for staging/production because ZeroClaw is reachable only by the proxy network, not directly through host-published ports.

Recommended fix:

1. Use `ZEROCLAW_NETWORK_MODE=shared` in staging/production.
2. Do not publish per-user ZeroClaw container ports publicly.
3. Firewall the proxy and container network.
4. Confirm only `claw-auth-proxy` can reach ZeroClaw container gateways.

### 7. Proxy stores user JWTs in memory for `save_to_library`

Severity: Medium

Relevant files:

- claw-auth-proxy-main\src\claw_proxy\containers\orchestrator.py`
- claw-auth-proxy-main\src\claw_proxy\ws\proxy.py`
- claw-auth-proxy-main\src\claw_proxy\tools\lifeatlas\save.py`

The proxy remembers a user's Supabase JWT in memory after WebSocket connection so the `save_to_library` tool can make user-scoped calls.

This is understandable, but JWT retention increases blast radius if process memory or logs are exposed.

Recommended fix:

1. Store user JWTs only as long as required.
2. Clear JWTs when the user's last WebSocket disconnects.
3. Do not log JWTs or request URLs containing tokens.
4. Prefer short-lived delegated tokens for write tools.
5. Add tests for JWT cleanup after disconnect.

### 8. Bandit found low/medium hardening issues

Severity: Low/Medium

Bandit found:

- `assert` in runtime code.
- broad `except Exception: pass`.
- warnings about binding to `0.0.0.0`.
- false-positive-looking hardcoded secret warnings for placeholders/paths.

Recommended fix:

1. Replace runtime `assert` with explicit checks and exceptions.
2. Log broad exception paths at debug/warning level.
3. Keep `0.0.0.0` only inside controlled container/reverse-proxy environments.
4. Mark false positives with comments only after review.

### 9. Docker images use mutable tags

Severity: Medium

Relevant file:

- claw-auth-proxy-main\docker-compose.yml`

Examples:

- `tecnativa/docker-socket-proxy:latest`
- `lifeatlas/claw-proxy:latest`

Recommended fix:

1. Pin production images to exact versions or digests.
2. Track image updates through a controlled release process.
3. Scan built images with Trivy or Grype.

### 10. Dependency vulnerability coverage is incomplete

Severity: Medium

`pip-audit` did not complete in this environment. The project depends on security-sensitive libraries including FastAPI, Supabase, Docker SDK, PyJWT, WebAuthn, cryptography, websockets, and httpx.

Recommended fix:

1. Run `uv sync` in a clean environment.
2. Run:

   ```powershell
   python -m pip_audit -f json
   ```

3. Add dependency audit to CI.
4. Enable Dependabot/Renovate for Python dependencies.
5. Treat `uv.lock` as the source of exact deployed versions.

## Recommended Remediation Order

1. Lock down admin API exposure.
2. Use shared/internal networking for production ZeroClaw containers.
3. Reduce Docker socket proxy permissions.
4. Move LifeAtlas tool tokens out of query parameters.
5. Add upload streaming limits and magic-byte validation.
6. Add cross-tenant tests for user/container/tool isolation.
7. Add rate limiting to auth, admin, upload, push, and tool routes.
8. Pin Docker images and scan container images.
9. Complete Python dependency audit in CI.

## Suggested Verification Tests

1. User A cannot connect to User B's container or session.
2. User A's container token cannot call tools for User B.
3. Missing/invalid JWT cannot open `/zeroclaw/ws`.
4. Missing/invalid container token cannot call `/zeroclaw/tools/lifeatlas/*`.
5. Oversized upload is rejected before full buffering.
6. MIME spoofed file is rejected.
7. Admin routes reject missing/invalid admin token.
8. Static admin tokens can be revoked and revocation takes effect immediately.
9. Production compose does not expose per-user ZeroClaw ports.
10. Docker socket proxy denies operations not needed in production.

## Residual Risk

This review did not include:

- live deployment testing,
- Supabase RLS validation against a real project,
- full Python dependency CVE audit,
- container image CVE scan,
- fuzzing of WebSocket protocols,
- Docker escape testing.

The most valuable next step is dynamic multi-user testing with two Supabase users and production-like Docker networking.
