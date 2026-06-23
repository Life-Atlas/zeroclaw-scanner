# ZeroClaw STRIDE Threat Model

**Date:** 2026-05-27

**Lead:** Naman Anand

**Contributors:** Varshit Pratap Singh, Kailash Narayana Prasad, Sania Gurung

**Scope:** `claw-auth-proxy`, `zeroclaw-la-fork`, `zeroclaw-scanner`

## System Boundaries & Trust Zones
The LifeAtlas ecosystem relies on strict separation of concerns. Our primary focus is the boundary between the authenticated user and the AI Agent environment.
1. **The Gateway:** `claw-auth-proxy` (High Trust) — Manages auth, routing, and container orchestration.
2. **The Execution Environment:** `zeroclaw-la-fork` Docker containers (Low Trust) — The isolated per-user agent runtime.

---

## 1. Spoofing (Pretending to be something else)
*Can an attacker bypass authentication or impersonate another user/service?*

* **Threats:**
  * User A uses an expired or forged JWT to open a WebSocket connection.
  * An attacker bypasses the proxy entirely and sends requests directly to the ZeroClaw container.
* **Verified Findings (W1 Triage):**
  * ⚠️ **Dead WebAuthn / Static Token Reliance (Kailash):** Passkey registration/verification routes (`/auth/login/complete`) are entirely missing in the proxy. This forces total operational reliance on static admin tokens, which are easily compromised.
  * ⚠️ **Container Bearer Auth Bypass [D-14] (Kailash):** The orchestrator injects `ZEROCLAW_REQUIRE_PAIRING="false"`. Any entity on the internal `lifeatlas-net` can hit the container gateways unauthenticated and exfiltrate session data.
* **Required Defenses:**
  * Implement missing passkey verification routes to deprecate static admin tokens.
  * Enforce secure token handshakes for container gateways even on internal networks.

## 2. Tampering (Modifying data or code)
*Can an attacker alter the code, configuration, or data in transit?*

* **Threats:**
  * An attacker manipulates the Docker image pulled during container provisioning.
  * A user uploads a malicious file that the agent executes.
* **Verified Findings (W1 Triage):**
  * ⚠️ **Mutable Docker Tags (Varshit):** `zeroclaw-la-fork` and `claw-auth-proxy` use `:latest` Docker tags, exposing the system to supply-chain tampering.
  * ⚠️ **Unprotected Config Files (Sania):** The ZeroClaw agent's `config.toml` has no write-protection or ownership checks. A compromised agent could silently rewrite its own rulebook and autonomy levels.
* **Required Defenses:**
  * Pin all Docker images to specific cryptographic digests (SHA256).
  * Lock `config.toml` file permissions and add a startup validation check in the Rust runtime.

## 3. Repudiation (Claiming you didn't do something)
*If an attack happens, do we have the logs to prove who did it and how?*

* **Threats:**
  * The ZeroClaw agent executes a destructive command, but there is no log tying the action back to the specific LifeAtlas user.
* **Verified Findings (W1 Triage):**
  * ⚠️ **Ephemeral Audit Logs (Sania):** The Rust runtime builds a secure Merkle hash-chain for its audit logs, but stores it entirely in RAM. Restarting or crashing the container permanently destroys the forensic trail.
* **Required Defenses:**
  * Connect the existing `audit.rs` Merkle chain to persistent disk storage or a dedicated database table.

## 4. Information Disclosure (Exposing private data)
*Can a user or the agent read data they shouldn't have access to?*

* **Threats:**
  * User A's agent reads files from User B's workspace.
  * The proxy leaks sensitive LifeAtlas tokens in URL parameters.
* **Verified Findings (W1 Triage):**
  * ⚠️ **LLM Plaintext Secret Exposure (Sania):** While logs correctly show `[REDACTED]`, the actual execution context passes plaintext API keys and secrets directly into the LLM context window. 
  * ⚠️ **JWT Memory Leak (Kailash):** `claw-auth-proxy` caches user Supabase JWTs in memory to enable `save_to_library` but never deletes them on WebSocket disconnect, leaving credentials permanently in RAM.
* **Required Defenses:**
  * Implement a secret reference/injection system so the LLM processes reference IDs, not raw secrets.
  * Add a `forget_user_jwt` hook upon WebSocket disconnection in the proxy.

## 5. Denial of Service (Crashing the system)
*Can an attacker consume enough resources to take the system offline?*

* **Threats:**
  * An attacker spams the system, maxing out memory or CPU.
* **Verified Findings (W1 Triage):**
  * ⚠️ **Rate Limiter Memory Leak (Sania):** The `PerSenderTracker` in the Rust runtime creates permanent memory slots for every unique sender with no eviction logic, guaranteeing an eventual Out-Of-Memory (OOM) crash.
  * ⚠️ **File Upload Memory Depletion (Kailash):** `upload.py` buffers the entire file payload into memory *before* checking if it exceeds the 25 MB limit, allowing trivial DoS via massive file uploads.
* **Required Defenses:**
  * Add Time-To-Live (TTL) eviction logic to the sender rate limiter.
  * Rewrite file upload handling to stream chunks and reject immediately upon exceeding the byte limit.

## 6. Elevation of Privilege (Gaining unauthorized power)
*Can a restricted entity gain administrative or host-level access?*

* **Threats:**
  * The ZeroClaw agent escapes its Docker container and gains root access to the host VM.
  * The proxy's connection to the Docker socket allows it to modify non-ZeroClaw containers.
* **Verified Findings (W1 Triage):**
  * ⚠️ **Privileged Workspace Escape (Kailash):** Workspace initialization uses a `busybox` container running as `root` to execute `chown` on host paths, temporarily breaking the non-root runtime boundary.
* **Required Defenses:**
  * Restrict the Docker socket proxy permissions.
  * Refactor workspace initialization to avoid spinning up root-level helper containers.
