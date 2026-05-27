# Security Review Report: zeroclaw-la-fork-master



It covers the ZeroClaw agent runtime fork used behind LifeAtlas through `claw-auth-proxy`.

## Executive Summary

`zeroclaw-la-fork-master` is the actual ZeroClaw agent runtime. It is primarily a Rust workspace with many crates, plus a React/TypeScript web dashboard.

Security-wise, this is a powerful component because it can:

- talk to LLM providers,
- expose an HTTP/WebSocket gateway,
- execute tools,
- handle shell/browser/HTTP/file operations,
- load plugins/skills,
- store memory and workspace data,
- run inside Docker containers.

The project already contains several security-conscious patterns:

- Gateway bearer-token pairing support.
- Rate-limiting code for authentication attempts.
- Non-root Docker runtime users.
- Distroless release image option.
- URL/private-host validation in browser tools.
- Path/workspace guard concepts in tool wrappers.
- Secret/leak detection code.

The largest risks come from deployment configuration and agent capability control. In the LifeAtlas architecture, `claw-auth-proxy` disables ZeroClaw pairing and exposes the ZeroClaw gateway inside Docker. That can be safe only if the ZeroClaw containers are reachable exclusively by the proxy on an internal network.

## Tools and Checks Run

Commands/checks used locally:

```powershell
npm audit --json
rg security-sensitive patterns across Rust crates, Dockerfiles, docker-compose.yml, .env.example
manual review of gateway auth, Docker config, tool execution, browser/fetch restrictions, plugin/tool surfaces
```

Results and limitations:

- `npm audit` in `web/` reported 0 vulnerabilities.
- `cargo`, `cargo audit`, and `cargo deny` were not available in this shell, so Rust dependency CVE coverage is incomplete.
- This was a local static review. It did not include live dynamic testing.

## Key Findings

### 1. ZeroClaw gateway exposure is the most important deployment risk

Severity: High

Relevant files:

- docker-compose.yml`
- zeroclaw-la-fork-master\crates\zeroclaw-gateway\src\api.rs`
- zeroclaw-la-fork-master\crates\zeroclaw-gateway\src\lib.rs`

The ZeroClaw gateway has bearer-token pairing support. However, in the LifeAtlas proxy flow, `claw-auth-proxy` sets:

```text
ZEROCLAW_GATEWAY_HOST=0.0.0.0
ZEROCLAW_GATEWAY_ALLOW_PUBLIC_BIND=true
ZEROCLAW_REQUIRE_PAIRING=false
```

This can be acceptable only when the gateway is not publicly reachable and only the proxy can access it.

If a ZeroClaw gateway is exposed to the internet while pairing is disabled, the gateway API and tool surface can become directly reachable.

Recommended fix:

1. In LifeAtlas production, run ZeroClaw containers only on an internal Docker network.
2. Do not publish per-user container ports publicly.
3. Keep `ZEROCLAW_REQUIRE_PAIRING=false` only behind `claw-auth-proxy`.
4. If running standalone or exposed directly, require pairing/bearer auth.
5. Add deployment tests that verify container ports are not externally reachable.

### 2. Agent tools can perform high-impact actions

Severity: High

Relevant areas:

- zeroclaw-la-fork-master\crates\zeroclaw-tools`
- zeroclaw-la-fork-master\src\approval`
- zeroclaw-la-fork-master\crates\zeroclaw-runtime`

ZeroClaw supports powerful tools including shell-like operations, browser/HTTP tools, file operations, plugins, memory, and external providers.

That is the point of an agent runtime, but it means prompt injection or malicious input can become operationally meaningful if tools are too permissive.

Recommended fix:

1. Use supervised/default risk profiles for production.
2. Do not enable YOLO/autonomous modes for user-facing production agents.
3. Disable shell or command tools unless the use case requires them.
4. Use workspace-only file access.
5. Require allowlists for browser and HTTP tools.
6. Add tool-call audit logging.
7. Add tests proving blocked commands and blocked paths stay blocked.

### 3. Pairing/auth can be bypassed by configuration

Severity: High

Relevant files:

- zeroclaw-la-fork-master\crates\zeroclaw-gateway\src\api.rs`
- zeroclaw-la-fork-master\crates\zeroclaw-gateway\src\acp.rs`
- zeroclaw-la-fork-master\crates\zeroclaw-gateway\src\sse.rs`

Gateway auth checks are conditional:

```rust
if !state.pairing.require_pairing() {
    return Ok(());
}
```

This is not a bug by itself. It is a deployment-sensitive switch. In proxy mode, `claw-auth-proxy` is expected to enforce authentication. In standalone mode, disabling pairing while binding publicly is dangerous.

Recommended fix:

1. Document clear deployment modes:
   - standalone: pairing required,
   - LifeAtlas proxy mode: pairing disabled but internal-only network.
2. Add startup guardrails: refuse `0.0.0.0 + require_pairing=false` unless an explicit trusted-proxy mode is set.
3. Add a health/status field that clearly shows whether pairing is active.
4. Add integration tests for direct unauthenticated access when pairing is disabled/enabled.

### 4. Docker Compose example exposes the gateway port and uses `latest`

Severity: Medium/High

Relevant file:

- zeroclaw-la-fork-master\docker-compose.yml`

The example compose file uses:

```text
ghcr.io/zeroclaw-labs/zeroclaw:latest
ports: 42617
ZEROCLAW_gateway__allow_public_bind=true
```

This may be fine for local examples, but production deployments should avoid mutable image tags and accidental public gateway exposure.

Recommended fix:

1. Pin production images to exact versions or digests.
2. Do not publish gateway port in LifeAtlas per-user container deployments.
3. Put ZeroClaw behind `claw-auth-proxy` or a trusted reverse proxy.
4. Add a production compose/k8s profile separate from local examples.

### 5. Rust dependency vulnerability scan was not completed

Severity: Medium/High

Relevant files:

- zeroclaw-la-fork-master\Cargo.toml`
- zeroclaw-la-fork-master\Cargo.lock`
- zeroclaw-la-fork-master\deny.toml`

This repo has a large Rust dependency surface. Local `cargo` was not available, so `cargo audit` and `cargo deny` could not be run.

Recommended fix:

1. Install Rust tooling in CI/security environment.
2. Run:

   ```powershell
   cargo audit
   cargo deny check
   cargo test --workspace
   ```

3. Treat `Cargo.lock` as the deployed dependency truth.
4. Add `cargo audit`/`cargo deny` to CI gates.

### 6. Plugin and skill supply chain needs strict controls

Severity: Medium/High

Relevant areas:

- zeroclaw-la-fork-master\crates\zeroclaw-plugins`
- zeroclaw-la-fork-master\plugins`
- zeroclaw-la-fork-master\marketplace`

ZeroClaw supports plugins/skills. That is powerful, but it introduces supply-chain risk if plugins can be installed from untrusted sources or updated without review.

Recommended fix:

1. Allowlist approved plugins in production.
2. Require plugin signatures where supported.
3. Block arbitrary plugin installation from user-controlled URLs.
4. Log plugin installation/update events.
5. Separate development plugin registry from production plugin registry.

### 7. Browser and web-fetch tools appear guarded, but need regression tests

Severity: Medium

Relevant files:

- zeroclaw-la-fork-master\crates\zeroclaw-tools\src\browser.rs`
- zeroclaw-la-fork-master\crates\zeroclaw-tools\src\browser_open.rs`
- zeroclaw-la-fork-master\crates\zeroclaw-tools\src\web_fetch.rs`

The source includes checks for private/local hosts and URL scheme restrictions. That is good because agent web tools can otherwise become SSRF primitives.

Recommended fix:

1. Keep private IP, localhost, link-local, metadata-service, and file/data/javascript scheme blocking.
2. Add tests for redirects to private IPs.
3. Add tests for IPv6 and IPv4-mapped IPv6 addresses.
4. Add allowlist support for production LifeAtlas mode.
5. Log blocked URL attempts for detection.

### 8. Secrets are present as examples/tests, not obvious live credentials

Severity: Low/Medium

Targeted pattern searches found example/test values, docs placeholders, and test fixtures, such as:

- `sk-ant-...` placeholders,
- `AKIAIOSFODNN7EXAMPLE`,
- fake private key snippets in leak-detector tests,
- documented environment variable examples.

I did not identify an obvious real production secret in this local scan.

Recommended fix:

1. Add Gitleaks or TruffleHog to CI.
2. Mark intentional test fixtures with allowlist comments/config.
3. Keep `.env` files untracked.
4. Rotate any real key that was ever committed elsewhere.

### 9. Web dashboard npm audit is clean, but should remain gated

Severity: Low/Medium

Relevant files:

- zeroclaw-la-fork-master\web\package.json`
- zeroclaw-la-fork-master\web\package-lock.json`

`npm audit --json` in `web/` reported:

- 0 critical
- 0 high
- 0 moderate
- 0 low

Recommended fix:

1. Keep `npm audit` in CI.
2. Pin/lock web dependencies with `package-lock.json`.
3. Review dashboard XSS surfaces, especially markdown/rendered output and code blocks.
4. Keep React/Vite updated.

### 10. Prefer distroless release image over Debian shell image in production

Severity: Medium

Relevant files:

- zeroclaw-la-fork-master\Dockerfile`
- zeroclaw-la-fork-master\Dockerfile.debian`

The default Dockerfile includes a distroless release stage and non-root user, which is good. The Debian variant includes shell tools and is useful for compatibility/debugging, but has a larger attack surface.

Recommended fix:

1. Use the distroless/non-root release image in production where possible.
2. Use the Debian image only where shell tooling is explicitly required.
3. Scan both image variants with Trivy or Grype.
4. Add runtime seccomp/AppArmor restrictions where supported.

## Recommended Remediation Order

1. Confirm LifeAtlas production uses internal-only ZeroClaw container networking.
2. Add a startup guard against `public bind + pairing disabled` outside trusted proxy mode.
3. Run Rust dependency audit with `cargo audit` and `cargo deny`.
4. Lock production tool permissions and risk profiles.
5. Pin Docker images by version/digest.
6. Add plugin/skill allowlisting.
7. Add SSRF/path traversal regression tests for browser, fetch, file, and shell tools.
8. Add container image scanning.

## Suggested Verification Tests

1. Direct request to a ZeroClaw container without proxy auth fails in standalone mode.
2. Direct request to a LifeAtlas-managed ZeroClaw container is impossible from outside the internal Docker network.
3. `require_pairing=false` with public bind is blocked or loudly fails in non-proxy mode.
4. Shell/file tools cannot access outside workspace boundaries.
5. Browser/fetch tools reject localhost, private IPs, metadata endpoints, and redirect-to-private cases.
6. Plugins cannot be installed from untrusted sources in production config.
7. Web dashboard API calls require bearer auth when pairing is enabled.
8. Distroless production image runs as non-root.

## Residual Risk

This review did not include:

- `cargo audit` or `cargo deny`,
- Rust test execution,
- dynamic gateway testing,
- plugin installation testing,
- container image CVE scanning,
- fuzzing of the WebSocket/API/tool-call surfaces.

The most valuable next step is a production-mode integration test where `claw-auth-proxy` starts a ZeroClaw container and a second client attempts to reach the container directly from outside the Docker network.
