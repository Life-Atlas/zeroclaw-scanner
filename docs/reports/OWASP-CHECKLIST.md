# OWASP Top 10 Security Checklist & Pass/Fail Criteria (Inventory Aligned)
**Stream:** Stream 5 — Security (ZeroClaw)  
**Ecosystem Scope:** 6-Stream Cohort Stack (Aligned with [STREAM-INVENTORY.md](file:///c:/Users/kaila/Desktop/amity/lifeatlas2/STREAM-INVENTORY.md))  
**Last Updated:** 2026-05-28

This checklist translates the standard OWASP Top 10:2021 framework into a precise, concrete set of **Pass/Fail Criteria** tailored specifically to the technologies, repositories, and integration phases of the Amity 2026 Spring cohort. Every stream lead must verify compliance prior to graduating phases.

---

## 📋 Cohort Security Mapping Summary

| Category | Vulnerability Type | Cohort Stack Relevance | Target Repositories | Primary SAST / Guardrails |
| :--- | :--- | :--- | :--- | :--- |
| **[A01:2021]** | **Broken Access Control** | FastAPI Guards, Supabase RLS, Proxy Bearer Tokens, Custom NDA | `DataCenterBackend`, `lpi-platform`, `claw-auth-proxy` | Supabase RLS scans, Manual Route Audits |
| **[A02:2021]** | **Cryptographic Failures** | Secrets Management, Bearer Storage, SSH Keys, SSL/TLS | `VSAB dashboard`, `claw-auth-proxy` | `gitleaks`, Yelp `detect-secrets` |
| **[A03:2021]** | **Injection** | Parameterized PostgreSQL, Neo4j Cypher bounds, React 19 XSS | `boardy-agents`, `vsab-data-dashboard` | `bandit`, AST Regex Scans |
| **[A04:2021]** | **Insecure Design** | Fargate Egress, WebAuthn flows, LLM Token Depletion | `DataCenter-flow`, `factory-twin`, `new-repo` | Rate limiters, Sandbox reviews |
| **[A05:2021]** | **Security Misconfiguration** | Unprivileged runtimes, Docker sockets, Committed configs | `claw-auth-proxy`, `zeroclaw-scanner` | `tfsec`, `checkov`, Config audits |
| **[A06:2021]** | **Vulnerable & Outdated** | Pinned dependency CVEs, pip/npm packages, cargo crates | All stream repos | `pip-audit`, `npm audit`, `cargo audit` |
| **[A07:2021]** | **Identification & Auth** | WebSockets JWT checks, MCP server auth, Session timeouts | `lpi-platform`, `claw-auth-proxy` | WebSocket connection filters |
| **[A08:2021]** | **Software & Data Integrity** | Docker image supply tags, CI/CD concurrent task loops | `factory-twin`, `AltioStar-tokyo-mro` | Tag digest audits, CI timeout gates |
| **[A09:2021]** | **Security Logging** | LLM cost/token telemetry, Sentry logs, Prometheus metrics | `new-repo`, `VSAB dashboard` | Cost counters, Grafana dashboards |
| **[A10:2021]** | **SSRF** | Outbound AI Tool boundaries, Playwright headless browsers | `new-repo`, `vsab-data-dashboard` | Host IP blocklists, Fargate limits |

---

## 🔍 Detailed Pass/Fail Criteria Per Category

### A01:2021 Broken Access Control

#### 📦 Technology Footprint
*   **Supabase PostgreSQL + RLS:** Active in Stream 2 (`DataCenterBackend`) and Stream 6 (`lpi-platform`).
*   **FastAPI Endpoint Guards:** Active in Stream 2, Stream 5 (`claw-auth-proxy`), and Stream 6.
*   **Custom NDA Layer:** Enforced on the frontend browsing panels in Stream 2 (`DataCenter-flow`).

#### Pass/Fail Criteria
*   **[PASS]** Every Supabase table containing user profiles, soul files, or transactional marketplace leads has Row Level Security active (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY;`) and specific policies targeting authenticated roles (`auth.uid()`).
*   **[PASS]** All FastAPI endpoints mapping to operational controls (e.g., Stream 5 container creation) or user records strictly contain explicit auth dependencies (e.g., `Depends(get_current_user)` or `Depends(require_admin)`).
*   **[PASS]** The Stream 2 frontend custom NDA UI cannot be bypassed via direct URL route traversal without validating active Supabase session approval flags.
*   **[FAIL]** Supabase tables lack active RLS policies, allowing anonymous REST requests to fetch or modify ecosystem records.
*   **[FAIL]** Direct URL route structures (e.g., `/tools/lifeatlas/{tool_name}?token=...`) pass authorization secrets in query parameters, exposing them to server access logs.

---

### A02:2021 Cryptographic Failures

#### 📦 Technology Footprint
*   **Secrets & Key Management:** Stream 3 (`VSAB dashboard` utilizing AWS Secrets Manager) and all streams utilizing GitHub Secrets.
*   **Bearer Auth at Rest:** Stream 5 (`claw-auth-proxy` utilizing encryption for stored container pairing keys).

#### Pass/Fail Criteria
*   **[PASS]** Internal SQLite/PostgreSQL bearer pairing tokens and third-party API keys (e.g., Retell AI, Resend) are encrypted at rest using AES-256 or hashed with bcrypt in database storage.
*   **[PASS]** The repository uses the pre-commit `detect-secrets` hook and passes automated `gitleaks` scans on all current files and Git histories.
*   **[PASS]** Infrastructure variables containing live credentials reside strictly in AWS Secrets Manager or GitHub Secrets, never hardcoded in Terraform configs.
*   **[FAIL]** Raw OpenAI (`sk-...`), Anthropic (`sk-ant-...`), or Retell AI (`key_...`) keys are stored in plaintext in local files, configurations, or environment example templates.
*   **[FAIL]** Database credentials or JWT signing secrets are written in plaintext inside SQLite databases or exposed in plain source code paths.

---

### A03:2021 Injection

#### 📦 Technology Footprint
*   **SQL/Graph Databases:** Stream 1 (Neo4j Cypher queries), Stream 3 (`psycopg2` / `SQLAlchemy 2.x`), and Supabase PostgreSQL.
*   **Command execution / sub-runtimes:** Stream 3 (`openpyxl` parsing user-supplied sheets and `APScheduler` executing tasks).
*   **React Frontends:** Stream 2, Stream 5, and Stream 6 utilizing TypeScript and Tailwind rendering loops.

#### Pass/Fail Criteria
*   **[PASS]** All PostgreSQL database interactions use parameterized queries, typed ORM models (e.g., SQLAlchemy 2.x, Pydantic validations), or explicit list parameter bindings (`execute("SELECT ... WHERE id = %s", (user_id,))`).
*   **[PASS]** Cypher graph queries construct paths dynamically using parameterized maps in the Neo4j driver rather than raw string addition.
*   **[PASS]** Web frontends strictly avoid browser bypass APIs like `dangerouslySetInnerHTML` unless input validation and escaping are performed by an audited sanitization helper.
*   **[FAIL]** Python files execute SQL scripts using f-strings or `.format()` formatting inside database cursor routines (e.g., `cursor.execute(f"SELECT * FROM cells WHERE name = '{cell_name}'")`).
*   **[FAIL]** Custom sheet parsing logic in Stream 3 processes Excel files using openpyxl without catching and sanitizing potentially injected formulas.

---

### A04:2021 Insecure Design

#### 📦 Technology Footprint
*   **Container Sandboxing:** Stream 3 (`factory-twin`) and Stream 5 (`claw-auth-proxy`).
*   **Conversational voice / transactional gates:** Stream 1 integrating Retell AI webhooks and Resend.
*   **Expensive AI pipelines:** Stream 1 (PydanticAI), Stream 2 (Gemini PDF extraction), and Stream 4 (Altiostar RL model training).

#### Pass/Fail Criteria
*   **[PASS]** Docker containers default to isolated internal bridge network modes (`shared` network with explicit internal DNS bindings), restricting host access by default.
*   **[PASS]** All endpoints executing Gemini, Claude, or Altiostar RL model calculations implement strict per-user rate limiters with hard caps stored dynamically.
*   **[PASS]** Retell AI conversational voice endpoints validate signed callback webhook signatures to prevent spoofing of simulated user voice payloads.
*   **[FAIL]** AI query endpoints lack request throttling, allowing automated loop attacks to trigger unlimited costly model tokens.
*   **[FAIL]** Container runtime configurations map ports dynamically to host interfaces without restricting bound local addresses, bypassing network boundaries.

---

### A05:2021 Security Misconfiguration

#### 📦 Technology Footprint
*   **Docker infrastructure:** Stream 2 (Traefik reverse proxy), Stream 3 (Docker Compose, AWS ECS/Fargate), Stream 5 (`claw-auth-proxy`), and Stream 6.
*   **Rust runtimes:** Stream 5 (`claw-auth-proxy` multi-crate runtime).
*   **Infrastructure as Code (IaC):** Stream 3 deploying via Terraform.

#### Pass/Fail Criteria
*   **[PASS]** Docker runtime environments strictly specify unprivileged non-root users inside their configurations (e.g., setting `USER 65534:65534` inside production Dockerfiles).
*   **[PASS]** Direct host Docker socket mounting (`/var/run/docker.sock`) is forbidden in target application containers, utilizing restricted Docker-Socket-Proxies operating strictly in read-only (`ro`) mode instead.
*   **[PASS]** Terraform AWS ECS/Fargate task definitions drop root capabilities (`cap_drop: ["ALL"]`) and enforce read-only root filesystems where applicable.
*   **[FAIL]** Production config templates or configurations (e.g., active `.env` files containing live credentials) are committed to standard public Git branches.
*   **[FAIL]** Container setup tasks execute workspace escapes using temporary helpers executing raw host file commands as the root user.

---

### A06:2021 Vulnerable and Outdated Components

#### 📦 Technology Footprint
*   **Multi-language dependencies:** Python (`requirements.txt`, `pyproject.toml`), Node.js (`package.json`), and Rust Crates.
*   **SAST scanning tools:** `pip-audit`, `npm audit`, `cargo audit`, and `bandit`.

#### Pass/Fail Criteria
*   **[PASS]** Python projects verify package security using automated static audits (`pip-audit`) on `requirements.txt` or `pyproject.toml` as a required CI step.
*   **[PASS]** Node.js repositories pass static vulnerability scans (`npm audit` or `yarn audit`) with zero Critical or High findings.
*   **[PASS]** Rust crates used in Stream 5 are validated using `cargo audit` in production pipelines.
*   **[FAIL]** Active dependency packages in production environments use archaic, vulnerable library versions (e.g., `pandas<=1.5.0` or `fastapi<=0.90.0`) with known published CVE indices.
*   **[FAIL]** Repositories deploy package configs using wildcard tags or unpinned tags, causing inconsistent package resolutions on deployment cycles.

---

### A07:2021 Identification and Authentication Failures

#### 📦 Technology Footprint
*   **Token Verification:** Stream 5 (`claw-auth-proxy` WebSockets proxy validating Supabase JWTs) and Stream 6 (`lpi-platform` FastAPI endpoints).
*   **Model Context Protocol (MCP):** Stream 6 (`lpi-platform` LPI MCP server tool bounds).

#### Pass/Fail Criteria
*   **[PASS]** WebSockets proxies validate user JWT signatures from Supabase during the initial upgrade handshake and enforce connection closures when sessions expire.
*   **[PASS]** WebSockets event loops implement a `finally` block or explicit disconnection handlers to wipe cached JWT credentials immediately upon browser socket termination.
*   **[PASS]** Stream 6 LPI MCP server enforces tool token authorization headers, verifying the caller has the necessary permissions to trigger structural changes.
*   **[FAIL]** User access tokens and JWT payloads are retained indefinitely inside server-side mapping caches (e.g., `user_jwt_map`), causing memory leaks and exposing credentials to process-level dumps.
*   **[FAIL]** API routers accept anonymous, unsigned, or unchecked session identifiers to map resources.

---

### A08:2021 Software and Data Integrity Failures

#### 📦 Technology Footprint
*   **CI/CD Workflows:** All streams running GitHub Actions.
*   **Supply Chain:** Base Docker images.
*   **Automation:** Stream 3 scheduling actions via `APScheduler` and `Playwright`.

#### Pass/Fail Criteria
*   **[PASS]** Dockerfiles pull base runtimes using specific, immutable digests or pinned tags rather than floating qualifiers (e.g., `tecnativa/docker-socket-proxy:1.3` instead of `tecnativa/docker-socket-proxy:latest`).
*   **[PASS]** CI/CD pipeline triggers strictly filter execution paths (`paths:` configurations) and set immediate concurrency cancels to prevent stale duplicate actions from exhausting platform minutes.
*   **[PASS]** Automated scrapers in Stream 3 running via Playwright validate download integrity and origin hashes before executing or storing scraped records.
*   **[FAIL]** Third-party packages or scripts are downloaded and piped directly into execution runtimes without hash validation (e.g., `curl -s https://example.com/install.sh | bash`).
*   **[FAIL]** Public CI pipelines run continuous integration steps on pull requests with highly privileged access scopes capable of exfiltrating repository secret parameters.

---

### A09:2021 Security Logging and Monitoring Failures

#### 📦 Technology Footprint
*   **Telemetry Stack:** Stream 3 (Sentry, Prometheus, Grafana) and all streams logging LLM requests.
*   **SMILE Metric Logs:** Stream 1 (Boardy AI matching explanation logging) and Stream 6.

#### Pass/Fail Criteria
*   **[PASS]** Prometheus metrics and Sentry integrations in Stream 3 are configured to log access violations, database connection limits, and failed background scheduler loops.
*   **[PASS]** AI operations track model calls by logging input/output tokens, target providers, costs, and request response hashes to database stores.
*   **[FAIL]** Security alerts or critical execution failures are logged without structured context, preventing automated monitoring from isolating errors.
*   **[FAIL]** Production backends expose plain credentials, bearer tokens, or full JWT strings inside standard output logs or monitoring logs.

---

### A10:2021 Server-Side Request Forgery (SSRF)

#### 📦 Technology Footprint
*   **Automation Scrapers:** Headless web operations in Stream 3 running via `Playwright`.
*   **AI Custom Tools:** Outbound request loops in Stream 1 (Retell Webhooks / custom APIs) and Stream 6 (MCP server integrations).

#### Pass/Fail Criteria
*   **[PASS]** Custom tools accessed by AI agents validate destination address schemas chunk-by-chunk and actively block private host IP spaces (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `169.254.169.254`).
*   **[PASS]** Target sandbox containers lack host interfaces and outbound route rules to target the cloud meta-data endpoint services or standard host orchestration endpoints.
*   **[PASS]** Playwright automation loops in Stream 3 strictly sanitize URLs, restricting navigation dynamically to a predefined domain whitelist.
*   **[FAIL]** Agent APIs allow custom document-fetch tools to access arbitrary local network endpoints, making the host network vulnerable to internal traversal.
*   **[FAIL]** Outgoing request routing inside sandboxed environments defaults to standard permissive configurations without explicit internal destination checks.
