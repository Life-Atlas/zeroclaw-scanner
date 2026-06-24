# ZeroClaw Scanner — Complete Setup & Usage Guide

> **ZeroClaw** is an automated, AI-powered security auditing platform designed to detect, analyze, and remediate vulnerabilities across codebases within the LifeAtlas ecosystem. It combines static analysis, dynamic API testing, and LLM-driven remediation into a single unified pipeline — accessible via both a **CLI** and a **Streamlit Dashboard**.

---

## 📖 Overview

ZeroClaw Scanner is a modular, multi-phase security tool built by **Stream 5 (Security)** of the LifeAtlas Amity 2026 Spring Cohort. It identifies security issues across multiple domains:

- **Hardcoded secrets** (API keys, tokens, passwords committed to source control)
- **Vulnerable & unpinned dependencies** (CVEs via the Google OSV API, floating versions, missing hash verification)
- **Dangerous code patterns** (SQL injection, XSS, command injection via `shell=True`)
- **Authentication & authorization gaps** (unprotected FastAPI routes, missing Supabase Row Level Security)
- **Dynamic API vulnerabilities** (auth bypass, rate limiting, session fixation/hijacking)

Additionally, ZeroClaw integrates an **AI-driven Enrichment Phase** that automatically analyzes critical findings using the ZeroClaw Rust Agent (backed by LLMs via OpenRouter), adding detailed reasoning chains and ready-to-apply code fixes.

The platform offers two interfaces:
1. **CLI** — For developers and CI/CD pipelines (`python -m zeroclaw.cli scan`)
2. **Streamlit Dashboard** — A full visual control panel with live scanning, scorecard tracking, remediation guides, auto-verification, and export capabilities

---

## 🚀 Key Features

### Static Analysis Scanners (SAST)

| Scanner | What It Detects | Key Capabilities |
|---|---|---|
| 🔑 **Secret Scanner** | API keys, database credentials, tokens, certificates | Strips code comments before evaluation; ignores placeholder values; skips files >5 MB to prevent OOM |
| 📦 **Dependency Scanner** | Vulnerable packages, unpinned versions, missing hashes | Queries the Google OSV API for known CVEs; offline fallback database for air-gapped environments; supports `requirements.txt`, `pyproject.toml`, and `package.json` |
| 🛡️ **Pattern Scanner** | SQL injection, XSS (`innerHTML`, `dangerouslySetInnerHTML`), command injection (`shell=True`) | Sliding window buffer to detect multi-line vulnerabilities; evaluates ALL patterns per context (no severity masking); TOCTOU-safe file reads |
| 🔒 **Auth & RLS Scanner** | Unprotected FastAPI routes, missing Supabase RLS | Uses Python AST parsing to verify `Depends(get_current_user)` on every HTTP endpoint; parses SQL migrations for `ENABLE ROW LEVEL SECURITY` |

### Dynamic Analysis (DAST)

| Tester | What It Tests |
|---|---|
| ⚡ **API Security Tester** | Auth bypass (invalid/expired tokens), rate limiting (429 enforcement), session fixation, session hijacking, session timeout |
| 💉 **Injection Tester** | Fires SQLi and XSS payloads against live FastAPI endpoints, compares responses against baselines to determine exploitability |

### AI Enrichment Engine

- Sends critical/high/medium findings to the **ZeroClaw Rust Agent** binary
- The agent calls an LLM (via OpenRouter) to produce a structured JSON response containing:
  - `reasoning_chain` — Step-by-step vulnerability analysis (root cause, attack vector, STRIDE/OWASP mapping)
  - `fixed_code` — Ready-to-paste remediated code snippet
- Circuit-breaker pattern: stops enrichment after 2 consecutive API failures to prevent cascading timeouts

### Dashboard Features

- 📡 **Live Scan Control Center** — Scan local directories or clone remote Git repos directly from the UI
- 📋 **Findings Tracker** — Expandable cards with severity badges, STRIDE/OWASP tags, AI reasoning, and suggested fixes
- 🏆 **GLASS Scorecard** — Per-stream security scores (0–10) with visual bar charts
- 🔄 **Auto-Verification** — When you mark a finding as "Fixed", the dashboard re-runs the relevant scanner to confirm the fix
- 📥 **Export** — Download findings as JSON or Markdown reports
- 📘 **Inline Remediation Guides** — Category-specific markdown guides rendered directly in finding cards

---

## 📐 System Architecture

ZeroClaw scans run through a strict **3-Phase pipeline**: Gathering → Enrichment → Reporting.

```mermaid
graph TD
    subgraph Input["📥 Input Sources"]
        LocalDir["Local Directory Path"]
        GitURL["Remote Git URL"]
    end

    LocalDir --> CLI["CLI Command Plane<br/><code>python -m zeroclaw.cli scan</code>"]
    GitURL --> Dashboard["Streamlit Dashboard<br/><code>streamlit run dashboard.py</code>"]
    LocalDir --> Dashboard
    Dashboard -->|"git clone --depth 1"| TempDir["Temp Clone Directory"]
    TempDir --> CLI

    subgraph Phase1["Phase 1: Static & Dynamic Analysis"]
        CLI --> SecretScan["🔑 Secret Scanner<br/>Regex + Comment Stripping"]
        CLI --> PatternScan["🛡️ Pattern Scanner<br/>Sliding Window + AST"]
        CLI --> DepScan["📦 Dependency Scanner<br/>OSV API + Offline DB"]
        CLI --> AuthScan["🔒 Auth & RLS Scanner<br/>FastAPI AST + SQL Parsing"]
        CLI --> APISec["⚡ API Security Tester<br/>Auth Bypass · Rate Limit · Session"]
    end

    SecretScan -->|Findings| Compiler["Findings Compiler"]
    PatternScan -->|Findings| Compiler
    DepScan -->|Findings| Compiler
    AuthScan -->|Findings| Compiler
    APISec -->|Findings| Compiler

    subgraph Phase2["Phase 2: AI Enrichment"]
        Compiler -->|"Critical/High/Medium"| AgentClient["Agent Client<br/><code>agent_client.py</code>"]
        AgentClient -->|"CLI subprocess call"| RustBin["ZeroClaw Rust Agent<br/><code>~/.cargo/bin/zeroclaw</code>"]
        RustBin -->|"API call"| LLM["OpenRouter LLM<br/><code>gemma-4-31b-it:free</code>"]
        LLM -->|"reasoning_chain + fixed_code"| RustBin
        RustBin -->|"JSON response"| AgentClient
    end

    subgraph Phase3["Phase 3: Reporting"]
        AgentClient -->|Enriched Findings| Scorecard["GLASS Scorecard<br/>Score Calculation"]
        Scorecard --> JSONReport["JSON Report<br/><code>reports/latest_scan.json</code>"]
        Scorecard --> TermReport["Terminal Report<br/>Rich Formatted Output"]
        Scorecard --> DashboardUI["Dashboard UI<br/>Tracker · Scorecard · Export"]
    end

    subgraph Persistence["💾 Persistence"]
        DashboardUI -->|Read/Write| Tracker["findings_tracker.json"]
        DashboardUI -->|Auto-Verify| VerifyScript["verify_fix.py"]
        VerifyScript -->|Re-scan| Phase1
    end
```

### Dashboard Architecture

```mermaid
graph LR
    subgraph Frontend["Streamlit Frontend"]
        Splash["🔐 Splash Screen"]
        Sidebar["Sidebar Filters<br/>Stream · Severity · Status"]
        ScanPanel["📡 Scan Control Center<br/>Path Input · Git URL · AI Toggle"]
        Tabs["Tabbed Interface"]
        T1["📋 Findings Tracker"]
        T2["🏆 Scorecard"]
        T3["📡 Scan Sources"]
        T4["📥 Export"]
        Tabs --> T1 & T2 & T3 & T4
    end

    subgraph Backend["Python Backend"]
        Scanners["Scanner Suite"]
        Agent["ZeroClaw Agent Client"]
        Verify["verify_fix.py"]
        TrackerDB["findings_tracker.json"]
    end

    ScanPanel -->|"Run Scan"| Scanners
    Scanners -->|Findings| Agent
    Agent -->|Enriched| TrackerDB
    T1 -->|"Status → Fixed"| Verify
    Verify -->|Re-scan result| TrackerDB
    TrackerDB -->|Load| Sidebar
```

---

## 📂 Codebase Directory Structure

```text
zeroclaw-scanner/
├── dashboard.py                      # Streamlit Dashboard (Phase 4 UI)
├── verify_fix.py                     # Auto-verification script for fix validation
├── findings_tracker.json             # Persistent findings database (JSON)
├── requirements.txt                  # Dashboard + scanner dependencies
├── pyproject.toml                    # Project metadata and CLI script entry
├── Makefile                          # Developer shortcuts (test, lint, scan)
├── .env.example                      # Environment variable template
├── .streamlit/
│   └── config.toml                   # Streamlit theme configuration (dark mode)
├── src/
│   └── zeroclaw/
│       ├── __init__.py
│       ├── cli.py                    # CLI parser: scan & report subcommands
│       ├── models.py                 # Pydantic data schemas (Finding, ScanResult, etc.)
│       ├── reporter.py               # GLASS scorecard calculation + terminal/JSON formatting
│       ├── agent_client.py           # Bridge to ZeroClaw Rust Agent for AI enrichment
│       ├── injection_tester.py       # Live SQLi + XSS payload fuzzer
│       ├── prompts/
│       │   └── remediation.txt       # System prompt template for the LLM agent
│       └── scanners/
│           ├── secret_scanner.py     # Credential / entropy scanner
│           ├── dependency_scanner.py # pip/npm manifest vulnerability scanner
│           ├── pattern_scanner.py    # Code pattern auditor (SQLi, XSS, Cmd Injection)
│           ├── auth_scanner.py       # FastAPI auth + Supabase RLS auditor
│           ├── api_security_tester.py# Ephemeral mock API pen-testing harness
│           └── run_scanners.py       # Standalone scanner orchestrator script
├── remediation/                      # Inline remediation guide markdown files
│   ├── hardcoded-secrets.md
│   ├── unpinned-deps.md
│   ├── sqli.md
│   ├── xss.md
│   ├── command-injection.md
│   ├── unprotected-routes.md
│   └── missing-rls.md
├── tests/                            # Unit and integration test suites
│   ├── conftest.py                   # Vulnerable & clean file system mocks
│   ├── test_secret_scanner.py
│   ├── test_dependency_scanner.py
│   ├── test_pattern_scanner.py
│   ├── test_auth_scanner.py
│   ├── test_api_security_tester.py
│   ├── test_agent_client.py
│   ├── test_smoke.py
│   └── vulnerable_app.py            # Intentionally vulnerable FastAPI app for testing
├── reports/                          # Scan output reports (JSON)
└── docs/
    ├── REMEDIATION-GUIDE.md
    ├── architecture/
    └── reports/
```

---

## 🛠️ Installation & Setup

### Prerequisites

| Requirement | Purpose |
|---|---|
| **Python 3.12+** (with `pip`) | Core scanner engine and dashboard |
| **Git** | Cloning target repositories from the dashboard |
| **Node.js / npm** *(optional)* | Required only if scanning Node.js projects (`package.json`) |
| **Rust & Cargo** *(optional)* | Required only if you want to compile the ZeroClaw Rust Agent from source |

---

### Option A: Run the Streamlit Dashboard (Recommended)

The dashboard provides a full visual interface for scanning, tracking, and remediating vulnerabilities.

#### Step 1: Clone the Repository

```bash
git clone https://github.com/Life-Atlas/zeroclaw-scanner.git
cd zeroclaw-scanner
```

#### Step 2: Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate    # Linux/macOS
# venv\Scripts\activate     # Windows PowerShell
```

#### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
pip install -e ".[dev]"     # Also installs the CLI tool in editable mode
```

#### Step 4: Set the OpenRouter API Key

The ZeroClaw AI Agent requires an OpenRouter API key for LLM-powered enrichment.

1. Get a free API key from [OpenRouter](https://openrouter.ai/keys)
2. Set it in your environment:
   ```bash
   export OPENROUTER_API_KEY="sk-or-v1-your-key-here"
   ```
   *(Add this to `~/.bashrc` or `~/.zshrc` to persist it across sessions)*

#### Step 5: Configure the ZeroClaw Rust Agent

> **Note:** The dashboard will automatically attempt to download a pre-built binary and write `~/.zeroclaw/config.toml` on startup. If this auto-setup fails, follow these manual steps:

```bash
# Install the ZeroClaw binary via Cargo
cargo install zeroclaw

# Verify it's accessible
~/.cargo/bin/zeroclaw --version

# Create config directory
mkdir -p ~/.zeroclaw
```

Create `~/.zeroclaw/config.toml`:

```toml
schema_version = 3

[providers.models.openrouter.scanner]
model = "google/gemma-4-31b-it:free"
temperature = 0.2
api_key_env = "OPENROUTER_API_KEY"
max_tokens = 1024
fallback_models = []
native_tools = false

[agents.scanner]
model_provider = "openrouter.scanner"
risk_profile = "default"
skill_bundles = []
enabled = true

[risk_profiles.default]
level = "full"
workspace_only = false
block_high_risk_commands = false
```

#### Step 6: Launch the Dashboard

```bash
streamlit run dashboard.py
```

This opens the dashboard at `http://localhost:8501` in your browser.

---

### Option B: Run via CLI

The CLI is ideal for automation, CI/CD pipelines, and quick terminal-based scans.

#### Running a Scan

```bash
# Scan the current directory
python -m zeroclaw.cli scan --target .

# Scan a specific directory with a stream label
python -m zeroclaw.cli scan --target /path/to/target/repo --stream boardy-agents

# Skip AI enrichment for faster scans
python -m zeroclaw.cli scan --target . --no-enrich

# Output as JSON instead of terminal
python -m zeroclaw.cli scan --target . --format json
```

#### CLI Arguments

| Argument | Description | Default |
|---|---|---|
| `--target` | Path to the directory to scan | `.` (current dir) |
| `--stream` | String tag identifying the team/stream | Directory name |
| `--no-enrich` | Skip the LLM agent enrichment step | Disabled |
| `--format` | Report output style: `terminal` or `json` | `terminal` |

#### Printing Saved Reports

Re-display report data from a previous scan without re-running the scanners:

```bash
# Display terminal-formatted output from latest scan
python -m zeroclaw.cli report --format terminal

# Output raw JSON
python -m zeroclaw.cli report --format json

# Load a specific scan report file
python -m zeroclaw.cli report --format terminal --input reports/boardy-agents_scan.json
```

#### Using Make Shortcuts

```bash
make install   # pip install -e ".[dev]" + pre-commit hooks
make scan      # python -m zeroclaw.cli scan --target .
make report    # python -m zeroclaw.cli report --format terminal
make test      # pytest tests/ -v --tb=short
make lint      # ruff check + mypy
```

---

## 🔐 Scanning Remote Git Repositories (Private Repos)

The dashboard's **Live Scan Control Center** supports scanning remote Git repositories by entering a Git URL. When you click **"🚀 Run Security Scan"**, the dashboard performs a `git clone --depth 1` of the repository into a temporary directory, scans it, and cleans up afterward.

### Authentication for Private Repositories

If the target repository is **private** (e.g., on GitHub), Git will prompt you for credentials in your terminal (where `streamlit run dashboard.py` is running). You have two options:

#### Option 1: Embed credentials in the URL (Quick & Simple)

Use the HTTPS URL format with your **username** and a **Personal Access Token (PAT)**:

```
https://<username>:<personal-access-token>@github.com/Life-Atlas/private-repo.git
```

For example:
```
https://naman:ghp_xxxxxxxxxxxxxxxxxxxx@github.com/Life-Atlas/boardy-agents.git
```

> ⚠️ **Security Warning:** Do not share URLs containing your PAT. Generate a fine-grained token with minimal permissions (read-only repository access) from [GitHub Settings → Developer Settings → Personal Access Tokens](https://github.com/settings/tokens).

#### Option 2: Configure Git Credential Storage (Recommended)

Set up Git credential caching so you only need to authenticate once:

```bash
# Cache credentials in memory for 1 hour
git config --global credential.helper 'cache --timeout=3600'

# OR store credentials permanently (less secure)
git config --global credential.helper store
```

Then, the first time the dashboard clones a private repo, enter your username and PAT in the terminal. Subsequent clones will use cached credentials.

#### Option 3: Use SSH URLs

If you have SSH keys configured with GitHub:

```
git@github.com:Life-Atlas/boardy-agents.git
```

This works seamlessly if your SSH agent is running and your key is added.

---

## 🎯 GLASS Scorecard Methodology

ZeroClaw implements the **GLASS** (Global LifeAtlas Application Security Score) metric to assign a safety score from **0.0** (highly vulnerable) to **10.0** (pristine) to each codebase.

### How It Works

The scorecard starts at a base score of `10.0` and applies deductions for every **active, real vulnerability finding** (excluding marked false positives and verified fixes):

| Severity | Deduction per Finding | Target Vulnerability Indicators |
|:---|:---|:---|
| **Critical** | `-2.5` | Committed `.env` files, hardcoded database credentials, raw secrets |
| **High** | `-1.5` | Unprotected API endpoints, missing RLS, raw SQLi, active XSS vectors |
| **Medium** | `-0.75` | Vulnerable packages (known CVEs), floating/unpinned versions, command injection |
| **Low** | `-0.25` | Unpinned packages without severe CVE listings |
| **Info** | `-0.0` | Configuration warnings and architectural annotations |

### Score Interpretation

| Score Range | Status | Meaning |
|:---|:---|:---|
| **8.0 – 10.0** | 🟢 Clean | Minimal or no active vulnerabilities |
| **5.0 – 7.9** | 🟡 Caution | Moderate risk, remediation recommended |
| **0.0 – 4.9** | 🔴 Critical | Severe vulnerabilities requiring immediate action |

> **Notes:**
> - The score is floored at `0.0` (scores cannot be negative) and rounded to 1 decimal place.
> - Findings marked as **"Verified"** (confirmed fixed via auto-verification) are excluded from the score calculation.
> - The dashboard scorecard uses slightly different weights (`-3.0` for Critical, `-2.0` for High, `-1.0` for Medium, `-0.5` for Low) to provide a more aggressive risk signal in the UI.

---

## 🧪 Developer Testing & Verification

ZeroClaw uses a test-driven development flow. All development gates are governed by tests.

### Run the Full Test Suite

```bash
# Via Make:
make test

# Via pytest directly:
PYTHONPATH="src" pytest tests/ -v --tb=short
```

### Test Individual Scanners

```bash
# Secret Scanner
PYTHONPATH="src" pytest tests/test_secret_scanner.py -v

# Dependency Scanner
PYTHONPATH="src" pytest tests/test_dependency_scanner.py -v

# Pattern Scanner
PYTHONPATH="src" pytest tests/test_pattern_scanner.py -v

# Auth & RLS Scanner
PYTHONPATH="src" pytest tests/test_auth_scanner.py -v

# API Security Tester
PYTHONPATH="src" pytest tests/test_api_security_tester.py -v

# Agent Client (ZeroClaw Rust Agent integration)
PYTHONPATH="src" pytest tests/test_agent_client.py -v
```

### Run Lints and Type Checking

```bash
make lint
# Equivalent to:
# ruff check src/ tests/
# mypy src/ --ignore-missing-imports
```

### Auto-Verification of Fixes

When a finding's status is changed to **"Fixed"** in the dashboard, the system automatically re-runs the relevant scanner against the original file to confirm the vulnerability is resolved:

- **If the issue is gone** → Status is upgraded to **"Verified"** ✅
- **If the issue persists** → Status is set to **"Fixed (unverified)"** ❌

You can also run verification manually from the CLI:

```bash
python verify_fix.py <FINDING_ID>
# Example: python verify_fix.py AUTH-007
```

---

## 🔮 Future Work: Scaling ZeroClaw Security Engine

This section outlines the strategic roadmap for Stream 5 (Security) to mature ZeroClaw from an internal Python tool into an enterprise-grade, Multi-Agent DevSecOps platform.

---

### 1. Migration to a Next.js / React Security Platform

**The Idea:** Transition from the current Streamlit dashboard to a native Next.js/React frontend with a persistent backend (Supabase/FastAPI) to integrate seamlessly with the LPI Platform (Stream 6).

**Why it matters:**
- **Scale:** Streamlit is excellent for prototyping but lacks component-level control, real-time WebSocket state management, and custom authentication flows needed for production.
- **Integration:** A Next.js frontend allows native injection of UI components into the central LPI dashboard using standard React hooks.
- **Performance:** A decoupled FastAPI backend running Python scanners asynchronously allows the UI to remain responsive during deep repository audits.

**Approach:**
- **Backend:** Wrap `cli.py` logic into isolated FastAPI async workers (Celery/Redis queues).
- **Database:** Migrate `findings_tracker.json` to a Supabase PostgreSQL database, linking findings to authenticated user IDs and stream teams.
- **Frontend:** Build a Next.js dashboard with TailwindCSS, featuring real-time SSE to update progress as the scanner processes directories.

---

### 2. Dynamic Application Security Testing (DAST) via LLM Agents

**The Idea:** Evolve beyond static analysis. Implement dynamic runtime fuzzing using AI agents to detect SSRF, BOLA, and race conditions.

**Why it matters:** Static analysis cannot catch vulnerabilities that only manifest at runtime (e.g., a malicious URL passed into a PDF generator).

**Approach:**
- **Ephemeral Environments:** Spin up target repos in isolated Docker containers on scan trigger.
- **"Attacker" Agent:** Deploy an LLM agent equipped with `requests`/`Playwright`, fed the target's OpenAPI schema.
- **Stateful Fuzzing:** The agent autonomously interacts with the live API — swapping JWT claims, attempting path traversals on upload endpoints.
- **Zero False Positives:** Because exploits are proven at runtime, DAST findings have a functionally 0% false-positive rate.

---

### 3. Cost-Optimized Remediation Pipeline

**The Idea:** Implement architectural protections to keep the AI remediation pipeline economically viable at scale.

**Why it matters:** Sending every minor finding to an LLM will exhaust API budgets and trigger rate limits, paralyzing CI/CD.

**Approach:**
- **Semantic Caching Layer:** Use a vector database (ChromaDB / Supabase pgvector). Before sending a finding to the LLM, embed the code snippet and search. If a 95%+ similar vulnerability was previously remediated, retrieve the cached fix instantly for $0.
- **100% Local Fallback (Ollama):** Bundle a local Ollama daemon running a quantized coding model (e.g., `qwen2.5-coder:7b`) into the scanner's Docker image for free, private remediation.

---

### 4. Automated PR Generation (Self-Healing Ecosystem)

**The Idea:** Move from *telling* developers what to fix to *doing* it for them.

**Why it matters:** A `fixed_code` snippet in the dashboard still requires manual copy-paste, testing, and committing.

**Approach:**
- Integrate `PyGithub` to fork the target repository, apply the string replacement patch to the specific file and line, and open a Pull Request titled: *"Security Patch: Resolving [PATTERN-0001] via ZeroClaw Sentinel."*
- The developer only needs to review the diff and click "Merge."

---

### 5. Software Supply Chain Attestation (SLSA)

**The Idea:** Secure the pipeline that builds the code, not just the code itself.

**Why it matters:** Scanning `requirements.txt` doesn't prove the final Docker image matches the scanned code.

**Approach:**
- Implement cryptographic signing via `Sigstore/Cosign`.
- When ZeroClaw finishes an audit with a "Clean" status, it signs the commit hash and generates an SBOM.
- The LPI Gateway refuses traffic to containers lacking a valid ZeroClaw cryptographic signature, enforcing zero-trust deployments.

---

## 📚 Quick Reference

| Action | Command |
|---|---|
| **Launch Dashboard** | `streamlit run dashboard.py` |
| **Run CLI Scan** | `python -m zeroclaw.cli scan --target /path/to/repo` |
| **Run CLI Scan (no AI)** | `python -m zeroclaw.cli scan --target . --no-enrich` |
| **Print Terminal Report** | `python -m zeroclaw.cli report --format terminal` |
| **Print JSON Report** | `python -m zeroclaw.cli report --format json` |
| **Run Tests** | `make test` |
| **Run Lints** | `make lint` |
| **Verify a Fix** | `python verify_fix.py AUTH-007` |
| **Install (editable)** | `pip install -e ".[dev]"` |

---

<div align="center">
<sub>ZeroClaw Security · Stream 5 · Phase 4 · Amity 2026 Spring Cohort</sub>
</div>
