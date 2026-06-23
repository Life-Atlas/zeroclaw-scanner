# 6-Stream Ecosystem Catalog & Tech Stack
**Owner:** Stream 5 (Security)  
**Last Updated:** 2026-05-28  

## Objective
Map the technological footprint of all 6 Amity 2026 Spring intern streams to define the security scanning scope, required tools, and integration phases for the central security dashboard.

---

### Stream 1: Boardy AI
* **Lead:** Shubham Kumar
* **Target Repositories:** `boardy-agents` (deprecated), `new-repo`
* **Expected Tech Stack:** * **AI Agents:** PydanticAI, Claude 3.5 Haiku (Structured Extraction)
  * **Vector Space:** pgvector extension (Supabase PostgreSQL), Embedding/Reranker APIs (all-MiniLM-L6-v2)
  * **Integrations:** Retell AI (Conversational Voice Platform), Resend (Transactional Email)
  * **Testing:** pytest, pytest-asyncio
* **Security Phasing:** Phase 2 (AI Data Pipeline Audit & Semantic Validation)
* **Required SAST Tools:** `pip-audit`, `bandit` (Python)

### Stream 2: DataPro+ 
* **Lead:** Saima
* **Target Repositories:** `DataCenter-flow`, `DataCenterBackend`
* **Expected Tech Stack:**
  * **Frontend:** React 19, TypeScript, Vite, Tailwind CSS, Leaflet, Cesium (3D Integration via VSAB), Custom NDA UI
  * **Backend:** FastAPI (Python), Uvicorn, Pydantic, Google Gemini AI (PDF Extraction), Python Dotenv
  * **Database/Auth:** Supabase (PostgreSQL, Auth, Storage, Row Level Security)
  * **Infrastructure:** Docker, Traefik (Reverse Proxy), Netlify (Frontend Hosting)
* **Security Phasing:** Phase 2 (PII Vaulting & Supabase RLS Validation)
* **Required SAST Tools:** `npm audit` (Frontend), `pip-audit`, `bandit` (Backend)

### Stream 3: VSAB (Manufacturing Digital Twins)
* **Lead:** Sanskriti
* **Target Repositories:** `VSAB dashboard`, `vsab-data-dashboard`, `factory-twin`
* **Expected Tech Stack:** * **Backend/Data:** Python 3.10+, pandas, SQLAlchemy 2.x, Alembic, PostgreSQL (psycopg2)
  * **UI:** Streamlit, plotly, openpyxl
  * **Automation/Scheduling:** Playwright (Headless Browser), APScheduler
  * **Infrastructure/CI-CD:** Docker, Docker Compose, AWS (ECS/Fargate), Terraform, GitHub Actions
  * **Monitoring/Secrets:** Sentry, Prometheus, Grafana, AWS Secrets Manager, GitHub Secrets
* **Security Phasing:** Phase 3 (Container Orchestration, IaC Audit, & SSRF Prevention)
* **Required SAST Tools:** `pip-audit`, `bandit` (Python), `tfsec` / `checkov` (Terraform)

### Stream 4: Altiostar
* **Lead:** Ananyaa M
* **Target Repositories:** `AltioStar-tokyo-mro`
* **Expected Tech Stack:** Python (`py`), Deployment Configurations (`yml`), Documentation (`md`)
* **Security Phasing:** Phase 2 (Script & Configuration Hardening)
* **Required SAST Tools:** `pip-audit`, `bandit` (Python)

### Stream 5: Security (ZeroClaw)
* **Lead:** Naman Anand
* **Target Repositories:** `claw-auth-proxy`, `zeroclaw-la-fork`, `zeroclaw-scanner`
* **Expected Tech Stack:** Python (FastAPI), Rust Workspace (Multi-crate runtime), TypeScript/React, Docker, Gitleaks, OWASP ZAP
* **Security Phasing:** Phase 1 (Internal Infrastructure Setup & Vulnerability Mapping)
* **Required SAST Tools:** `pip-audit`, `bandit` (Proxy), `cargo audit` (Rust Runtime), `npm audit` (Dashboard)

### Stream 6: LPI Platform
* **Lead:** Jaivardhan
* **Target Repositories:** `lpi-platform`
* **Expected Tech Stack:** * **Core Stack:** Python, FastAPI, Supabase (Identity & RLS), React (Frontend)
  * **Architecture Layer:** LPI MCP Server (Model Context Protocol reference implementation)
  * **Methodology:** SMILE framework integration
* **Security Phasing:** Phase 3 (Cross-Stream Authentication Layer & API Specification Audit)
* **Required SAST Tools:** `pip-audit`, `bandit` (Backend), `npm audit` (Frontend)

---

## 🛠️ Global Security Scanning Requirements

Based on the completed catalog, our scanning infrastructure can be highly streamlined:
1. **Python Dominance:** 5 out of 6 streams use Python as their backend execution language. Our automated `pip-audit` and `bandit` pipelines will cover over 80% of the entire ecosystem.
2. **Supabase Dependency:** Streams 1, 2, 5, and 6 rely heavily on Supabase for data and authentication. Our custom OWASP checklist validation tool *must* prioritize Supabase RLS policy scans.
3. **Infrastructure as Code (IaC):** Stream 3 requires specialized static analysis configuration (`tfsec` or `checkov`) to scan cloud configurations prior to AWS landing.
