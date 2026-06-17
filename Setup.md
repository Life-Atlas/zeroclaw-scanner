# ZeroClaw Scanner Setup Guide

This guide explains how to install and configure the **ZeroClaw Scanner** and the underlying **ZeroClaw Rust Agent** on a new client device or server.

## Prerequisites

Before starting, ensure the target system has the following installed:
- **Python 3.10+** (with `pip`)
- **Rust & Cargo** (Required to install the ZeroClaw binary)
  ```bash
  # Install Rust via rustup if not already installed
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

---

## 1. Install the ZeroClaw Rust Agent

The Python scanner relies on the core ZeroClaw Rust binary to perform AI enrichment. 

1. Install the binary using Cargo:
   ```bash
   cargo install zeroclaw
   ```
2. Verify the installation:
   ```bash
   ~/.cargo/bin/zeroclaw --version
   ```

---

## 2. Install the Python Scanner Package

Clone this repository and install the Python package. We recommend using a virtual environment or installing it system-wide using `pipx`.

```bash
# Clone the repository (if not already done)
git clone <repository-url>
cd zeroclaw-scanner

# Option A: Install via Pipx (Recommended for global CLI usage)
pipx install .

# Option B: Install into a local virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

---

## 3. Configure the ZeroClaw Agent

The agent requires a configuration file at `~/.zeroclaw/config.toml` to define its model provider, risk profile, and alias. 

1. Create the `~/.zeroclaw` directory if it doesn't exist:
   ```bash
   mkdir -p ~/.zeroclaw
   ```
2. Create or edit `~/.zeroclaw/config.toml` with the following configuration. 

> [!IMPORTANT]
> **Free Tier Consideration:** If you are using OpenRouter's free tier, many free models reject API payloads that include "tools" or function-calling arrays. The model `google/gemma-4-31b-it:free` is specifically configured below because it correctly handles these payloads without returning a 404 error.

```toml
schema_version = 3

[providers.models.openrouter.scanner]
# Recommended free model that supports the ZeroClaw tool payload
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

---

## 4. Set the OpenRouter API Key

The agent uses OpenRouter to communicate with LLMs. You must provide an OpenRouter API key.

1. Get a free API key from [OpenRouter](https://openrouter.ai/keys).
2. Set the key in your environment. You can add this to your `~/.bashrc` or `~/.zshrc`:
   ```bash
   export OPENROUTER_API_KEY="sk-or-v1-your-key-here"
   ```

*(Alternatively, you can securely store the key directly inside the ZeroClaw config by running: `~/.cargo/bin/zeroclaw config set providers.models.openrouter.scanner.api_key`)*

---

## 5. Run the Scanner

Once everything is installed and the API key is set, you can run the scanner against any target directory.

```bash
# Example: Scan a target directory
python -m zeroclaw.cli scan --target /path/to/target/codebase
```

The scanner will execute 3 phases:
1. **Static Analysis**: Scans for secrets, dependencies, and code patterns.
2. **Enrichment**: Sends the findings to the ZeroClaw agent to generate remediation steps and fixed code.
3. **Reporting**: Outputs the AI-enriched findings.
