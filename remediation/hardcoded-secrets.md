# Finding: Hardcoded Secrets

## Why it's dangerous
Hardcoding API keys, credentials, private certificates, or tokens directly in your code deposits them in clear text inside the repository. Anyone with access to the source code or git history can read them and hijack your external services (like databases, Anthropic/OpenAI, or AWS).

## How to fix it
Remove all hardcoded secrets from code files. Store them in a secure environment configuration file (`.env`) that is listed in your `.gitignore`, and reference them at runtime using environmental variable lookup APIs or a secret vault.

## Before (vulnerable)
```python
# Secret is exposed in plain text in the codebase
API_KEY = "sk-ant-abc123xyz"
```

## After (fixed)
```python
# Secret is resolved dynamically from the environment
import os
API_KEY = os.getenv("API_KEY")
```
