# Security Scan Report

**Target Directory:** `C:\Users\mrvar\lpi-platform`

## Pattern Scanner

No findings.

## Auth Scanner (FastAPI)

- **[HIGH]** Unprotected FastAPI Route: `src\lpi\main.py:16`
- **[HIGH]** Unprotected FastAPI Route: `src\lpi\routers\goals.py:32`
- **[HIGH]** Unprotected FastAPI Route: `src\lpi\routers\goals.py:59`
- **[HIGH]** Unprotected FastAPI Route: `src\lpi\routers\goals.py:82`
- **[HIGH]** Unprotected FastAPI Route: `src\lpi\routers\goals.py:99`
- **[HIGH]** Unprotected FastAPI Route: `src\lpi\routers\goals.py:160`
- **[HIGH]** Unprotected FastAPI Route: `src\lpi\routers\recommendations.py:8`
- **[HIGH]** Unprotected FastAPI Route: `src\lpi\routers\signals.py:8`
- **[HIGH]** Unprotected FastAPI Route: `src\lpi\routers\signals.py:14`

## Auth Scanner (Supabase RLS)

No findings.

## Secret Scanner

No findings.

## Dependency Scanner

- **[MEDIUM]** Unpinned dependency: fastapi: `C:\Users\mrvar\lpi-platform\pyproject.toml:11`
- **[MEDIUM]** Unpinned dependency: uvicorn: `C:\Users\mrvar\lpi-platform\pyproject.toml:12`
- **[MEDIUM]** Unpinned dependency: pydantic: `C:\Users\mrvar\lpi-platform\pyproject.toml:13`
- **[MEDIUM]** Unpinned dependency: pydantic-settings: `C:\Users\mrvar\lpi-platform\pyproject.toml:14`
- **[MEDIUM]** Unpinned dependency: supabase: `C:\Users\mrvar\lpi-platform\pyproject.toml:15`
- **[MEDIUM]** Unpinned dependency: httpx: `C:\Users\mrvar\lpi-platform\pyproject.toml:16`
- **[MEDIUM]** Unpinned dependency: python-dotenv: `C:\Users\mrvar\lpi-platform\pyproject.toml:17`

