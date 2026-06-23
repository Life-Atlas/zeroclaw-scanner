# ZeroClaw Security Remediation Guide

This guide details the 7 primary types of security findings identified by the ZeroClaw scanners across the LifeAtlas Ecosystem streams, explaining why they are dangerous and providing step-by-step remediation guidance with before-and-after code blocks.

---

## 1. SQL Injection (SQLi)
- **Why it's dangerous**: Allows attackers to manipulate SQL queries executed by the backend, giving them unauthorized access to read, modify, or delete sensitive data, and potentially bypass login mechanisms.
- **How to fix it**: Always use parameterized queries (prepared statements). Never interpolate variables directly into SQL queries using f-strings or format strings.
- **Before (Vulnerable)**:
  ```python
  cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
  ```
- **After (Fixed)**:
  ```python
  cursor.execute("SELECT * FROM users WHERE name = %s", (user_input,))
  ```

---

## 2. Cross-Site Scripting (XSS)
- **Why it's dangerous**: Attackers can inject malicious scripts into web pages viewed by other users. This allows them to steal cookies, hijack sessions, deface the website, or redirect users to malicious URLs.
- **How to fix it**: Use safe APIs like `textContent` (or `innerText`) rather than assigning user-controlled input to `innerHTML`. If rendering HTML is necessary, parse and sanitize it first using a library like DOMPurify.
- **Before (Vulnerable)**:
  ```javascript
  element.innerHTML = userInput;
  ```
- **After (Fixed)**:
  ```javascript
  element.textContent = userInput;
  ```

---

## 3. Command Injection
- **Why it's dangerous**: Allows an attacker to run arbitrary shell commands on the hosting server, which can lead to complete server takeover, sensitive data theft, or service disruption.
- **How to fix it**: Avoid invoking the system shell (`shell=True`). Always execute commands directly by passing arguments as a list.
- **Before (Vulnerable)**:
  ```python
  subprocess.call(f"ls {user_input}", shell=True)
  ```
- **After (Fixed)**:
  ```python
  subprocess.call(["ls", user_input], shell=False)
  ```

---

## 4. Hardcoded Secrets
- **Why it's dangerous**: Storing API keys, database credentials, passwords, or tokens in source code leaks them to anyone with read access to the repository. They are also permanently stored in the Git history.
- **How to fix it**: Externalize configuration. Load all credentials from environment variables (`.env`) or fetch them from a dedicated secrets manager at runtime.
- **Before (Vulnerable)**:
  ```python
  API_KEY = "sk-ant-abc123xyz"
  ```
- **After (Fixed)**:
  ```python
  import os
  API_KEY = os.getenv("API_KEY")
  ```

---

## 5. Unpinned Dependencies
- **Why it's dangerous**: Floating dependency versions (e.g. `fastapi`) allow package managers to fetch the latest release automatically. This can break production builds due to API changes or silently pull in compromised releases (supply chain attack).
- **How to fix it**: Pin all packages to exact versions in configuration files (e.g., `requirements.txt` or `package.json`).
- **Before (Vulnerable)**:
  ```
  fastapi
  requests
  ```
- **After (Fixed)**:
  ```
  fastapi==0.115.0
  requests==2.32.3
  ```

---

## 6. Unprotected FastAPI Routes
- **Why it's dangerous**: Sensitive endpoints can be queried by anyone on the internet, leaking internal data or exposing administrative functions without authentication checks.
- **How to fix it**: Wrap the route endpoints using FastAPI's dependency injection (`Depends(...)`) to validate authentication tokens before handling requests.
- **Before (Vulnerable)**:
  ```python
  @app.get("/users")
  def get_users():
      return db.get_all_users()
  ```
- **After (Fixed)**:
  ```python
  from fastapi import Depends
  from auth import get_current_user

  @app.get("/users")
  def get_users(user=Depends(get_current_user)):
      return db.get_all_users()
  ```

---

## 7. Missing Supabase RLS (Row Level Security)
- **Why it's dangerous**: Supabase tables exposed via the client API can be accessed, read, or modified by any user if Row Level Security is disabled, even if they aren't authenticated.
- **How to fix it**: Enable RLS on the table and define targeted security policies to restrict queries based on user auth tokens.
- **Before (Vulnerable)**:
  ```sql
  -- Table is public and unrestricted
  ```
- **After (Fixed)**:
  ```sql
  ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
  CREATE POLICY "Users can only see own data"
  ON profiles FOR SELECT
  USING (auth.uid() = user_id);
  ```
