"""API Security Tester for dynamic analysis of auth bypass, rate limiting, and session security."""
from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Any
import httpx
from fastapi import FastAPI

logger = logging.getLogger(__name__)


class SecurityTestError(AssertionError):
    """Raised when a security test fails."""
    pass


def run_async(coro) -> Any:
    """Run an async coroutine synchronously, handling any active event loops."""
    try:
        return asyncio.run(coro)
    except RuntimeError:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, coro)
            return future.result()


class APISecurityTester:
    """Utility class to dynamically test FastAPI applications for security vulnerabilities."""

    @staticmethod
    def test_auth_bypass(app: FastAPI, protected_routes: list[dict[str, Any]]) -> None:
        """
        Verify that protected endpoints reject unauthorized requests.

        For each route in protected_routes:
        - Hits the route without an auth token -> expects 401 or 403.
        - Hits the route with an expired token -> expects 401 or 403.
        - Hits the route with an incorrect user role -> expects 403.

        Each route dict can specify:
        - 'path' (str): the target endpoint path (required)
        - 'method' (str): HTTP method, e.g., 'GET', 'POST' (default 'GET')
        - 'params' (dict): query parameters (optional)
        - 'json' (dict): JSON body (optional)
        - 'headers' (dict): normal/base headers (optional)
        - 'cookies' (dict): normal/base cookies (optional)
        - 'expired_headers' (dict): headers for expired token test (optional)
        - 'expired_cookies' (dict): cookies for expired token test (optional)
        - 'wrong_role_headers' (dict): headers for wrong role test (optional)
        - 'wrong_role_cookies' (dict): cookies for wrong role test (optional)
        """
        async def run():
            failures = []
            transport = httpx.ASGITransport(app=app)

            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                for idx, route in enumerate(protected_routes):
                    path = route.get("path")
                    if not path:
                        failures.append(f"Route at index {idx} is missing 'path'.")
                        continue

                    method = route.get("method", "GET").upper()
                    params = route.get("params")
                    json_body = route.get("json")
                    base_headers = route.get("headers") or {}
                    base_cookies = route.get("cookies") or {}

                    # 1. No Auth Check
                    # Remove any authorization headers or session cookies
                    no_auth_headers = {k: v for k, v in base_headers.items() if k.lower() != "authorization"}
                    no_auth_cookies = {k: v for k, v in base_cookies.items() if "session" not in k.lower()}

                    client.cookies.clear()
                    client.cookies.update(no_auth_cookies)

                    try:
                        response = await client.request(
                            method=method,
                            url=path,
                            params=params,
                            json=json_body,
                            headers=no_auth_headers,
                        )
                        if response.status_code not in (401, 403):
                            failures.append(
                                f"Auth Bypass Check Failed: Endpoint {method} {path} with no auth headers "
                                f"returned {response.status_code} instead of 401/403."
                            )
                    except Exception as e:
                        failures.append(f"Auth Bypass Check Error on {method} {path} (No Auth): {e}")

                    # 2. Expired Token Check
                    expired_headers = route.get("expired_headers")
                    expired_cookies = route.get("expired_cookies")

                    # Fallback to dummy values if not provided
                    if not expired_headers and not expired_cookies:
                        expired_headers = {"Authorization": "Bearer expired_token_xyz"}

                    req_headers = {**base_headers, **(expired_headers or {})}
                    req_cookies = {**base_cookies, **(expired_cookies or {})}

                    client.cookies.clear()
                    client.cookies.update(req_cookies)

                    try:
                        response = await client.request(
                            method=method,
                            url=path,
                            params=params,
                            json=json_body,
                            headers=req_headers,
                        )
                        if response.status_code not in (401, 403):
                            failures.append(
                                f"Auth Bypass Check Failed: Endpoint {method} {path} with expired credentials "
                                f"returned {response.status_code} instead of 401/403."
                            )
                    except Exception as e:
                        failures.append(f"Auth Bypass Check Error on {method} {path} (Expired Auth): {e}")

                    # 3. Wrong Role Check
                    wrong_role_headers = route.get("wrong_role_headers")
                    wrong_role_cookies = route.get("wrong_role_cookies")

                    # Fallback to dummy values if not provided
                    if not wrong_role_headers and not wrong_role_cookies:
                        wrong_role_headers = {"Authorization": "Bearer wrong_role_token_xyz"}

                    req_headers = {**base_headers, **(wrong_role_headers or {})}
                    req_cookies = {**base_cookies, **(wrong_role_cookies or {})}

                    client.cookies.clear()
                    client.cookies.update(req_cookies)

                    try:
                        response = await client.request(
                            method=method,
                            url=path,
                            params=params,
                            json=json_body,
                            headers=req_headers,
                        )
                        # Wrong role should result in a 403 Forbidden
                        if response.status_code != 403:
                            failures.append(
                                f"Auth Bypass Check Failed: Endpoint {method} {path} with incorrect role "
                                f"returned {response.status_code} instead of 403."
                            )
                    except Exception as e:
                        failures.append(f"Auth Bypass Check Error on {method} {path} (Wrong Role): {e}")

            if failures:
                raise SecurityTestError("\n".join(failures))

        run_async(run())

    @staticmethod
    def test_rate_limiting(app: FastAPI, rate_limited_routes: list[dict[str, Any]]) -> None:
        """
        Verify that rate-limited routes enforce limits and return 429 Too Many Requests.

        For each route in rate_limited_routes:
        - Sends requests sequentially exceeding the expected limit.
        - Asserts that we eventually receive a 429 status code.

        Each route dict can specify:
        - 'path' (str): the target endpoint path (required)
        - 'method' (str): HTTP method, e.g., 'GET', 'POST' (default 'GET')
        - 'limit' (int): the configured limit before hitting 429 (default 5)
        - 'params' (dict): query parameters (optional)
        - 'json' (dict): JSON body (optional)
        - 'headers' (dict): request headers (optional)
        - 'cookies' (dict): request cookies (optional)
        """
        async def run():
            failures = []
            transport = httpx.ASGITransport(app=app)

            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                for idx, route in enumerate(rate_limited_routes):
                    path = route.get("path")
                    if not path:
                        failures.append(f"Route at index {idx} is missing 'path'.")
                        continue

                    method = route.get("method", "GET").upper()
                    limit = route.get("limit", 5)
                    params = route.get("params")
                    json_body = route.get("json")
                    headers = route.get("headers")
                    cookies = route.get("cookies") or {}

                    client.cookies.clear()
                    client.cookies.update(cookies)

                    hit_429 = False
                    status_codes = []

                    # We attempt up to limit + 10 requests to trigger rate limiting
                    max_attempts = limit + 10
                    for i in range(max_attempts):
                        try:
                            response = await client.request(
                                method=method,
                                url=path,
                                params=params,
                                json=json_body,
                                headers=headers,
                            )
                            status_codes.append(response.status_code)
                            if response.status_code == 429:
                                hit_429 = True
                                break
                        except Exception as e:
                            failures.append(f"Rate Limiting Check Error on {method} {path} at request {i+1}: {e}")
                            break

                    if not hit_429:
                        failures.append(
                            f"Rate Limiting Check Failed: Endpoint {method} {path} did not return 429 after {max_attempts} "
                            f"requests. Response status codes: {status_codes}"
                        )

            if failures:
                raise SecurityTestError("\n".join(failures))

        run_async(run())

    @staticmethod
    def test_session_security(app: FastAPI, session_routes: list[dict[str, Any]]) -> None:
        """
        Verify session fixation, session hijacking (signature tampering), and session timeout.

        Each item in session_routes can specify:
        - 'login_path' (str): login endpoint to test session fixation
        - 'login_method' (str): HTTP method for login (default 'POST')
        - 'login_data' (dict): credentials payload for login (optional)
        - 'session_cookie_name' (str): name of cookie used for sessions (optional)
        - 'session_header_name' (str): name of header or JSON response key for session tokens (optional)
        - 'protected_path' (str): a protected path to verify hijacking and timeouts (required for hijacking/timeout)
        - 'protected_method' (str): method for protected path (default 'GET')
        - 'valid_headers' (dict): valid session headers if login bypass is preferred (optional)
        - 'valid_cookies' (dict): valid session cookies if login bypass is preferred (optional)
        - 'expired_headers' (dict): expired session headers (optional)
        - 'expired_cookies' (dict): expired session cookies (optional)
        """
        async def run():
            failures = []
            transport = httpx.ASGITransport(app=app)

            for idx, route in enumerate(session_routes):
                cookie_name = route.get("session_cookie_name")
                header_name = route.get("session_header_name")
                if not cookie_name and not header_name:
                    cookie_name = "session"

                # 1. Session Fixation Check
                login_path = route.get("login_path")
                if login_path:
                    login_method = route.get("login_method", "POST").upper()
                    login_data = route.get("login_data")

                    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                        # Set pre-existing session token/cookie
                        dummy_token = "pre_existing_session_id_123456"
                        if isinstance(cookie_name, str):
                            client.cookies[cookie_name] = dummy_token
                        
                        req_headers = {}
                        if header_name:
                            req_headers[header_name] = f"Bearer {dummy_token}"

                        try:
                            response = await client.request(
                                method=login_method,
                                url=login_path,
                                json=login_data,
                                headers=req_headers,
                            )
                            
                            # Verify fixation protection without ValueError on duplicates
                            if isinstance(cookie_name, str):
                                new_cookie_val = response.cookies.get(cookie_name)
                                if not new_cookie_val:
                                    # Inspect client jar safely
                                    matching_vals = [c.value for c in client.cookies.jar if c.name == cookie_name]
                                    if len(matching_vals) == 1 and matching_vals[0] == dummy_token:
                                        failures.append(
                                            f"Session Fixation Vulnerability: Login at {login_path} did not set a new "
                                            f"session cookie '{cookie_name}'. Value remained the pre-existing '{dummy_token}'."
                                        )
                                else:
                                    if new_cookie_val == dummy_token:
                                        failures.append(
                                            f"Session Fixation Vulnerability: Login at {login_path} set session cookie "
                                            f"'{cookie_name}' but kept the pre-existing value '{dummy_token}'."
                                        )
                            
                            if header_name:
                                new_header_val = response.headers.get(header_name)
                                try:
                                    res_json = response.json()
                                    new_json_val = res_json.get(header_name) or res_json.get("access_token") or res_json.get("token")
                                except Exception:
                                    new_json_val = None

                                new_val = new_header_val or new_json_val
                                if new_val == dummy_token:
                                    failures.append(
                                        f"Session Fixation Vulnerability: Login at {login_path} did not rotate the "
                                        f"session header/token '{header_name}'. Value remained '{dummy_token}'."
                                    )

                        except Exception as e:
                            failures.append(f"Session Fixation Check Error at {login_path}: {e}")

                # 2. Session Hijacking & Tampering / Removal
                protected_path = route.get("protected_path")
                if protected_path:
                    protected_method = route.get("protected_method", "GET").upper()
                    valid_headers = route.get("valid_headers") or {}
                    valid_cookies = route.get("valid_cookies") or {}

                    # If login_path is specified and we don't have valid headers/cookies, log in dynamically
                    if not valid_headers and not valid_cookies and login_path:
                        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                            try:
                                login_method = route.get("login_method", "POST").upper()
                                login_data = route.get("login_data")
                                response = await client.request(method=login_method, url=login_path, json=login_data)
                                if response.status_code in (200, 201):
                                    valid_cookies = dict(client.cookies)
                                    try:
                                        res_json = response.json()
                                        token = res_json.get("access_token") or res_json.get("token")
                                        if token:
                                            valid_headers = {"Authorization": f"Bearer {token}"}
                                        else:
                                            cookie_val = response.cookies.get(cookie_name or "session")
                                            if cookie_val:
                                                valid_cookies = {cookie_name or "session": cookie_val}
                                    except Exception:
                                        pass
                            except Exception as e:
                                failures.append(f"Login setup for hijacking check failed: {e}")

                    # Establish baseline request works with valid credentials
                    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                        client.cookies.clear()
                        client.cookies.update(valid_cookies)
                        try:
                            res_ok = await client.request(
                                method=protected_method,
                                url=protected_path,
                                headers=valid_headers,
                            )
                            if res_ok.status_code not in (200, 201, 204):
                                logger.warning(
                                    "Baseline request for hijacking test on %s %s returned %s instead of success. "
                                    "Will proceed with tampering checks.",
                                    protected_method, protected_path, res_ok.status_code
                                )
                        except Exception as e:
                            logger.warning("Baseline request for hijacking test error: %s", e)

                        # Tamper test 1: Removal of credentials
                        client.cookies.clear()
                        try:
                            res_removed = await client.request(
                                method=protected_method,
                                url=protected_path,
                            )
                            if res_removed.status_code not in (401, 403):
                                failures.append(
                                    f"Session Hijacking / Credentials Removal Vulnerability: Protected route "
                                    f"{protected_method} {protected_path} accessed without credentials returned "
                                    f"{res_removed.status_code} instead of 401/403."
                                )
                        except Exception as e:
                            failures.append(f"Session Hijacking Removal Check Error: {e}")

                        # Tamper test 2: Modified/Corrupted credentials
                        tampered_headers = {}
                        for k, v in valid_headers.items():
                            if k.lower() == "authorization":
                                if "bearer " in v.lower():
                                    tampered_headers[k] = v + "invalidsignature"
                                else:
                                    tampered_headers[k] = v + "_tampered"
                            else:
                                tampered_headers[k] = v + "_altered"

                        tampered_cookies = {k: v + "_tampered" for k, v in valid_cookies.items()}

                        client.cookies.clear()
                        client.cookies.update(tampered_cookies)
                        if tampered_headers or tampered_cookies:
                            try:
                                res_tampered = await client.request(
                                    method=protected_method,
                                    url=protected_path,
                                    headers=tampered_headers,
                                )
                                if res_tampered.status_code not in (401, 403):
                                    failures.append(
                                        f"Session Hijacking / Signature Tampering Vulnerability: Protected route "
                                        f"{protected_method} {protected_path} accessed with tampered credentials "
                                        f"returned {res_tampered.status_code} instead of 401/403."
                                    )
                            except Exception as e:
                                failures.append(f"Session Hijacking Tampering Check Error: {e}")

                # 3. Session Timeout Check
                if protected_path:
                    expired_headers = route.get("expired_headers")
                    expired_cookies = route.get("expired_cookies")

                    if not expired_headers and not expired_cookies:
                        expired_headers = {"Authorization": "Bearer expired_session_token_123"}
                        expired_cookies = {"session": "expired_session_cookie_123"}

                    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                        client.cookies.clear()
                        client.cookies.update(expired_cookies or {})
                        try:
                            res_timeout = await client.request(
                                method=protected_method,
                                url=protected_path,
                                headers=expired_headers,
                            )
                            if res_timeout.status_code not in (401, 403):
                                failures.append(
                                    f"Session Timeout / Expiration Vulnerability: Protected route "
                                    f"{protected_method} {protected_path} accessed with expired credentials "
                                    f"returned {res_timeout.status_code} instead of 401/403."
                                )
                        except Exception as e:
                            failures.append(f"Session Timeout Check Error: {e}")

            if failures:
                raise SecurityTestError("\n".join(failures))

        run_async(run())
