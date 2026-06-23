import pytest
from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
from fastapi.responses import JSONResponse
from zeroclaw.scanners.api_security_tester import APISecurityTester, SecurityTestError

# ----------------- Helper Mock Apps -----------------

def create_secure_app() -> FastAPI:
    app = FastAPI()

    # Simple auth dependency
    def get_user(request: Request):
        auth = request.headers.get("Authorization")
        if not auth:
            raise HTTPException(status_code=401, detail="Missing token")
        if "expired" in auth:
            raise HTTPException(status_code=401, detail="Token expired")
        if "wrong_role" in auth:
            raise HTTPException(status_code=403, detail="Forbidden: wrong role")
        return {"user": "alice"}

    @app.get("/protected")
    def protected_route(user: dict = Depends(get_user)):
        return {"status": "success", "user": user}

    # Rate limiting mock (state stored in app state for simplicity in tests)
    app.state.request_count = 0

    @app.get("/rate-limited")
    def rate_limited_route():
        app.state.request_count += 1
        if app.state.request_count > 5:
            return JSONResponse(status_code=429, content={"detail": "Too many requests"})
        return {"status": "ok"}

    # Login and session management mocks
    @app.post("/login")
    def login(request: Request, response: Response):
        # Session fixation defense: always rotate session ID
        response.set_cookie(key="session", value="new_secure_session_id_789")
        return {"status": "logged_in"}

    @app.get("/session-protected")
    def session_protected(request: Request):
        cookie = request.cookies.get("session")
        if not cookie:
            raise HTTPException(status_code=401, detail="No session")
        if "tampered" in cookie or "expired" in cookie:
            raise HTTPException(status_code=401, detail="Invalid session signature or expired")
        return {"status": "ok"}

    return app


def create_vulnerable_app() -> FastAPI:
    app = FastAPI()

    # Unprotected route (vulnerable to auth bypass)
    @app.get("/protected")
    def protected_route():
        return {"status": "success", "bypass": True}

    # Endpoint with no rate limiting (vulnerable)
    @app.get("/rate-limited")
    def rate_limited_route():
        return {"status": "ok"}

    # Login route vulnerable to session fixation
    @app.post("/login")
    def login(request: Request, response: Response):
        # Does NOT rotate cookie if pre-existing
        old_session = request.cookies.get("session")
        if old_session:
            response.set_cookie(key="session", value=old_session)
            return {"status": "logged_in", "rotated": False}
        response.set_cookie(key="session", value="new_session")
        return {"status": "logged_in", "rotated": True}

    # Protected route vulnerable to hijacking (accepts tampered sessions)
    @app.get("/session-protected")
    def session_protected(request: Request):
        cookie = request.cookies.get("session")
        # Vuln 1: doesn't require session at all, or accepts tampered/expired ones
        if cookie and "tampered" in cookie:
            # Accepts tampered cookie!
            return {"status": "ok", "tampered_accepted": True}
        if not cookie:
            # Accepts missing cookie as well!
            return {"status": "ok", "no_session_accepted": True}
        return {"status": "ok"}

    return app


# ----------------- Tests for APISecurityTester -----------------

class TestAPISecurityTesterAuthBypass:
    def test_auth_bypass_passes_on_secure_app(self):
        app = create_secure_app()
        protected_routes = [
            {
                "path": "/protected",
                "method": "GET",
                "headers": {"Authorization": "Bearer valid_token"},
                "expired_headers": {"Authorization": "Bearer expired_token"},
                "wrong_role_headers": {"Authorization": "Bearer wrong_role_token"},
            }
        ]
        # Should execute without raising SecurityTestError
        APISecurityTester.test_auth_bypass(app, protected_routes)

    def test_auth_bypass_fails_on_vulnerable_app(self):
        app = create_vulnerable_app()
        protected_routes = [
            {
                "path": "/protected",
                "method": "GET",
                "headers": {"Authorization": "Bearer valid_token"},
                "expired_headers": {"Authorization": "Bearer expired_token"},
                "wrong_role_headers": {"Authorization": "Bearer wrong_role_token"},
            }
        ]
        with pytest.raises(SecurityTestError) as exc_info:
            APISecurityTester.test_auth_bypass(app, protected_routes)
        
        assert "Auth Bypass Check Failed" in str(exc_info.value)
        assert "/protected" in str(exc_info.value)


class TestAPISecurityTesterRateLimiting:
    def test_rate_limiting_passes_on_secure_app(self):
        app = create_secure_app()
        rate_limited_routes = [
            {
                "path": "/rate-limited",
                "method": "GET",
                "limit": 5,
            }
        ]
        # Should pass because secure app returns 429 on 6th request
        APISecurityTester.test_rate_limiting(app, rate_limited_routes)

    def test_rate_limiting_fails_on_vulnerable_app(self):
        app = create_vulnerable_app()
        rate_limited_routes = [
            {
                "path": "/rate-limited",
                "method": "GET",
                "limit": 5,
            }
        ]
        with pytest.raises(SecurityTestError) as exc_info:
            APISecurityTester.test_rate_limiting(app, rate_limited_routes)

        assert "Rate Limiting Check Failed" in str(exc_info.value)
        assert "/rate-limited" in str(exc_info.value)


class TestAPISecurityTesterSessionSecurity:
    def test_session_security_passes_on_secure_app(self):
        app = create_secure_app()
        session_routes = [
            {
                "login_path": "/login",
                "login_method": "POST",
                "session_cookie_name": "session",
                "protected_path": "/session-protected",
                "protected_method": "GET",
                "valid_cookies": {"session": "valid_session_123"},
                "expired_cookies": {"session": "expired_session_123"},
            }
        ]
        # Should pass cleanly
        APISecurityTester.test_session_security(app, session_routes)

    def test_session_security_fails_on_vulnerable_app(self):
        app = create_vulnerable_app()
        session_routes = [
            {
                "login_path": "/login",
                "login_method": "POST",
                "session_cookie_name": "session",
                "protected_path": "/session-protected",
                "protected_method": "GET",
                "valid_cookies": {"session": "valid_session_123"},
                "expired_cookies": {"session": "expired_session_123"},
            }
        ]
        with pytest.raises(SecurityTestError) as exc_info:
            APISecurityTester.test_session_security(app, session_routes)

        err_msg = str(exc_info.value)
        # Verify fixation vulnerability, hijacking vulnerability, or timeout vulnerability is flagged
        assert "Session Fixation" in err_msg or "Session Hijacking" in err_msg or "Session Timeout" in err_msg
