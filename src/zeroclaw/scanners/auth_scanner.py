"""Auth scanner: detect unprotected endpoints, missing RLS."""
from pathlib import Path

from zeroclaw.models import Finding


def scan_fastapi_auth(target_dir: Path) -> list[Finding]:
    """Check FastAPI routes for missing auth dependencies."""
    findings: list[Finding] = []
    # Structural scaffolding for Phase 3:
    # 1. Walk target_dir for python files (*.py)
    # 2. Check each file line-by-line for route decorators (e.g. @app.get, @router.post)
    # 3. Assert if route definitions contain Depends(get_current_user) or equivalent security checks
    # 4. Generate Category.AUTH findings for routes missing these parameters
    return findings


def scan_supabase_rls(target_dir: Path) -> list[Finding]:
    """Check Supabase migrations for missing RLS policies."""
    raise NotImplementedError("Phase 3 task: Sania implements this")
