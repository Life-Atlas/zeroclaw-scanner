"""Auth scanner: detect unprotected endpoints, missing RLS."""
from pathlib import Path

from zeroclaw.models import Finding


def scan_fastapi_auth(target_dir: Path) -> list[Finding]:
    """Check FastAPI routes for missing auth dependencies."""
    raise NotImplementedError("Phase 3 task: Kailash implements this")


def scan_supabase_rls(target_dir: Path) -> list[Finding]:
    """Check Supabase migrations for missing RLS policies."""
    raise NotImplementedError("Phase 3 task: Sania implements this")
