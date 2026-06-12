"""Auth scanner: detect unprotected endpoints, missing RLS."""
import ast
import logging
import os
import re
import stat
from pathlib import Path

from zeroclaw.models import Category, Finding, Severity

logger = logging.getLogger(__name__)

EXTENSIONS_PY = {".py"}
EXTENSIONS_SQL = {".sql"}

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head", "api_route"}

CREATE_TABLE_PAT = re.compile(
    r"create\s+table\s+(?:if\s+(?:not\s+)?exists\s+)?([a-zA-Z0-9_\-\"\.]+)", re.IGNORECASE
)
RLS_ENABLE_PAT = re.compile(
    r"alter\s+table\s+([a-zA-Z0-9_\-\"\.]+)\s+enable\s+row\s+level\s+security", re.IGNORECASE
)


def contains_depends_or_security(tree_node) -> bool:
    """Recursively search an AST node for any call to Depends or Security."""
    if not tree_node:
        return False
    for child in ast.walk(tree_node):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name):
                if child.func.id in {"Depends", "Security"}:
                    return True
            elif isinstance(child.func, ast.Attribute):
                if child.func.attr in {"Depends", "Security"}:
                    return True
    return False


def get_fastapi_route_decorator(node) -> ast.Call | None:
    """Return the FastAPI route decorator node if present, otherwise None."""
    for dec in node.decorator_list:
        if isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Attribute):
                if dec.func.attr in HTTP_METHODS:
                    return dec
            elif isinstance(dec.func, ast.Name):
                if dec.func.id in HTTP_METHODS:
                    return dec
    return None


def scan_fastapi_auth(target_dir: Path) -> list[Finding]:
    """Check FastAPI routes for missing auth dependencies using AST parsing."""
    findings: list[Finding] = []
    resolved_target = target_dir.resolve()

    for file_path in target_dir.rglob("*"):
        # skip symlinks
        if file_path.is_symlink():
            logger.warning("Skipping symbolic link: %s", file_path)
            continue

        # only process regular files
        if not file_path.is_file():
            continue

        if file_path.suffix not in EXTENSIONS_PY:
            continue

        fd = None
        try:
            # Boundary check using Path.resolve() before open
            resolved_file = file_path.resolve()
            if not resolved_file.is_relative_to(resolved_target):
                logger.warning("Skipping file outside target directory: %s", file_path)
                continue

            # Open file descriptor securely (O_NOFOLLOW prevents following trailing symlinks)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(resolved_file, flags)

            # Inspect metadata securely on the opened descriptor (TOCTOU fix)
            fstat_info = os.fstat(fd)
            if not stat.S_ISREG(fstat_info.st_mode):
                logger.warning("Skipping non-regular file: %s", file_path)
                os.close(fd)
                fd = None
                continue

            # Limit file size to 5MB
            if fstat_info.st_size > 5 * 1024 * 1024:
                os.close(fd)
                fd = None
                continue

            # Read securely using the file descriptor
            with os.fdopen(fd, "r", encoding="utf-8", errors="ignore") as f:
                fd = None  # os.fdopen takes ownership of the descriptor
                content = f.read()

            try:
                tree = ast.parse(content)
            except SyntaxError as e:
                logger.warning("Syntax error parsing %s: %s", file_path, e)
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    route_dec = get_fastapi_route_decorator(node)
                    if route_dec:
                        # Check protection status
                        protected = False
                        
                        # Check decorator keywords (e.g. dependencies=[Depends(...)])
                        for kw in route_dec.keywords:
                            if kw.arg == "dependencies":
                                if contains_depends_or_security(kw.value):
                                    protected = True
                                    break
                        
                        # Check function default arguments
                        if not protected:
                            for default in node.args.defaults:
                                if contains_depends_or_security(default):
                                    protected = True
                                    break
                            
                            if not protected:
                                for default in node.args.kw_defaults:
                                    if contains_depends_or_security(default):
                                        protected = True
                                        break
                        
                        if not protected:
                            route_start_line = route_dec.lineno
                            func_name = node.name
                            relative_path = str(resolved_file.relative_to(resolved_target))
                            
                            findings.append(
                                Finding(
                                    id=f"AUTH-{len(findings)+1:04d}",
                                    severity=Severity.HIGH,
                                    category=Category.AUTH,
                                    title="Unprotected FastAPI Route",
                                    description=(
                                        f"FastAPI endpoint '{func_name}' at line {route_start_line} "
                                        "does not enforce authentication/authorization checks."
                                    ),
                                    file_path=relative_path,
                                    line_number=route_start_line,
                                    remediation=(
                                        "Add Depends(get_current_user) or equivalent security "
                                        "dependency check to the route handler."
                                    ),
                                )
                            )

        except (OSError, UnicodeDecodeError) as e:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            logger.warning("Could not read file %s: %s", file_path, e)
        except Exception as e:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            logger.error("Unexpected error processing file %s: %s", file_path, e)

    return findings


def normalize_table_name(name: str) -> str:
    """Normalize a database table name by stripping quotes and lowercasing."""
    return name.strip().strip('"').strip("'").lower()


def scan_supabase_rls(target_dir: Path) -> list[Finding]:
    """Check Supabase migrations for missing RLS policies."""
    findings: list[Finding] = []
    resolved_target = target_dir.resolve()

    created_tables: dict[str, tuple[Path, int, str]] = {}
    enabled_tables: set[str] = set()

    for file_path in target_dir.rglob("*"):
        if file_path.is_symlink():
            logger.warning("Skipping symbolic link: %s", file_path)
            continue

        if not file_path.is_file():
            continue

        if file_path.suffix not in EXTENSIONS_SQL:
            continue

        fd = None
        try:
            resolved_file = file_path.resolve()
            if not resolved_file.is_relative_to(resolved_target):
                logger.warning("Skipping file outside target directory: %s", file_path)
                continue

            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(resolved_file, flags)

            fstat_info = os.fstat(fd)
            if not stat.S_ISREG(fstat_info.st_mode):
                logger.warning("Skipping non-regular file: %s", file_path)
                os.close(fd)
                fd = None
                continue

            if fstat_info.st_size > 5 * 1024 * 1024:
                os.close(fd)
                fd = None
                continue

            with os.fdopen(fd, "r", encoding="utf-8", errors="ignore") as f:
                fd = None
                content = f.read()

            # Find all table creations
            for match in CREATE_TABLE_PAT.finditer(content):
                raw_table_name = match.group(1)
                norm_name = normalize_table_name(raw_table_name)
                char_idx = match.start()
                line_num = content[:char_idx].count("\n") + 1
                if norm_name not in created_tables:
                    created_tables[norm_name] = (resolved_file, line_num, raw_table_name)

            # Find all RLS enablement
            for match in RLS_ENABLE_PAT.finditer(content):
                raw_table_name = match.group(1)
                norm_name = normalize_table_name(raw_table_name)
                enabled_tables.add(norm_name)

        except (OSError, UnicodeDecodeError) as e:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            logger.warning("Could not read SQL file %s: %s", file_path, e)
        except Exception as e:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            logger.error("Unexpected error processing SQL file %s: %s", file_path, e)

    # Reconcile created tables against enabled tables
    for norm_name, (resolved_file, line_num, original_name) in created_tables.items():
        if norm_name not in enabled_tables:
            relative_path = str(resolved_file.relative_to(resolved_target))
            findings.append(
                Finding(
                    id=f"RLS-{len(findings)+1:04d}",
                    severity=Severity.HIGH,
                    category=Category.AUTH,
                    title="Missing Row Level Security (RLS) Policy",
                    description=(
                        f"Database table '{original_name}' is created at line {line_num} "
                        "but Row Level Security (RLS) is not enabled."
                    ),
                    file_path=relative_path,
                    line_number=line_num,
                    remediation=(
                        f"Add 'ALTER TABLE {original_name} ENABLE ROW LEVEL SECURITY;' "
                        "to your migration file to enable RLS."
                    ),
                )
            )

    return findings
