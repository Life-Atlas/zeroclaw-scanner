"""Automated injection tester: SQLi + XSS payloads against FastAPI endpoints."""
import json
import time
from datetime import datetime
from pathlib import Path

import httpx

# ── Payloads ────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users;--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "admin'--",
    "1' AND SLEEP(5)--",
    "1' AND 1=2--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

# ── Endpoints to test ───────────────────────────────────────────────────────

ENDPOINTS = [
    {
        "method": "GET",
        "path": "/search",
        "param_type": "query",
        "param_name": "q",
    },
    {
        "method": "GET",
        "path": "/profile/{value}",
        "param_type": "path",
        "param_name": "user_id",
    },
    {
        "method": "POST",
        "path": "/login",
        "param_type": "body",
        "param_name": "username",
    },
    {
        "method": "GET",
        "path": "/greet",
        "param_type": "query",
        "param_name": "name",
    },
    {
        "method": "GET",
        "path": "/comment",
        "param_type": "query",
        "param_name": "text",
    },
]

# ── Helpers ─────────────────────────────────────────────────────────────────

SQLI_ERROR_SIGNALS = [
    "syntax error",
    "sql",
    "mysql",
    "sqlite",
    "postgresql",
    "ora-",
    "unclosed quotation",
    "unterminated",
    "warning",
    "stack trace",
    "traceback",
]

XSS_SIGNALS = [
    "<script>",
    "onerror=",
    "onload=",
    "javascript:",
    "<svg",
    "<img",
]


def get_baseline(client: httpx.Client, base_url: str, endpoint: dict) -> dict:
    """Get baseline response with safe input."""
    return fire_request(client, base_url, endpoint, "safe_baseline_input")


def fire_request(client: httpx.Client, base_url: str, endpoint: dict, payload: str) -> dict:
    """Fire a single request and return response details."""
    start = time.time()
    try:
        if endpoint["param_type"] == "query":
            url = f"{base_url}{endpoint['path']}"
            resp = client.request(endpoint["method"], url, params={endpoint["param_name"]: payload})
        elif endpoint["param_type"] == "path":
            url = f"{base_url}{endpoint['path'].replace('{value}', payload)}"
            resp = client.request(endpoint["method"], url)
        elif endpoint["param_type"] == "body":
            url = f"{base_url}{endpoint['path']}"
            resp = client.request(endpoint["method"], url, json={endpoint["param_name"]: payload})
        else:
            return {}

        latency = round((time.time() - start) * 1000, 2)
        return {
            "status": resp.status_code,
            "body": resp.text,
            "headers": dict(resp.headers),
            "latency_ms": latency,
        }
    except Exception as e:
        return {"error": str(e), "latency_ms": 0}


def check_sqli_verdict(baseline: dict, injected: dict, payload: str) -> str:
    """Determine SQLi verdict."""
    body = injected.get("body", "").lower()
    latency = injected.get("latency_ms", 0)

    for signal in SQLI_ERROR_SIGNALS:
        if signal in body:
            return "VULNERABLE"

    if payload in injected.get("body", ""):
        return "VULNERABLE"

    if latency > 4000 and "SLEEP" in payload.upper():
        return "VULNERABLE"

    if injected.get("status") != baseline.get("status"):
        return "INCONCLUSIVE"

    return "NOT VULNERABLE"


def check_xss_verdict(injected: dict, payload: str) -> str:
    """Determine XSS verdict."""
    body = injected.get("body", "")
    headers = injected.get("headers", {})

    for signal in XSS_SIGNALS:
        if signal in body:
            return "VULNERABLE"

    csp = headers.get("content-security-policy", "")
    if not csp:
        return "INCONCLUSIVE — No CSP header"

    return "NOT VULNERABLE"


# ── Main runner ──────────────────────────────────────────────────────────────

def run_injection_tests(base_url: str = "http://localhost:8000") -> list[dict]:
    """Run all SQLi and XSS tests against the target."""
    findings = []

    with httpx.Client(timeout=10.0) as client:
        for endpoint in ENDPOINTS:
            baseline = get_baseline(client, base_url, endpoint)

            # SQLi tests
            for payload in SQLI_PAYLOADS:
                injected = fire_request(client, base_url, endpoint, payload)
                verdict = check_sqli_verdict(baseline, injected, payload)
                findings.append({
                    "test_type": "SQLi",
                    "endpoint": endpoint["path"],
                    "parameter": endpoint["param_name"],
                    "payload": payload,
                    "baseline_status": baseline.get("status"),
                    "injected_status": injected.get("status"),
                    "latency_ms": injected.get("latency_ms"),
                    "verdict": verdict,
                })

            # XSS tests
            for payload in XSS_PAYLOADS:
                injected = fire_request(client, base_url, endpoint, payload)
                verdict = check_xss_verdict(injected, payload)
                findings.append({
                    "test_type": "XSS",
                    "endpoint": endpoint["path"],
                    "parameter": endpoint["param_name"],
                    "payload": payload,
                    "baseline_status": baseline.get("status"),
                    "injected_status": injected.get("status"),
                    "latency_ms": injected.get("latency_ms"),
                    "verdict": verdict,
                })

    return findings


def save_report(findings: list[dict], output_dir: Path) -> None:
    """Save findings as JSON and Markdown."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Save JSON
    json_path = output_dir / f"injection_report_{timestamp}.json"
    json_path.write_text(json.dumps(findings, indent=2))
    print(f"JSON report saved: {json_path}")

    # Save Markdown
    md_path = output_dir / f"injection_report_{timestamp}.md"
    lines = [
        "# Injection Test Report\n",
        f"**Date:** {timestamp}\n",
        f"**Total Tests:** {len(findings)}\n",
        f"**Vulnerable:** {sum(1 for f in findings if f['verdict'] == 'VULNERABLE')}\n",
        f"**Not Vulnerable:** {sum(1 for f in findings if f['verdict'] == 'NOT VULNERABLE')}\n",
        f"**Inconclusive:** {sum(1 for f in findings if 'INCONCLUSIVE' in f['verdict'])}\n\n",
        "## Results\n\n",
        "| Type | Endpoint | Parameter | Payload | Status | Latency | Verdict |\n",
        "|------|----------|-----------|---------|--------|---------|--------|\n",
    ]
    for f in findings:
        lines.append(
            f"| {f['test_type']} | {f['endpoint']} | {f['parameter']} "
            f"| `{f['payload'][:30]}` | {f['injected_status']} "
            f"| {f['latency_ms']}ms | **{f['verdict']}** |\n"
        )
    md_path.write_text("".join(lines))
    print(f"Markdown report saved: {md_path}")


if __name__ == "__main__":
    import sys
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    print(f"Running injection tests against: {base_url}")
    findings = run_injection_tests(base_url)
    save_report(findings, Path("reports"))
    print(f"\nDone! {len(findings)} tests run.")
    vulnerable = [f for f in findings if f["verdict"] == "VULNERABLE"]
    if vulnerable:
        print(f"\n🚨 {len(vulnerable)} VULNERABLE findings!")
        for v in vulnerable:
            print(f"  - {v['test_type']} | {v['endpoint']} | {v['payload'][:40]}")
    else:
        print("\n✅ No vulnerabilities found.")