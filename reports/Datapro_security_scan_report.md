# Security Scan Report — `lifeatlas/datacenter-flow`

**Scanners run:** Auth Scanner · Pattern Scanner · Dependency Scanner · Secret Scanner

## Findings Summary

| Scanner | High | Medium | Low | Total |
|---|---|---|---|---|
| Auth Scanner | 0 | 0 | 0 | 0 |
| Pattern Scanner | 6 | 0 | 0 | 6 |
| Dependency Scanner | 2 | 1 | 0 | 3 |
| Secret Scanner | 0 | 0 | 0 | 0 |
| **Total** | **8** | **1** | **0** | **9** |

---

## ✅ Auth Scanner — 0 findings

Clean — no unprotected FastAPI routes or missing Supabase Row Level Security (RLS) policies detected.

---

## 🟡 Pattern Scanner — 6 findings (High)

XSS risk via `innerHTML` assignment.

**Where:** `src/components/map/DealMap.tsx`

| Element | Line | Notes |
|---|---|---|
| `el.innerHTML = ...` | 66 | Marker element structure containing inline SVG path |
| `<svg width="25" ...>` | 67 | Part of the marker inner HTML SVG structure |
| `<path d="..." ...>` | 68 | Part of the marker inner HTML SVG structure |
| `popupNode.innerHTML = ...` | 76 | Map popup structure containing HTML template literal |
| `<h3 class="font-bold ...>` | 77 | Template literal displaying dynamically resolved `${deal.name}` |
| `<div class="space-y-1 ...>` | 78 | Template literal displaying dynamically resolved deal attributes |

**Why it's flagged:** Assigning to `.innerHTML` lets injected HTML/JS execute in the page context.
- **Lines 66–68** contain static SVG structures with inline dynamically-injected `${stageConfig.hex}` (color hex code). The risk is extremely low as the hex code is derived from hardcoded client configuration, not direct user input.
- **Lines 76–78** contain the dynamic deal popup template. It interpolates `{deal.name}`, which is populated from backend database values. If the backend accepts unescaped, attacker-controlled text for the deal name, this becomes a **reflected/stored XSS** vulnerability when users view the deal on the map.

**Remediation:** 
1. Use safe DOM APIs (e.g. `document.createElement`, `element.textContent`, or `element.setAttribute`) to construct markers and popups dynamically.
2. If template literals are required, sanitize the interpolated values (e.g., using `DOMPurify`) before assigning to `innerHTML`.

---

## 🔴 Dependency Scanner — 3 findings (2 High, 1 Medium)

Vulnerable npm packages detected in `package.json` / `package-lock.json`.

**Where:** `package.json`

| Package | Severity | CVE / Advisory | Why it's flagged |
|---|---|---|---|
| `esbuild` | High | GHSA-GV7W-RQVM-QJHR | Missing binary integrity verification in Deno module enables remote code execution via NPM_CONFIG_REGISTRY. |
| `esbuild` | High | GHSA-G7R4-M6W7-QQQR | Allows arbitrary file read when running the development server on Windows. |
| `react-router` | Medium | GHSA-2J2X-HQR9-3H42 | Same-origin redirect with path starting `//` causes open redirect via protocol-relative URL reinterpretation. |

**Remediation:** 
Run `npm audit fix` or explicitly upgrade the packages:
- Upgrade `esbuild` to at least `8.0.16` or the latest safe version.
- Upgrade `react-router` (or `react-router-dom`) to the latest patched version.

---

## ✅ Secret Scanner — 0 findings

Clean — no hardcoded credentials, API keys, or tokens detected.

---

**Priority order for fixes:** Pattern (lines 76–78 deal popup sanitization) → Dependency upgrading (esbuild / react-router) → Pattern SVG refactoring (lines 66-68).
