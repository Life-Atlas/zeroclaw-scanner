# Deep Vulnerability Scan Report


## Executive Summary

This scan went deeper than the first dependency-only pass. It combined dependency audit, Python SAST, Semgrep SAST, heuristic secrets scanning, Git history pattern search, Docker/CI review, Supabase Edge Function review, Supabase RLS pattern review, and manual review of high-risk code paths.

No scan can prove that all vulnerabilities are found. The most important additional finding from this deeper pass is not a CVE: it is an authorization problem in the Supabase `send-feedback` Edge Function, which uses the service-role key without verifying the caller.

Highest-priority areas:

1. `send-feedback` Edge Function: service-role access without caller authentication.
2. PDF/document stack: vulnerable `jspdf` and `pdfjs-dist` plus user document flows.
3. Unauthenticated API proxy functions: Google Maps/Mapbox/event proxy endpoints can be abused for quota/cost or scraping.
4. Supabase RLS and `SECURITY DEFINER` review: several policies/functions require manual validation.
5. Container/config hardening: root container, exposed database/vector ports, default dev passwords, unpinned `latest` images.

## Tools and Commands Used

Installed locally for this scan:

- `bandit`
- `detect-secrets`
- `semgrep`

Commands run:

```powershell
python -m pip_audit . -f json --progress-spinner off
npx pnpm@10.24.0 audit --json
npx retire@latest --path . --outputformat json --severity none
python -m bandit -r src scripts tests -f json -o bandit-report.json
semgrep scan --config p/security-audit --config p/secrets --json -o semgrep-report.json --exclude .git --exclude node_modules --exclude .pytest_cache
semgrep scan --config p/owasp-top-ten --config p/python --config p/typescript --json -o semgrep-broad-report.json --no-git-ignore --exclude .git --exclude node_modules --exclude .pytest_cache
git grep -n -I -E "(SUPABASE_SERVICE_ROLE_KEY|service_role_key|OPENAI_API_KEY|STRIPE_SECRET|RESEND_API_KEY|JWT_SECRET|PRIVATE KEY|sk_live_|sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})" $(git rev-list --all)
rg -n --hidden -i -e "dangerouslySetInnerHTML" -e "innerHTML" -e "eval\(" -e "new Function" -e "localStorage" -e "window.location" -g "!node_modules/**" -g "!.git/**"
rg -n -i "create policy|using \(true\)|with check \(true\)|grant .* to anon|security definer|set search_path" lifeatlas-core-code\supabase\migrations
```

Notes:

- `detect-secrets scan --all-files` hit a Windows multiprocessing permission error in this environment. I compensated with Semgrep secrets rules, Git history grep, and targeted `rg` secret patterns.
- `secretlint` requires a project config and was not used as a final source.
- Retire.js completed and returned no additional vulnerable JS-library findings beyond `pnpm audit`.
- Semgrep reported 2 findings in the broad scan.

## Confirmed / High-Confidence Findings

### P0: `send-feedback` uses service role without authenticating the caller

File: `lifeatlas-core-code/supabase/functions/send-feedback/index.ts`

The function:

- accepts arbitrary request JSON,
- reads `feedback`, `userId`, `email`, and `attachmentStoragePath`,
- creates a Supabase client with `SUPABASE_SERVICE_ROLE_KEY`,
- queries `decrypted_profiles` by request-supplied `userId`,
- optionally creates a signed URL for `feedback_attachments` if `attachmentStoragePath` starts with `${userId}/`,
- sends the result by email.

There is no `Authorization` header validation and no `auth.getUser()` call. Because the function uses service role, this bypasses RLS. A caller can submit another user's `userId` and potentially:

- cause emails to include another user's decrypted first/last name,
- generate signed links to attachments if object paths are guessable or leaked,
- spam the feedback recipient list,
- use the function as an unauthenticated service-role-backed email relay.

Severity: Critical if deployed publicly.

Recommended fix:

1. Require `Authorization: Bearer <jwt>`.
2. Create an anon/user-scoped Supabase client with that JWT.
3. Verify `auth.getUser()`.
4. Ignore client-supplied `userId`; derive it from the verified JWT.
5. Ensure `attachmentStoragePath` belongs to the authenticated user using a DB/storage ownership check, not only a string prefix.
6. Add rate limiting, captcha, or authenticated-only submission controls.
7. Remove stack traces and raw error details from public responses.

### P0/P1: Vulnerable PDF libraries in user document flows

Files include:

- `lifeatlas-core-code/packages/shared/src/utils/fileUtils.ts`
- `lifeatlas-core-code/packages/timeline/src/components/TimelinePDFGenerator.ts`
- `lifeatlas-core-code/packages/timeline/src/components/TimelinePDFService.tsx`
- `lifeatlas-core-code/apps/lifeatlas-equestrai/package.json`
- `lifeatlas-core-code/apps/lifeatlas-ironman/package.json`
- `lifeatlas-core-code/packages/healthcare/package.json`
- `lifeatlas-core-code/packages/healthcare-animals/package.json`

`pnpm audit` reported:

- `jspdf@2.5.2`: multiple advisories, including 2 critical findings.
- `pdfjs-dist@3.11.174`: high severity CVE-2024-4367, arbitrary JavaScript execution when malicious PDFs are opened with eval support.

`fileUtils.ts` pins the PDF.js worker to:

```ts
https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js
```

That hardcoded CDN worker keeps the vulnerable PDF.js version active even if package versions are later changed without updating the worker URL.

Severity: Critical/high where users can upload, preview, or generate PDFs.

Recommended fix:

1. Upgrade `pdfjs-dist` to a patched version and update worker loading to match the installed version.
2. Explicitly set `isEvalSupported: false` in PDF loading/rendering code.
3. Upgrade or replace `jspdf`; review `html`, `addImage`, `addSvgAsImage`, `addJS`, and AcroForm usages.
4. Add PDF-specific regression tests with benign and malformed files.
5. Consider server-side PDF sanitization or conversion isolation if user PDFs are processed.

### P1: Unauthenticated Google Maps proxy can be abused

File: `lifeatlas-core-code/supabase/functions/google-maps-autocomplete/index.ts`

The function:

- exposes Google Maps autocomplete/place-details through an unauthenticated public endpoint,
- uses wildcard CORS,
- accepts arbitrary `query` and `place_id`,
- calls Google APIs with the server-side `GOOGLE_MAPS_API_KEY`.

This is not data exfiltration by itself, but it can burn quota, create cost, and allow uncontrolled use of the server-side API key through the function.

Severity: High if the function is public and the Google key has billing enabled.

Recommended fix:

1. Require authenticated user JWT.
2. Add per-user/IP rate limits.
3. Restrict allowed actions and validate input length.
4. Configure Google API key restrictions in Google Cloud.
5. Consider moving this behind application backend controls.

### P1: Public Mapbox token endpoint has hardcoded fallback token and stack trace leakage

File: `lifeatlas-core-code/supabase/functions/get-mapbox-token/index.ts`

The function:

- returns a fallback public Mapbox token if env is missing or not `pk.*`,
- uses wildcard CORS,
- returns error details and stack trace in error responses.

Public Mapbox tokens are not secrets in the same way as service keys, but exposing a fallback token in code couples the repo to a real Mapbox account/project and can be abused for quota if token restrictions are weak.

Severity: Medium to high depending on Mapbox token restrictions.

Recommended fix:

1. Remove hardcoded fallback token.
2. Return 500 if `MAPBOX_TOKEN` is missing.
3. Restrict Mapbox token by allowed origins/domains.
4. Do not return stack traces to clients.

### P1: `upload-file` accepts files without explicit max-size enforcement

File: `lifeatlas-core-code/supabase/functions/upload-file/index.ts`

The function verifies JWT and profile ownership, which is good. It also restricts MIME types:

- PDF
- CSV
- PNG
- JPEG

However, it does not enforce an application-level max file size before reading `file.arrayBuffer()`. Large uploads can consume memory/storage and increase processing cost. It relies on platform limits or client behavior.

Severity: High for abuse/DoS/storage-cost risk if public.

Recommended fix:

1. Enforce a hard file size limit before reading the full body into memory.
2. Use a shared constant aligned with backend `UPLOAD_MAX_BYTES`.
3. Validate file magic bytes, not only browser-provided `file.type`.
4. Consider virus/malware scanning or quarantine for uploaded PDFs/images.
5. Avoid returning raw storage/db errors to clients.

### P1: Timeline map popups use `innerHTML`

File: `lifeatlas-core-code/packages/timeline/src/components/TimelineMap.tsx`

The code builds Mapbox popup DOM using `popupContent.innerHTML = ...`. Some user-controlled fields appear escaped with `escapeHtml`, which lowers risk. However, this remains a fragile sink because:

- all interpolated values must be escaped consistently forever,
- translations are interpolated into HTML,
- style attributes interpolate color values,
- similar code appears in translation JSON as extracted strings.

Severity: Medium/high depending on whether timeline content, location, description, or translations are user-controlled/admin-controlled.

Recommended fix:

1. Replace string-based HTML construction with DOM APIs or React-rendered popup content.
2. If string templates remain, centralize HTML escaping and validate color values.
3. Add XSS regression tests for timeline description/location/type fields.

### P1: Docker/container hardening gaps

Files:

- `Dockerfile`
- `docker-compose.yml`

Findings:

- Runtime container does not set a non-root `USER`.
- Neo4j and Qdrant ports are published to the host.
- Default dev passwords exist for Neo4j if env vars are missing.
- Images use mutable tags such as `neo4j:5-community`, `qdrant/qdrant:latest`, and `traefik:latest`.
- Qdrant has no API key configured in compose.
- Neo4j APOC unrestricted procedures are enabled.

Severity: Medium/high depending on deployment exposure. On a public server, exposed database/vector ports are high risk.

Recommended fix:

1. Add a non-root user in the runtime Docker image.
2. Avoid publishing Neo4j/Qdrant host ports in production.
3. Require strong Neo4j passwords and fail startup if defaults are used.
4. Pin image versions by digest or exact versions.
5. Configure Qdrant API key/network isolation.
6. Restrict APOC procedures to the minimum needed.

### P1: CI/deployment supply-chain hardening gaps

File: `.github/workflows/deploy.yml`

Findings:

- GitHub Actions are pinned by tags, not commit SHAs.
- Deployment uses `appleboy/ssh-action@v1.0.0`, also tag-pinned.
- Remote script runs `git pull`, `docker compose down`, writes `.env`, builds, and prunes images on the target host.

This is common, but less hardened than a locked release pipeline.

Severity: Medium.

Recommended fix:

1. Pin third-party GitHub Actions to commit SHAs.
2. Use least-privilege deploy keys/users.
3. Consider signed images/artifacts instead of building on prod host.
4. Avoid broad remote shell deployment if a release artifact pipeline is available.
5. Add dependency/security scans as required CI gates.

## Dependency Findings

### TypeScript/pnpm

`pnpm audit` reported:

- 2 critical
- 37 high
- 27 moderate

Most important packages:

- `jspdf@2.5.2`
- `pdfjs-dist@3.11.174`
- `fast-uri@3.1.0`
- `tar@7.5.2`
- `@remix-run/router`
- `flatted`
- `lodash` / `lodash-es`
- `minimatch`
- `picomatch`
- `vite`
- `i18next-http-backend`
- `dompurify`
- `postcss`
- `protocol-buffers-schema`

Retire.js did not report additional findings.

Recommended fix order:

1. Patch PDF libraries first.
2. Update direct parents that pull vulnerable transitive dependencies:
   - `dependency-cruiser`
   - `supabase`
   - `vite`
   - `react-router-dom`
   - `@vitest/ui`
   - `ts-morph`
   - `i18next-http-backend`
3. Use `pnpm.overrides` only when direct updates cannot resolve a transitive advisory.

### Python

`pip-audit` found:

- `langchain-text-splitters@0.3.11`
- CVE-2026-41481 / GHSA-fv5p-p927-qmxr
- SSRF bypass in `HTMLHeaderTextSplitter.split_text_from_url()`
- Fixed in `>=1.1.2`, with newer LangChain dependency requirements.

I did not find direct usage of `HTMLHeaderTextSplitter.split_text_from_url()` in the current code during this scan, so this is probably a vulnerable installed component rather than a confirmed reachable exploit path. Still patch or document it.

## SAST Findings

### Semgrep

Broad Semgrep scan found:

1. `Dockerfile`: no non-root runtime user.
2. `src/chat/backend/memory.py`: possible logger credential disclosure warning. This appears likely false positive because the logged message is `tiktoken unavailable (%s), using fallback character estimate`, not an actual credential.

Semgrep had taint-analysis timeouts on a few large/complex files, including:

- `lifeatlas-core-code/apps/lifeatlas-health/src/pages/Index.tsx`
- `lifeatlas-core-code/packages/healthcare-animals/src/components/HealthDocumentsUpload.tsx`
- `lifeatlas-core-code/packages/timeline/src/components/TimelineMap.tsx`
- `lifeatlas-core-code/supabase/functions/chatlifeatlas/index.ts`
- `lifeatlas-core-code/supabase/functions/oura-sync-data/index.ts`
- `lifeatlas-core-code/supabase/functions/whoop-sync-data/index.ts`

Timeouts do not mean vulnerable, but they are blind spots worth manual review.

### Bandit

Bandit reported only low-severity findings:

- many `assert` warnings in tests,
- hardcoded test/JWT placeholder strings in legacy scripts/tests,
- one broad `except Exception: pass` in `src/chat/backend/services/chat_service.py`.

The `except Exception: pass` occurs around disconnect handling in an SSE stream. It is not immediately exploitable, but logging at debug level would help troubleshooting.

## Secrets Scan

Current-tree targeted scans did not find obvious high-impact secrets such as:

- service-role keys,
- OpenAI keys,
- Stripe secret keys,
- GitHub tokens,
- AWS access keys,
- private key blocks.

Git history pattern search mostly returned placeholder env var names, docs, test constants, and example values. It did not surface an obvious real service-role or OpenAI key in the searched patterns.

Important caveat:

- The `lifeatlas-core-code` folder is untracked from the root repo's current Git status, so root Git history does not necessarily cover that entire tree.
- A dedicated tool such as Gitleaks or TruffleHog should still be run over any actual Git repository/history for `lifeatlas-core-code` if it exists elsewhere.

## Supabase RLS / SQL Review Targets

The migrations contain many policies that look correctly user-scoped, but several patterns need manual validation:

- `SECURITY DEFINER` functions, some without visible `SET search_path`.
- policies using `using (true)` or `with check (true)`.
- broad public/authenticated read policies for reference data.
- professional/client access policies.
- service-role-managed tables for integration tokens/summaries.

Specific examples to review:

- `lifeatlas-core-code/supabase/migrations/20251215160748_remote_schema.sql`
- `lifeatlas-core-code/supabase/migrations/20251220000007_create_professional_functions.sql`
- `lifeatlas-core-code/supabase/migrations/20251220000009_add_professional_view_patient_data_rls.sql`
- `lifeatlas-core-code/supabase/migrations/20251220000015_fix_rls_recursion_and_switch_role.sql`
- `lifeatlas-core-code/supabase/migrations/20260217000001_request_connection_accept_profile_id.sql`
- `lifeatlas-core-code/supabase/migrations/20260217000002_request_connection_check_professional_profiles.sql`
- `lifeatlas-core-code/supabase/migrations/20260219092712_resolve_rpc_overloading.sql`
- `lifeatlas-core-code/supabase/migrations/20260219093556_resolve_rpc_overloading_v2_fix_logic.sql`

Review checklist:

1. Every `SECURITY DEFINER` function should set `search_path` safely.
2. Every function should verify the invoker's identity/role when returning or mutating sensitive data.
3. Professional access should require accepted connections and correct profile/user matching.
4. Token tables should never be readable by connected professionals unless explicitly intended.
5. Reference tables with `using (true)` should not contain user/private data.

## Prioritized Remediation Plan

### Immediate P0

1. Fix `send-feedback` authentication and authorization.
2. Patch/mitigate `pdfjs-dist` and `jspdf`.
3. Remove hardcoded Mapbox fallback token.

### Short-Term P1

1. Add auth/rate limiting to `google-maps-autocomplete`.
2. Add max file size and magic-byte validation to `upload-file`.
3. Replace `innerHTML` Mapbox popup construction with safer DOM/React rendering.
4. Remove public host port exposure for Neo4j/Qdrant in production compose.
5. Add non-root Docker runtime user.
6. Pin mutable Docker image tags.

### Medium-Term P2

1. Review all Supabase `SECURITY DEFINER` functions and permissive policies.
2. Add Gitleaks/TruffleHog to CI and scan full history of all actual repos.
3. Add Semgrep/Bandit/pip-audit/pnpm-audit gates to CI.
4. Pin GitHub Actions to SHA.
5. Add dependency update workflow and `pnpm.overrides` policy.

## Suggested Verification Tests

Security tests to add:

1. `send-feedback` rejects missing/invalid JWT.
2. `send-feedback` ignores client-supplied `userId` and uses JWT subject.
3. `send-feedback` refuses attachment paths not owned by the authenticated user.
4. `upload-file` rejects oversized files before buffering.
5. `upload-file` rejects MIME spoofing, such as `.pdf` with image or script bytes.
6. Timeline popup escapes `<img onerror=...>` and similar payloads.
7. Professional/client RLS tests prove a professional cannot read unrelated client data.
8. Storage signed URL tests prove users cannot sign/read another user's path.

## Residual Risk

This was a static/local scan. It did not include:

- live Supabase policy evaluation against a real project,
- authenticated dynamic testing,
- OWASP ZAP or API fuzzing,
- container image CVE scan with Trivy/Grype,
- full Gitleaks/TruffleHog history scan across separate nested repos,
- exploit validation.

The most valuable next step would be to fix `send-feedback`, then run authenticated integration tests against a disposable Supabase environment to validate RLS and Edge Function behavior.
