# Security Review Report: ZeroClaw LA Fork
**Rust Runtime Security & Tool Permission Patterns**
**Version: v0.8.0-beta-1 (Edition 2024)**

---

## 1. Rust Runtime Security

### Cryptography

The runtime's crypto choices are solid across the board. Secrets use ChaCha20-Poly1305 AEAD with a fresh random nonce per secret — this is modern, correct, and means even if one secret is compromised, others aren't. Legacy secrets (old XOR-based `enc:` format) are auto-upgraded to `enc2:` on load, so no manual migration needed.

Network traffic uses rustls 0.23 with optional mutual TLS and certificate pinning — good for preventing man-in-the-middle attacks. The audit chain uses a SHA-256 Merkle hash-chain, meaning any tampering with historical records is detectable.

One weak spot: The WeChat channel is forced to use AES-128-ECB + MD5 by protocol. ECB mode is cryptographically weak (it leaks patterns in data). It's feature-flagged and isolated, so it doesn't contaminate the core — but it's a compliance risk worth flagging.

### Unsafe Code Containment

Across 770+ files and 17 crates, unsafe Rust is confined to exactly one crate: `aardvark-sys`, which handles FFI bindings to a hardware SDK. The pattern is disciplined — dynamic library loading via `libloading`, no raw pointer arithmetic, no manual memory management anywhere else. This is genuinely well-contained and verifiable.

### Shell Execution

When spawning shell commands, the runtime clears all environment variables first, then re-adds only a hardcoded safe list (PATH, HOME, LANG, etc.). This directly prevents API keys or tokens from leaking into subprocesses. Output is also capped at 1 MB to prevent buffer overflow scenarios.

---

## 2. Tool Permission Patterns

The system uses three independent gates — all three must pass for a tool to execute. This is a strong defense-in-depth design.

### Gate 1 — Allowlist/Denylist

Tools are checked against an allowlist and a denylist. If no allowlist is set, all tools are permitted by default — the denylist always applies on top. Simple, predictable logic, though the open-by-default stance means misconfiguration risk if the denylist isn't carefully maintained.

### Gate 2 — Autonomy Levels

Three modes control how much the robot acts on its own:

- **ReadOnly** — can only look at things, never change anything
- **Supervised** (default) — low-risk tasks auto-run, medium-risk asks the operator, high-risk is blocked outright
- **Full** — no approval needed for anything

Within Supervised mode, the `always_ask` list correctly overrides everything else, including session-level approvals — this prevents a previously approved action from quietly getting re-approved in a riskier context.

### Gate 3 — Execution Guards

The final gate enforces:

- Rate limiting per sender (sliding 1-hour window)
- Path restrictions (workspace-only mode, forbidden paths)
- Command filtering via a shell lexer that blocks subshell injection (`$()`, backticks), output redirects, background execution (`&`), and dangerous combos like `find -exec` or `git config`

This is thorough and shows the shell lexer was written with real attack patterns in mind.

### Sub-Agent Escalation

Child agents are mathematically constrained to have equal or fewer permissions than their parent — autonomy, file paths, commands, and rate limits can all only narrow, never expand. This is enforced in code (`policy.rs:417-467`), not just by documentation or convention.

---

## 3. Findings Summary

### Finding 1 — Audit Logs Disappear on Restart

**What it is**
The robot keeps a diary of everything it does — tools used, approvals, blocks. This diary lives only in RAM (memory).

**The Problem**
RAM is wiped on restart or crash. The entire activity history is gone forever with no way to recover it.

**Risk Level:** Medium

**Currently**
The code already has a tamper-proof Merkle hash-chain built inside `audit.rs` — meaning the technology to do this properly exists. But it was never connected to any actual storage like a database or file on disk. It's built but not plugged in.

---

### Finding 2 — Memory Leak in Rate Limiter

**What it is**
The robot tracks how many actions each sender has done per hour to prevent abuse. Every unique sender gets a slot in a memory table called `PerSenderTracker`.

**The Problem**
Slots are never deleted. Every sender who ever contacts the robot gets a permanent entry — even if they never message again. The table grows forever.

**Risk Level:** Medium

**Currently**
There is no eviction logic anywhere in the current code. The table just keeps growing. This appears to be an oversight rather than a conscious decision — the rate limiting feature itself works correctly, the cleanup part was simply never implemented.

---

### Finding 3 — Config File Not Write-Protected

**What it is**
The robot's rulebook (`config.toml`) defines all its permissions — what tools it can use, what autonomy level it has, which paths it can access. There is no check on who can edit this file.

**The Problem**
If the robot has `file_write` access to its own config folder, it (or anything that has compromised it) can quietly rewrite its own rules. The changes take effect on the next restart — silently, with no alerts.

**Risk Level:** High

**Currently**
There is no runtime check that validates config file ownership or write permissions anywhere in the codebase. This gap appears to have been completely overlooked. It is also one of the easier fixes — a simple file permission change and a startup validation check would close this.

---

### Finding 4 — WeChat Channel Uses Weak Encryption

**What it is**
The WeChat integration is forced by WeChat's own protocol to use AES-128-ECB encryption and MD5 hashing — both considered weak and outdated by modern security standards.

**The Problem**
ECB mode encrypts data in identical chunks, meaning repeated data produces identical encrypted output. A pattern-matching attacker can learn things about the content without ever decrypting it. MD5 has been cryptographically broken for years.

**Risk Level:** Low

**Currently**
The WeChat channel is behind a feature flag (`channel-wechat`) so it's off by default. It is also completely isolated from the core security stack — the weak crypto cannot bleed into other parts of the system. They cannot fix the underlying cipher because WeChat mandates it at the protocol level. The containment is the best possible response here.

---

### Finding 5 — AI Can See Secrets in Plaintext During Execution

**What it is**
When the robot logs its actions, sensitive values like passwords, API keys and tokens are automatically redacted — they show as `[REDACTED]` in logs. But this only applies to the logs, not to actual execution.

**The Problem**
When a tool actually runs, the real unmasked secret is passed as a plain argument. The AI's brain (the LLM) processes these arguments in its context window — meaning the AI itself sees the actual secret in plaintext.

**Risk Level:** Medium

**Currently**
The implementation redacts values in the approval log summaries (`ApprovalLogEntry`) which does protect the audit trail. But this is only half the solution — it protects the logs while leaving the actual execution context completely unprotected. There is no secret reference system, no environment variable injection pattern, and no isolation between the LLM context and sensitive argument values. The harder architectural fix has not been started.

---

## 4. Overall Assessment

The runtime's security architecture is well-designed for a beta. The highlights are the crypto defaults, unsafe code discipline, and the sub-agent escalation controls. The permission system is layered and systematic.

The most actionable issues to address before production would be, in priority order: config file write protection (self-escalation risk), audit log persistence (forensic gap), and rate-limiter eviction (operational stability risk).


