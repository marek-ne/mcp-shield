# Security Policy

mcp-shield is a security product. We take vulnerabilities in it — and reports
of bypassed guardrails — seriously.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.3.x | ✅ current |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Instead, report privately via [GitHub private vulnerability reporting]
(https://github.com/marek-ne/mcp-shield/security/advisories/new) (enabled on the
repo), or by email to the maintainer listed on the repository profile.

Include, where possible:

- the `mcp-shield --version` output and platform (OS/arch),
- the policy file (`~/.mcp-shield/policy.toml`, redact any secrets),
- a minimal JSON-RPC message or config snippet that reproduces the issue,
- observed vs expected behavior.

## What counts as a vulnerability

- A `tools/call` / `resources/read` payload that bypasses a documented default
  policy rule (e.g. destructive SQL/shell executes, blocked paths are read).
- A plaintext secret surviving `wrap` in a governed config file.
- A secret (Keychain-resolved value, env var, or child output token) appearing
  in an audit log entry, stderr relay, or host stdout.
- A broken audit hash chain under normal operation.
- Panics, deadlocks, or stream corruption in the stdio proxy.

Hardening ideas and defense-in-depth suggestions are welcome as regular issues.

## Response targets

- acknowledgment within 72 hours,
- triage within 7 days,
- fix or mitigation guidance for confirmed critical issues (secret leaks,
  guardrail bypasses) as fast as possible, typically within 14 days.

## Scope note

The default policy is a deliberately conservative starting point. Rule
*over-blocking* of unusual-but-legitimate commands is a tuning matter (edit
`policy.toml`), not a vulnerability — but we still want to hear about it.
