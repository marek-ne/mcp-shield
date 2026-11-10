# mcp-shield — Pilot Quickstart (3 minutes)

## What you need

- **System:** Windows 10/11 (x86_64), macOS 13+ (Apple Silicon or Intel), or a
  recent Linux. No admin/root rights, no dependencies, no network access —
  the single ~3.7 MB binary is all that is required. No drivers, no services,
  no background daemon.
- **First-run prompt:** the OS may ask once for permission to access the
  credential store (Credential Manager / login keychain) — allow it. On
  keyring-less machines (headless Linux/CI), set `MCP_SHIELD_VAULT_PASSWORD`
  to use the built-in encrypted vault; the tool tells you if that's needed.

## What to expect from each step

1. **`audit`** — read-only scan of all IDE MCP configs. Prints one line per
   server (`EXPOSED` with every secret + kind, or `SHIMMED`) and a final grade:
   **CRITICAL** = plaintext secrets found, **WARN** = ungoverned servers,
   **PASS** = clean. Nothing is modified.
2. **`wrap`** — the only step that changes anything. Per config: timestamped
   `.bak` backup → secrets moved to the OS Keychain → config rewritten so the
   shim governs each server. Re-running `audit` must show **PASS** (success
   criterion #1: 100% plaintext elimination). `--dry-run` previews everything.
3. **`verify`** — 60-second self-test with its own mock server. Prints a
   9-line Pass/Fail table: sub-2 ms latency, blocked path traversal
   (incl. URL-encoded), blocked destructive SQL/shell, secret redaction,
   taint escalation, audit hash-chain integrity, <25 MB RAM.
4. **Daily use** — invisible: ~0.75 ms per call, ~2.5 MB RAM. You only see it
   when it protects you: a native approval dialog for risky actions (auto-deny
   after 30 s) or a `[mcp-shield] BLOCKED (<rule>)` message in the agent's tool
   result. Nothing breaks; the agent continues.
5. **`unwrap`** (any time) — restores original configs, deletes Keychain
   entries. Full uninstall = `unwrap` + delete `%USERPROFILE%\.mcp-shield\`.

`mcp-shield` is an enterprise, local-first MCP runtime security shim. It wraps
the stdio JSON-RPC channel between desktop AI agents (Claude Code,
Claude Desktop, Windsurf) and local MCP servers to deliver, with **no kernel
drivers, no SSL MITM, and no local LLM**:

1. **Secret zeroization** — plaintext API keys are moved from IDE config files
   into the OS Keychain (macOS Keychain / Windows Credential Manager + DPAPI /
   Linux Secret Service) and injected only at child-process spawn time.
2. **Deterministic guardrails (<2 ms)** — every `tools/call` /
   `resources/read` is evaluated against regex/AST-style rules: path traversal
   (including URL-encoded), destructive SQL/shell, env dumps.
3. **HITL + redaction + audit** — risky actions trigger a native OS approval
   dialog; leaked secrets (PEM keys, AWS/GitHub/Slack tokens, JWTs, credit
   cards via Luhn, IBANs via Mod-97, high-entropy tokens) are redacted from
   tool output before it reaches the LLM context; every decision lands in a
   tamper-evident, hash-chained JSONL audit log with per-call latency.

## 0. Install

Copy the single binary `mcp-shield.exe` (Windows) or `mcp-shield` (macOS/Linux)
to a stable location, e.g. `C:\Program Files\mcp-shield\` or `~/bin/`.

## 1. Audit (Day-1 exposure report) — 30 seconds

```bash
mcp-shield audit          # human-readable risk report (CRITICAL / WARN / PASS)
mcp-shield audit --json   # machine-readable report for SIEM ingestion
```

Scans `~/.claude.json`, `./.mcp.json`, the Claude Desktop config,
`Code/User/mcp.json`, `.vscode/mcp.json`, `~/.kimi-code/mcp.json`,
`~/.config/muse/settings.json`, and `~/.gemini/config/mcp_config.json`
for hardcoded secrets and unshimmed servers.

## 2. Wrap (eliminate plaintext secrets) — 10 seconds

```bash
mcp-shield wrap --target all --dry-run   # preview first
mcp-shield wrap --target all             # migrate
```

For every configured server this:

- writes a timestamped **encrypted** backup (`<config>.bak.<timestamp>`),
- stores each secret in the OS Keychain (`mcp-shield` / `<server>:<KEY>`),
- replaces the value with `mcp-shield://keychain/<config_id>/<server>/<KEY>`
  (namespaced per config file),
- rewrites the server entry so `mcp-shield exec` is the entrypoint.

Re-run `mcp-shield audit`: grade must flip to **PASS** (criterion #1:
100% elimination of plaintext secrets).

If the OS keychain is unavailable (headless/CI), set
`MCP_SHIELD_VAULT_PASSWORD=<passphrase>` to use the built-in AES-256-GCM
encrypted vault instead.

## 3. Verify (60-second attack & performance proof)

```bash
mcp-shield verify
```

Spawns the built-in mock MCP server behind the shim and runs the red-team
suite, printing a Pass/Fail scorecard:

- MCP handshake passthrough (0 broken handshakes)
- p99 proxy overhead vs. direct baseline (budget: < 2.0 ms per JSON-RPC call)
- path traversal block (`~/.ssh/id_rsa`, `file:///etc/%73hadow`)
- destructive SQL block (`DROP TABLE`, `DELETE` without `WHERE`)
- destructive shell block (`rm -rf /`, env dumps)
- secret redaction from child output
- taint escalation (fetch → write must be approved)
- audit hash-chain integrity + latency metrics
- RSS memory footprint (< 25 MB)

## 4. Daily operation

Nothing to do — every wrapped MCP server now routes through the shim.
Inspect activity at `~/.mcp-shield/audit.jsonl` (or `%MCP_SHIELD_HOME%`).

### Human-in-the-Loop modes

- Interactive (default): native OS dialog, 30 s timeout → Deny.
- Headless/CI: `MCP_SHIELD_HITL=auto-allow` or `MCP_SHIELD_HITL=auto-deny`.

### Policy

`~/.mcp-shield/policy.toml` is auto-generated on first run. Edit the blocked
paths / SQL / shell patterns, prompt rules, and taint sources to match your
risk posture; redistribute via MDM or GitOps.

## 5. Unwrap (clean removal)

```bash
mcp-shield unwrap
```

Restores every config from its encrypted `.bak` backup and deletes the Keychain entries.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `MCP_SHIELD_HOME` | State directory (default `~/.mcp-shield`) |
| `MCP_SHIELD_CONFIG_HOME` | Override the home directory used for IDE config discovery (tests, demos, MDM packaging) |
| `MCP_SHIELD_HITL` | `interactive` (default) / `auto-deny` — headless approval denial; `auto-allow` is honored only when the signed policy sets `allow_headless_hitl_override` |
| `MCP_SHIELD_VAULT_PASSWORD` | Passphrase for the encrypted vault fallback |

## Support matrix

- **OS:** macOS 13+, Windows 10/11, Linux (x86_64 & Apple Silicon)
- **Agents/IDEs:** Claude Code, Claude Desktop, Windsurf, VS Code
  (Copilot agent mode), Kimi Code, Meta Muse Code, Antigravity/Gemini — and any
  other client that can launch MCP servers over stdio (Grok Build, Cline,
  Roo Code, Aider, Zed, OpenCode, …) via manual `exec` wrapping
- **SIEM:** audit.jsonl is newline-delimited JSON — forward with any OTel
  collector/file agent to Splunk, Datadog, or Elastic.
