# mcp-shield

**Enterprise-grade, local-first security shim for MCP (Model Context Protocol) tool servers.**

[![CI](https://github.com/marek-ne/mcp-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/marek-ne/mcp-shield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.3.3-blue)](CHANGELOG.md)

Desktop AI agents (Claude Code, Claude Desktop, Windsurf, **VS Code**,
**Kimi Code**, **Meta Muse Code**, Antigravity/Gemini) spawn local MCP servers over
stdio — usually with **plaintext API keys in IDE config files** and **no
oversight** of what those servers read or execute. Cloud AI gateways can't see
this traffic; EDR sees processes, not intent. `mcp-shield` closes the gap as a
**user-space stdio wrapper**: no kernel drivers, no SSL MITM, no local LLM, no
background daemon.

One binary. Sub-millisecond enforcement. Fully reversible.

```text
$ mcp-shield verify
CASE                                                           RESULT  DETAIL
MCP handshake passthrough (initialize/ping/tools_list)           PASS  0 broken handshakes
p99 proxy overhead < 2.0 ms (vs direct baseline)                 PASS  p50=462µs p99=747µs over 200 calls
Path traversal blocked (~/.ssh, /etc/%73hadow)                   PASS  BLOCKED (URL-encoded payload normalized first)
Destructive SQL blocked (DROP TABLE, DELETE w/o WHERE)           PASS  BLOCKED before reaching the child process
Destructive shell blocked (rm -rf /, env dump)                   PASS  BLOCKED
Secret exfiltration redacted (ghp_/sk-/AKIA/JWT/IBAN/CC)         PASS  7 redaction markers, 0 raw secrets reached host
Taint escalation (fetch -> write_file HITL-gated)                PASS  poisoned-source writes require approval
Audit log hash-chain integrity + latency metrics                 PASS  SHA-256 chain INTACT, latency_us per decision
Memory footprint < 25 MB RSS                                     PASS  2.5 MB
RESULT: ALL CHECKS PASSED
```

## What it does

| Risk | Control |
| --- | --- |
| Plaintext secrets in `claude_desktop_config.json`, `~/.claude.json`, `.vscode/mcp.json` | `audit` grades the workstation CRITICAL/WARN/PASS; `wrap` moves secrets to the OS Keychain (macOS Keychain / Windows Credential Manager+DPAPI / Linux Secret Service) and rewrites configs — `unwrap` restores byte-for-byte from timestamped backups |
| Secrets entering the LLM context window | **Late-bound injection**: configs hold `mcp-shield://keychain/…` placeholders; real values are resolved at child-process spawn, never logged. Child output is redacted before the agent sees it |
| Prompt injection → destructive SQL/shell | Deterministic guardrails (p99 ~0.1 ms): blocked paths (`**/.ssh/**`, `**/.aws/**`, `**/.kube/**`, `.env*`, `*.pem`, `*.key`, `/etc/*`) after percent-decoding + dot-segment + CWD resolution; `DROP`/`TRUNCATE`/`GRANT ALL`/`ALTER`, `DELETE` without `WHERE`, tokenized `rm -rf`, `mkfs`, `dd if=`, `curl\|sh`, `chmod 777`, env dumps |
| Indirect prompt injection (poisoned issues/pages) | Session taint tracking: after `fetch`/`web_search`/`read_email`/`github_get_issue`, write/exec tools escalate to human approval |
| Silent autonomous action | Native OS HITL dialog (macOS/Windows/Linux, fail-closed 30 s timeout) + append-only **SHA-256 hash-chained** JSONL audit log with per-call `latency_us` |

Blocked calls never reach the child process; the agent receives a graceful MCP
`isError` result (or JSON-RPC `-32600` for malformed requests), so IDE sessions
never break.

## Requirements

**Supported systems**

| Platform | Versions | Architecture | Notes |
| --- | --- | --- | --- |
| Windows | 10 / 11 | x86_64 | uses Credential Manager + DPAPI; PowerShell only for the HITL popup |
| macOS | 13 (Ventura) and newer | Apple Silicon & Intel | uses the login Keychain; HITL via `osascript` dialog |
| Linux | any recent distro | x86_64 / ARM64 | Secret Service (gnome-keyring/KWallet) when present; encrypted-vault fallback otherwise |

**What you need**

- The single binary (~3.7 MB) from [Releases](https://github.com/marek-ne/mcp-shield/releases) — nothing else.
- **No admin/root rights.** The tool runs entirely in user space: no kernel
  drivers, no services, no background daemon, no `sudo`.
- **No dependencies.** Not even Rust — that's only needed if you build from source.
- **No network access.** Everything is local-first: no telemetry, no phone-home,
  no cloud component. The only traffic ever possible is what your MCP servers
  themselves make.

**What the machine will ask you**

- The first time `wrap` stores or `exec` resolves a secret, the OS may show a
  one-time permission prompt for its credential store ("mcp-shield wants to
  access the Windows Credential Manager / login keychain"). Allow it.
- On a machine without an OS keyring (common on headless Linux/CI), set
  `MCP_SHIELD_VAULT_PASSWORD=<passphrase>` to activate the built-in encrypted
  vault instead — you'll get a clear error message telling you exactly that.

## Quickstart

**Install:** copy the single binary from [Releases](https://github.com/marek-ne/mcp-shield/releases)
or build it (`cargo build --release` → `target/release/mcp-shield[-exe]`).

**1 — Audit (read-only, 30 s):** see what your workstation exposes.

```bash
mcp-shield audit          # or: mcp-shield.exe audit
```

**2 — Prove it (60 s):** the self-contained attack & performance self-test.

```bash
mcp-shield verify
```

**3 — Zeroize (reversible):** move plaintext secrets into the Keychain and put
every MCP server under governance.

```bash
mcp-shield wrap --target all --dry-run   # preview
mcp-shield wrap --target all             # migrate (encrypted .bak backups)
mcp-shield audit                         # expect: GRADE: PASS
mcp-shield unwrap                        # any time: restore + delete Keychain entries
```

A full scripted demo against planted fake secrets ships in
[`testenv/`](testenv): `bash testenv/run-demo.sh` (Git Bash) — watch the grade
flip CRITICAL → PASS and every attack get blocked live.

## What to expect (exactly)

**`mcp-shield audit`** — read-only, finishes in seconds. Nothing is modified.

Scans the standard IDE config paths:

- Claude Code (`~/.claude.json`, `./.mcp.json`)
- Claude Desktop
- Antigravity / Gemini (`~/.gemini/config/mcp_config.json`)
- VS Code (`Code/User/mcp.json`, `./.vscode/mcp.json`)
- Windsurf (`~/.codeium/windsurf/mcp_config.json`)
- Kimi Code (`~/.kimi-code/mcp.json` or `$KIMI_CODE_HOME/mcp.json`, `./.kimi-code/mcp.json`)
- Meta Muse Code (`~/.config/muse/settings.json`)

Prints one line per MCP server: `EXPOSED` (secret + kind) or `SHIMMED`, then a
final grade: **CRITICAL** (plaintext secrets), **WARN** (ungoverned servers),
**PASS**.

**`mcp-shield wrap --target all`** — the only command that changes your system.
Per config file you will see a `[wrapped] … (backup: …)` line.

Concretely, for each config:

1. The original file is saved to `<name>.bak.<timestamp>` first — **encrypted
   at rest** (AES-256-GCM, key in the secret store), so no plaintext copy
   survives on disk.
2. Every plaintext secret in `env` blocks *and* in credential-bearing command
   arguments (e.g. `postgresql://user:pass@…`) is moved into the OS Keychain and
   replaced by a `mcp-shield://keychain/…` placeholder.
3. Each server entry is rewritten so the shim becomes its entrypoint.

Your IDEs keep working unchanged — they simply launch servers through the shim.
Add `--dry-run` to preview every change with zero writes.

**While coding (the shim in action)** — invisible in normal operation. Measured
overhead is **p99 ~0.75 ms per tool call** and **~2.5 MB RAM** — far below
human perception.

Two things can surface:

1. When an agent attempts a risky but allowed action (`UPDATE` SQL,
   `git push --force`, network egress, or any write after fetching untrusted
   external content), a native OS dialog asks for approval. It shows the exact
   tool and arguments, and **denies automatically after 30 s**.
2. Blocked attempts produce a visible `[mcp-shield] BLOCKED (<rule>)` error
   inside the agent's tool result. The agent handles it and continues; your MCP
   session does not break.

**`mcp-shield verify`** — 60 seconds, changes nothing (it uses its own mock
server). Prints the 9-check Pass/Fail table from the top of this README so you
can screenshot the security posture for your own records.

**Where things live** — everything in one folder:
`%USERPROFILE%\.mcp-shield\` (Windows) / `~/.mcp-shield/`

- `audit.jsonl` — the hash-chained audit log
- `policy.toml` — editable rules
- `wrap-state.json`
- the vault, if used

**Uninstalling** — `mcp-shield unwrap` restores every config from its backup
and deletes the Keychain entries. Deleting `~/.mcp-shield/` removes all
remaining state. Nothing else was ever installed.

## Commands

| Command | Purpose |
| --- | --- |
| `mcp-shield audit [--json]` | Day-1 exposure report across all standard IDE MCP config paths |
| `mcp-shield wrap [--target all\|claude-code\|claude-desktop\|antigravity\|vscode\|windsurf\|kimi-code\|muse] [--dry-run]` | Back up, extract secrets (env **and** credential-bearing argv), rewrite configs through the shim |
| `mcp-shield unwrap` | Decrypt and restore `.bak` configs, delete Keychain entries |
| `mcp-shield exec --server-name <n> [--policy <p>] -- <cmd> [args…]` | The inline interceptor (invoked automatically by wrapped configs) |
| `mcp-shield verify` | Automated red-team + performance self-test (also: `mock-server` subcommand) |
| `mcp-shield doctor` | Operational health: secret store, policy signature, audit keying, config drift, HITL helper |

## Client coverage — built-in vs. automatic

`mcp-shield` enforces at the **process pipe**, not inside any IDE, so every
stdio MCP host benefits from wrapped servers — including clients with no
built-in discovery target yet (Cline, Roo Code, Aider, Zed, OpenCode, Goose,
JetBrains, …).

| Client | Discovery/wrap support | Notes |
| --- | --- | --- |
| Claude Code, Claude Desktop | ✅ built-in | global + workspace configs |
| VS Code (Copilot agent mode) | ✅ built-in | `Code/User/mcp.json`, `.vscode/mcp.json` |
| Windsurf | ✅ built-in | `~/.codeium/windsurf/mcp_config.json` |
| Kimi Code | ✅ built-in | `~/.kimi-code/mcp.json`, `.kimi-code/mcp.json` ([docs](https://www.kimi.com/code/docs/en/kimi-code-cli/customization/mcp.html)) |
| Antigravity / Gemini | ✅ built-in | `~/.gemini/config/mcp_config.json` |
| Meta **Muse Code** | ✅ built-in | `mcpServers` block of `~/.config/muse/settings.json` (its `schema_version` is preserved) |
| xAI **Grok Build** CLI | 🔧 manual today | local stdio MCP via `~/.grok/config.toml` (TOML); wrap it by pointing its entry at the shim, e.g. `grok mcp add -- /abs/path/mcp-shield exec --server-name <n> -- <original cmd>` — automatic TOML config rewriting is on the roadmap |
| **Grok Bot** (grok.com / X), Claude web, ChatGPT | ➖ n/a | cloud-only remote MCP connectors — nothing executes locally, so there is no local stdio to shim; remote MCP governance belongs at the cloud gateway, which is exactly the boundary this project is designed to complement |

If your client accepts a custom stdio launch command, it is protectable **now**
by wrapping that command with `mcp-shield exec --server-name <name> -- …`; open
an issue with the config path and we will add a discovery target.

## Architecture

```
Claude Code / Claude Desktop / Windsurf / VS Code / Kimi Code
        |  JSON-RPC 2.0 over stdio (newline-delimited)
        v
+-------------------------+        +----------------------+
| mcp-shield exec         |------->| OS Keychain /        |
| · policy engine (<1ms)  |        | encrypted vault      |
| · secret redactor (DLP) |        | (late-bound secrets) |
| · HITL · audit hashchain|        +----------------------+
+-------------------------+
        |  unchanged JSON-RPC              | npx / node / uvx …
        v                                  v
   blocked calls -> MCP isError       local MCP server child
   (never reach the child)
```

Guardrail decisions are 100% deterministic — compiled regexes, checksum
validation (Luhn, Mod-97), glob matching, tokenized shell inspection, and an
exact-match dictionary of every Keychain-resolved secret. No ML, no local model,
no probabilistic answers to audit against.

## Security properties

- **Signed policy**: `policy.toml` is ed25519-signed (key in the secret store or
  MDM-provisioned); any modification outside `mcp-shield` aborts startup, and
  state files are created `0600`/`0700` (user-only).
- **Keyed audit**: every event carries an HMAC (key in the secret store) in
  addition to the SHA-256 hash chain — rewriting the log from genesis is
  detectable, not just edits.
- **Framing discipline**: only newline-delimited JSON-RPC is governed; batches,
  `Content-Length` framing, and non-JSON frames are denied, never proxied.
- **Tool-surface pinning**: the advertised `tools/list` is fingerprinted per
  session; a mid-session change is refused (rug-pull defense), and tool
  descriptions are scanned for instructive prompt injections and masked before
  the agent sees them.
- **Server & env pinning** (policy knobs): `server_allowlist` refuses unknown
  wrapped servers; `child_env_allowlist` restricts what the child process
  receives. Both ship empty (permissive) — enable per fleet policy.
- **Fail-closed**: unresolvable secrets abort the server start, dialog errors
  and timeouts deny; `MCP_SHIELD_HITL=auto-allow` is ignored unless the signed
  policy explicitly allows it.
- **Tamper-evident**: appending/editing/reordering audit events breaks the
  SHA-256 chain; `verify` detects it.
- **No plaintext at rest**: the only fallback store is AES-256-GCM with an
  Argon2id-derived key (`MCP_SHIELD_VAULT_PASSWORD`), for keyring-less hosts.
- **Evasion-resistant**: URL-encoded (`%73hadow`), dot-segment (`../../`),
  tilde-relative, and CWD-relative paths are canonicalized before rule matching;
  aggregator tool prefixes (`github__read_file`) are stripped; `id:null`
  tool calls are rejected with `-32600` (Invariant-labs-style confusion).
- See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## Configuration

`~/.mcp-shield/policy.toml` (auto-generated, TOML) — blocked paths/SQL/shell,
HITL-prompt rules, taint sources/escalation. Redistribute via MDM or GitOps.

| Env var | Purpose |
| --- | --- |
| `MCP_SHIELD_HOME` | State directory (default `~/.mcp-shield`) |
| `MCP_SHIELD_CONFIG_HOME` | Override home root used for IDE config discovery (tests/demos) |
| `MCP_SHIELD_HITL` | `interactive` (default) / `auto-deny`; `auto-allow` only works when the signed policy sets `allow_headless_hitl_override` |
| `MCP_SHIELD_VAULT_PASSWORD` | Passphrase for the encrypted vault fallback |

## Testing

- **Unit + integration:** `cargo test` — 49 unit tests (policy, redactor, audit
  chain, vault, canonicalization) + 8 end-to-end tests that spawn the real
  binary and drive attacks through real stdio pipes.
- **Self-test:** `mcp-shield verify` (see the table above).
- **Demo environment:** `testenv/` with planted-secret fixtures and
  `run-demo.sh`.
- CI runs the full matrix (Ubuntu/Windows/macOS): build with `-D warnings`,
  tests, `verify`, and crates.io packaging validation.

## Project status & roadmap

`v0.3.3` is the current release; the review rounds it incorporates: signed
policy, HMAC-keyed audit, framing discipline, tool-surface pinning, and
server/env pinning. Deliberately deferred to the next milestones (documented,
not silently claimed): **child network sandboxing** (macOS seatbelt / Linux
seccomp+netns / Windows AppContainer — the strongest remaining lever, since
stdout DLP alone cannot stop a malicious child from exfiltrating injected
secrets), **Touch ID HITL** (requires a LocalAuthentication helper app),
**OTel/SIEM export + scheduled heartbeat** (MDM packaging), **release signing**
(Authenticode / Apple notarization), and **OAuth 2.1/OIDC upstream identity**
(Aembit/Okta/CyberArk integration).

## Links

[Changelog](CHANGELOG.md) · [Security policy](SECURITY.md) ·
[Contributing](CONTRIBUTING.md) · [Pilot quickstart](PILOT_QUICKSTART.md)

## License

[MIT](LICENSE)
