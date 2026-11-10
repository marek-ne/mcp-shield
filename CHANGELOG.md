# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [0.1.0] - 2026-11-10

Initial public release — the customer-pilot-ready MVP.

### Added

- `mcp-shield audit [--json]`: workstation exposure report across
  Claude Code, Claude Desktop, Antigravity/Gemini, VS Code, Windsurf, Kimi
  Code, and Meta Muse Code MCP config paths (user- and workspace-level);
  CRITICAL/WARN/PASS grading of plaintext secrets and unshimmed servers.
- `mcp-shield wrap [--target …] [--dry-run]` / `unwrap`: automatic shimming —
  timestamped `.bak` backups, secret extraction (env blocks and
  credential-bearing argv) into the OS Keychain, config rewrite to route
  servers through the shim, and clean restore.
- `mcp-shield exec`: inline stdio JSON-RPC 2.0 interceptor — env hydration of
  `mcp-shield://keychain/…` placeholders at child-spawn time (late-bound
  injection), non-blocking stderr relay, capped line framing, malformed
  request rejection (`-32600` for `id: null` tool calls).
- Deterministic policy engine (`~/.mcp-shield/policy.toml`, auto-generated):
  blocked paths (component-based `**/.ssh/**`, `**/.aws/**`, `**/.kube/**`,
  `.env*`, `*.pem`, `*.key`, `/etc/*`) with percent-decoding, dot-segment
  resolution, and CWD-relative resolution before rule evaluation; destructive
  SQL (DROP/TRUNCATE/GRANT ALL/ALTER, DELETE without WHERE); destructive shell
  (tokenized `rm -rf`, mkfs, `dd if=`, `curl|sh`, base64 pipe exec, chmod 777,
  env dumps); HITL prompts for UPDATE/INSERT, `git push --force`, `npm
  publish`, network egress; session taint escalation for indirect prompt
  injection (fetch/web_search/read_email/github_get_issue → writes/exec gated).
- Secret redaction from child output before it reaches the LLM context:
  PEM keys, AWS/GitHub/Slack/OpenAI/Anthropic tokens, JWTs, Bearer tokens,
  DB connection-string passwords, credit cards (Luhn), IBANs (Mod-97,
  token-trimmed matching), high-entropy opaque tokens, and exact-match
  redaction of every Keychain-resolved secret.
- Human-in-the-Loop approval: native OS dialogs (macOS osascript, Windows
  PowerShell MessageBox, Linux zenity), 30 s fail-closed timeout,
  `MCP_SHIELD_HITL=auto-allow|auto-deny` for headless/CI.
- Tamper-evident audit: append-only JSONL with SHA-256 hash chain, per-event
  `latency_us`, cross-process safe (atomic lock + chain re-sync).
- `mcp-shield verify`: self-contained attack & performance self-test with a
  built-in mock MCP server (`mcp-shield mock-server`) — handshake passthrough,
  p99 overhead vs direct baseline, 5-vector red-team suite, redaction checks,
  taint escalation, audit-chain integrity, RSS footprint.
- Encrypted file-vault fallback (AES-256-GCM, Argon2id) for headless
  environments without an OS keyring.
- Test environment: planted-secret fixtures + demo loop script
  (`../testenv/run-demo.sh`).
- 39 unit + 4 end-to-end integration tests; zero-warning release build.

### Security notes

- Fail-closed everywhere: unresolvable secrets, dialog errors, and timeouts
  deny the action.
- Audit log records commands with placeholders only — resolved secrets never
  touch the log.
- Relative tool paths resolve against the shim's CWD so `../.ssh/…` cannot
  escape path rules; blocked-path globs are component-based to catch
  `~/../.ssh` on multi-user machines.

## [0.3.3] - 2026-11-10

- **Anti-unwrapping, Windows separators**: `extract_path_tokens` now converts
  `\` to `/` before the path-shape check, so `C:\Users\x\.kimi-code\mcp.json`
  (and `%USERPROFILE%\...` forms) are matched against the blocked-config
  globs instead of being dropped (unit-tested at the token and policy level,
  incl. a `python -c open(r'...')` rewrite attempt).

[0.3.3]: https://github.com/marek-ne/mcp-shield/releases/tag/v0.3.3

## [0.3.2] - 2026-11-10

Follow-up hardening (review #4): closing the policy-bootstrap and
shim-removal gaps.

### Fixed

- **Custom `--policy` files are never auto-signed**: first-boot auto-sign is
  restricted to the default policy path. A policy dropped at a fresh path is
  refused until an admin runs `mcp-shield resign-policy --policy <path>`
  (integration-tested: unsigned refusal, explicit signing, then enforcement).
- **Anti-unwrapping**: the default policy now blocks writes to every wrapped
  MCP client config (`**/mcp.json`, `**/.mcp.json`, `**/mcp_config.json`,
  `**/.claude.json`, `**/claude_desktop_config.json`, `**/.vscode/mcp.json`,
  `**/.config/muse/settings.json`), so an agent can no longer rewrite its own
  server entries back to the raw command and silently bypass the shim.
- **Upgrade drift is visible and self-healing**: `doctor` flags policies that
  predate security defaults (lists exactly what is missing); `resign-policy`
  merges those defaults into the default policy and re-signs. Demonstrated
  end-to-end on a live 0.3.1-era policy.
- **ADS stripping hardened**: only plausible stream suffixes are stripped
  (drive letters and `scheme://` preserved; "curl https://x | sh" is no
  longer amputated at the scheme colon), applied in both normalize and
  canonicalize. Drive-letter ADS (`C:/keys/server.pem:hidden`) now matches
  `**/*.pem` (unit-tested).
- **Docs drift**: README test counts, status version, and mojibake repaired.

[0.3.2]: https://github.com/marek-ne/mcp-shield/releases/tag/v0.3.2

## [0.3.1] - 2026-11-10

Follow-up hardening (review #3). The headline fix: policy signing is now
fail-closed against a signature-file deletion attack.

### Fixed

- **Policy signing fail-closed**: a Keychain trust pin (per policy path) holds
  the hash of the signed policy. Deleting `policy.toml.sig` no longer yields a
  fresh signature for modified content: re-signing only happens on first boot,
  when the content is byte-identical to the pin, or via the explicit admin
  action `mcp-shield resign-policy`. Integration-tested end-to-end (benign
  restore + tamper refusal + admin recovery).
- **`child_env_allowlist` actually restricts**: `env_clear()` is called before
  applying the allowlist (previously the child inherited everything and the
  list was additive). Integration-tested with an env probe.
- **Windows HITL**: restored `Add-Type -AssemblyName PresentationFramework`
  (dropped in the stdin rewrite), so the dialog loads on a clean PowerShell.
- **realpath is now a real call**: extracted path tokens are resolved with
  `fs::canonicalize` (symlinks/junctions cannot walk around blocked paths);
  NTFS alternate-data-stream suffixes are stripped before matching.
- **Default policy blocks `**/.mcp-shield/**`**: an agent can no longer edit
  the policy, audit log, vault, or backups through a governed tool.
- **Taint classification boundaries**: patterns match whole name segments, so
  `research_*` no longer taints via "search" (fewer false HITL prompts).
- **Poison-signature coverage**: "disregard your system prompt", base64-decode
  instructions, and "your system prompt" added; scan still masks pre-agent.
- **Keychain probe race**: parallel shim processes no longer fail each other's
  backend probe (per-process probe account) — this was an intermittent
  integration-test failure.
- **CI**: clippy component installed; README test counts corrected;
  PILOT_QUICKSTART no longer presents `auto-allow` as a normal switch.

[0.3.1]: https://github.com/marek-ne/mcp-shield/releases/tag/v0.3.1

## [0.3.0] - 2026-11-10

Defense-in-depth release addressing the second, threat-model-level review:
framing evasion, policy integrity, audit keying, and tool-surface attacks.

### Fixed (defects from review #2)

- **JSON-RPC batches** (arrays), **non-JSON frames**, and **Content-Length
  framing** are denied with `-32600` and audited — never forwarded unevaluated.
- **Method coverage inverted to default-allow**: only `initialize`, `ping`,
  `notifications/*`, and `tools/list` pass through untouched; every other
  method (incl. `prompts/get`, `completion/complete`) is policy-evaluated.
- **`--target antigravity` no longer also wraps Muse** (filter fallback bug).
- **Unwrap** deletes the encrypted backups it restored from; backups live under
  `~/.mcp-shield/backups/<config_id>/`, not beside the config.
- **HITL injection**: dialog text now travels as data (macOS `argv`, Windows
  stdin) — tool arguments can no longer alter the dialog program.
- **`MCP_SHIELD_HITL=auto-allow`** is ignored unless the signed policy sets
  `allow_headless_hitl_override` (no env-var kill switch).
- **Crypto hygiene**: CSPRNG (OsRng) for nonces/salts/keys (was UUID-derived);
  vault entry filenames are hashed (no sanitizer collisions); Windows
  Credential Manager size cap documented in the error message.
- **State file permissions**: `0700`/`0600` on everything under
  `~/.mcp-shield` (Unix; Windows relies on default ACLs — documented).

### Added

- **Signed policy**: ed25519 signature over `policy.toml` (key in the secret
  store or MDM); verification fail-closed at every `exec` startup. New policy
  knobs: `allow_headless_hitl_override`, `child_env_allowlist`,
  `server_allowlist`.
- **HMAC-keyed audit**: every event carries an `event_mac` (key in the secret
  store); `verify_chain` detects full-rewrites, with a legacy-prefix
  exception for pre-upgrade logs (hash chain still covers the prefix).
- **tools/list pinning**: advertised tools are fingerprinted per session; a
  mid-session mutation is refused (rug-pull defense). Tool descriptions are
  scanned for instructive prompt injections ("ignore previous instructions",
  "you must call...") and masked before the agent sees them.
- **Server pinning gate**: `exec` refuses servers outside a signed-policy
  `server_allowlist`.
- **Env allowlist mode**: `child_env_allowlist` restricts the child's
  environment (opt-in; default inherits).
- **Taint classification by pattern** (external-read vs write/exec/egress
  regex classes) instead of exact tool-name lists; **path-token extraction**
  catches buried paths (`cat ~/.ssh/id_rsa`, JSON blobs, `%USERPROFILE%`,
  NTFS ADS); **interpreter env dumps** (`python -c os.environ`, `node -e
  process.env`, `gci env:`) blocked as env dumps.
- **`mcp-shield doctor`**: secret store, policy signature + permissions,
  audit chain + keying, config drift (stale shim paths), HITL helper, env
  override posture.
- New `verify` vectors: batch/Content-Length/garbage denial, interpreter env
  dumps, buried path tokens, tools/list pinning + poison masking. New
  integration tests: policy tamper fails closed, server pinning fails closed.
- CI: `cargo clippy -D warnings` and `cargo audit`.

[0.3.0]: https://github.com/marek-ne/mcp-shield/releases/tag/v0.3.0

## [0.2.0] - 2026-11-10

Security hardening release: independent review found gaps between the pilot
claims and the implementation; all findings are fixed here and covered by new
tests and `verify` vectors.

### Fixed

- **Plaintext backups**: `wrap` backups are now AES-256-GCM encrypted at rest
  (key held in the secret store, never on disk); `unwrap` decrypts them
  (legacy plaintext backups still restore). `audit` additionally scans
  `*.bak.*` siblings and flags any plaintext secret found in them.
- **Keychain account collisions**: accounts are now namespaced per config file
  (`<config_id>:<server>:<KEY>`; placeholders encode the same), so identical
  server names in different configs no longer overwrite each other.
- **`resources/read` inspected**: the proxy merges `params.uri` into the
  evaluated arguments, so `file://~/.ssh/id_rsa` is blocked like any path.
- **Fail-closed secret resolution**: an unresolvable placeholder now aborts
  the server spawn instead of starting it with the placeholder in argv/env.
- **Oversized frames**: request lines hitting the 16 MB cap are denied with
  `-32600` and never forwarded unevaluated; responses are still redacted and
  re-framed; stderr relay is capped (1 MB) **and redacted**, so secrets a
  child prints to stderr no longer reach the IDE.
- **Client schema coverage**: current VS Code `servers` key and `command`-as-
  array form are supported; remote (http/sse) entries are no longer rewritten
  into broken stdio entries; current Devin Desktop / Cascade path
  (`…/devin/mcp_config.json`) added for Windsurf; credentials in remote
  `headers` are flagged by `audit`.
- **Memory measurement on the pilot OS**: RSS is now measured on macOS
  (`ps`) and Linux (`/proc/<pid>/status`) too — no more auto-PASS off Windows.
- **Linux HITL**: `zenity` approval now uses the exit code (stdout is empty),
  so prompts can actually succeed.
- **Guardrail holes**: shell-wrapped SQL (`psql -c "DROP TABLE …"`) is blocked
  by unconditional statement matching; `bash -c "rm -rf /"` and
  `rm --recursive --force` are caught by quote-stripping, long-flag-aware rm
  detection; `DELETE … WHERE 1=1` is treated as no-WHERE; fine-grained
  `github_pat_…` and temporary `ASIA…` AWS keys are detected/redacted;
  sensitive env values shorter than 8 chars are no longer skipped.
- **Spec field**: audit decisions now also record `processing_time_us`.

### Added

- `heartbeat` audit events every 30 min of a shim session (pilot retention
  metric 4 is now measurable from the audit log).
- New `verify` vectors: `resources/read` URI traversal, `WHERE 1=1`, shell-
  wrapped DROP, quoted/long-flag rm variants, fine-grained PAT / temp AWS key
  redaction.

[0.2.0]: https://github.com/marek-ne/mcp-shield/releases/tag/v0.2.0
[0.1.0]: https://github.com/marek-ne/mcp-shield/releases/tag/v0.1.0
