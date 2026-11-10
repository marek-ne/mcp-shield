# Contributing to mcp-shield

Thanks for your interest. This is a security product: the bar is **deterministic,
reviewable, tested** change.

## Ground rules

- No new dependencies without an issue explaining why the std library or an
  existing crate cannot do the job.
- No ML/LLM components in the enforcement path — decisions must be
  deterministic and explainable (violation IDs in denials).
- No plaintext secrets anywhere: not in logs, not in error messages, not in
  test fixtures (use obviously fake tokens like `ghp_demo...`).
- Fail closed: unresolved secrets, dialog errors, and timeouts deny.

## Development setup

Windows (this repo was bootstrapped without MSVC — gnu toolchain + rust-lld):

```bash
rustup default stable-x86_64-pc-windows-gnu
cargo test
cargo build --release
```

macOS/Linux: any recent stable toolchain works out of the box.

## Workflow

1. Fork + branch (`feat/…`, `fix/…`, `policy/…`).
2. `cargo fmt` and keep `cargo build --all-targets` warning-free (CI enforces).
3. Add tests: unit tests in the module for rules/redactors/audit logic;
   end-to-end cases in `tests/integration.rs` (they spawn the real binary).
   Extend `mcp-shield verify` only for pilot-facing checks.
4. Run the full loop before opening a PR:

   ```bash
   cargo test
   cargo build --release
   ./target/release/mcp-shield verify
   bash testenv/run-demo.sh
   ```

5. PR description: what threat scenario changes, what the before/after
   behavior is, and the verify/test output.

## Policy changes

Rules in `src/policy.rs` (`DEFAULT_POLICY_TOML`) ship to customers via
auto-generated `~/.mcp-shield/policy.toml`. Changing defaults is a
compatibility decision: describe the customer impact and the expected
false-positive/negative trade-off in the PR.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Never open a public issue for a
vulnerability.
