#!/usr/bin/env bash
# Pilot demo loop against the isolated test environment (fake HOME with
# planted plaintext secrets). Runs: audit -> wrap -> audit -> verify -> unwrap.
#
# Usage:  bash testenv/run-demo.sh [/path/to/mcp-shield.exe]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-$ROOT/../target/release/mcp-shield.exe}"
FAKE_HOME="$ROOT/home"
# Fresh state per run: the Keychain trust pin is keyed by policy path, so
# a reused state dir would (correctly) refuse after any policy upgrade.
SHIELD_HOME="$(mktemp -d /tmp/mcp-shield-demo.XXXXXX)"
export MCP_SHIELD_HOME="$SHIELD_HOME"
# Encrypted vault fallback password (only used if the OS keychain is unavailable).
export MCP_SHIELD_VAULT_PASSWORD="pilot-demo-password"

if [ ! -f "$BIN" ]; then
  echo "binary not found: $BIN (run: cargo build --release)" >&2
  exit 1
fi

# Point config discovery at the fake profile so the planted fixtures are
# scanned instead of the real machine (MCP_SHIELD_CONFIG_HOME overrides the
# OS home directory for discovery).
export MCP_SHIELD_CONFIG_HOME="$FAKE_HOME"

echo "================= 1) mcp-shield audit (Day 1: exposure) ================="
"$BIN" audit
echo
echo "================= 2) mcp-shield wrap --dry-run =========================="
"$BIN" wrap --target all --dry-run
echo
echo "================= 3) mcp-shield wrap (zeroize secrets) ================"
"$BIN" wrap --target all
echo
echo "================= 4) mcp-shield audit (Day 2: after wrap) =============="
"$BIN" audit
echo
echo "================= 5) mcp-shield verify (attack & performance) =========="
"$BIN" verify
echo
echo "================= 6) mcp-shield unwrap (restore) ======================"
"$BIN" unwrap
echo
echo "Demo loop complete. Audit log + policy were under: $SHIELD_HOME"
