//! CLI definition (`clap` derive).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "mcp-shield",
    version,
    about = "Enterprise Local-First MCP Runtime Security Shim, Secret Broker & Policy Enforcement",
    long_about = "mcp-shield wraps local MCP server invocations (Claude Code, Claude Desktop, \
                  Windsurf, VS Code, Kimi Code, Antigravity) to zeroize plaintext secrets into the OS \
                  Keychain, enforce deterministic <2ms policy guardrails on JSON-RPC stdio traffic, \
                  redact leaked secrets before they reach the LLM, and write tamper-evident audit logs."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan standard IDE MCP config paths for plaintext secrets and unshimmed servers
    Audit {
        /// Emit the report as JSON
        #[arg(long)]
        json: bool,
    },
    /// Migrate IDE MCP configs so every server is governed by mcp-shield
    Wrap {
        /// Which configs to migrate
        #[arg(long, default_value = "all")]
        target: String,
        /// Preview changes without writing configs or storing secrets
        #[arg(long)]
        dry_run: bool,
    },
    /// Restore original configs from .bak backups and remove Keychain entries
    Unwrap,
    /// Inline stdio JSON-RPC interceptor (invoked automatically by wrapped configs)
    Exec {
        /// Logical MCP server name (used for Keychain accounts & audit log)
        #[arg(long)]
        server_name: String,
        /// Path to a policy TOML (default: ~/.mcp-shield/policy.toml)
        #[arg(long)]
        policy: Option<PathBuf>,
        /// The original MCP server command, after `--`
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Run the automated attack & performance self-test (red-team suite)
    Verify,
    /// Operational health check for IT/DevEx (store, policy, drift, HITL)
    Doctor,
    /// Re-sign the policy after admin review (updates the sig and trust pin)
    ResignPolicy {
        /// Policy file to sign (default: ~/.mcp-shield/policy.toml)
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Run the built-in mock MCP server (used by `verify` and tests)
    MockServer,
}
