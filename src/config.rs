//! IDE MCP config discovery, risk auditing (`audit`), automatic shimming
//! (`wrap`) and restore (`unwrap`).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::keychain::{self, SecretStore};
use crate::redactor::{classify_secret, is_extractable_secret};
use crate::util::{collect_strings, sensitive_env_key, wrap_state_path, VAULT_PREFIX};

#[derive(Debug, Clone)]
struct ConfigLocation {
    origin: &'static str,
    path: PathBuf,
}

fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

/// Root used for IDE config discovery. `MCP_SHIELD_CONFIG_HOME` overrides the
/// OS home directory — used by tests, the bundled demo environment, and
/// portable/MDM deployments that stage configs in a non-standard location.
fn discovery_root() -> PathBuf {
    std::env::var_os("MCP_SHIELD_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(home)
}

fn config_home_is_overridden() -> bool {
    std::env::var_os("MCP_SHIELD_CONFIG_HOME").is_some()
}

/// Per-platform user config dir (where VS Code & friends keep `User/` state),
/// honoring MCP_SHIELD_CONFIG_HOME for tests/demos.
fn user_config_dir() -> PathBuf {
    let root = discovery_root();
    if config_home_is_overridden() {
        #[cfg(target_os = "windows")]
        let p = root.join("AppData/Roaming");
        #[cfg(target_os = "macos")]
        let p = root.join("Library/Application Support");
        #[cfg(all(unix, not(target_os = "macos")))]
        let p = root.join(".config");
        #[cfg(not(any(target_os = "macos", target_os = "windows", unix)))]
        let p = root.join(".config");
        return p;
    }
    dirs::config_dir().unwrap_or_else(home)
}

/// Kimi Code's state root: `$KIMI_CODE_HOME`, else `~/.kimi-code`.
fn kimi_code_dir() -> PathBuf {
    std::env::var_os("KIMI_CODE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| discovery_root().join(".kimi-code"))
}

fn claude_desktop_config() -> PathBuf {
    let root = discovery_root();
    if config_home_is_overridden() {
        #[cfg(target_os = "windows")]
        let p = root.join("AppData/Roaming/Claude/claude_desktop_config.json");
        #[cfg(target_os = "macos")]
        let p = root.join("Library/Application Support/Claude/claude_desktop_config.json");
        #[cfg(all(unix, not(target_os = "macos")))]
        let p = root.join(".config/Claude/claude_desktop_config.json");
        #[cfg(not(any(target_os = "macos", target_os = "windows", unix)))]
        let p = root.join(".config/Claude/claude_desktop_config.json");
        return p;
    }
    #[cfg(target_os = "macos")]
    let p = home().join("Library/Application Support/Claude/claude_desktop_config.json");
    #[cfg(target_os = "windows")]
    let p = dirs::config_dir()
        .unwrap_or_else(|| home().join("AppData/Roaming"))
        .join("Claude/claude_desktop_config.json");
    #[cfg(all(unix, not(target_os = "macos")))]
    let p = home().join(".config/Claude/claude_desktop_config.json");
    #[cfg(not(any(target_os = "macos", target_os = "windows", unix)))]
    let p = home().join(".config/Claude/claude_desktop_config.json");
    p
}

fn known_locations(target: &str) -> Result<Vec<ConfigLocation>> {
    let home = discovery_root();
    let cwd = std::env::current_dir()?;
    let all = vec![
        ConfigLocation {
            origin: "cursor-global",
            path: home.join(".cursor/mcp.json"),
        },
        ConfigLocation {
            origin: "cursor-workspace",
            path: cwd.join(".cursor/mcp.json"),
        },
        ConfigLocation {
            origin: "claude-code-global",
            path: home.join(".claude.json"),
        },
        ConfigLocation {
            origin: "claude-code-workspace",
            path: cwd.join(".mcp.json"),
        },
        ConfigLocation {
            origin: "claude-desktop",
            path: claude_desktop_config(),
        },
        ConfigLocation {
            origin: "antigravity",
            path: home.join(".gemini/config/mcp_config.json"),
        },
        ConfigLocation {
            origin: "vscode-user",
            path: user_config_dir().join("Code/User/mcp.json"),
        },
        ConfigLocation {
            origin: "vscode-workspace",
            path: cwd.join(".vscode/mcp.json"),
        },
        ConfigLocation {
            origin: "windsurf",
            path: home.join(".codeium/windsurf/mcp_config.json"),
        },
        ConfigLocation {
            // Current Devin Desktop / Cascade location (the ~/.codeium path
            // above is the legacy Windsurf location).
            origin: "windsurf",
            path: user_config_dir().join("devin/mcp_config.json"),
        },
        ConfigLocation {
            origin: "kimi-code-user",
            path: kimi_code_dir().join("mcp.json"),
        },
        ConfigLocation {
            origin: "kimi-code-workspace",
            path: cwd.join(".kimi-code/mcp.json"),
        },
        ConfigLocation {
            // Meta Muse Code: MCP servers live in the `mcpServers` block of
            // its settings.json (which also carries "schema_version": 1 —
            // preserved untouched by wrap).
            origin: "muse",
            path: home.join(".config/muse/settings.json"),
        },
    ];
    const KNOWN: [&str; 9] = [
        "all",
        "cursor",
        "claude-code",
        "claude-desktop",
        "antigravity",
        "vscode",
        "windsurf",
        "kimi-code",
        "muse",
    ];
    if !KNOWN.contains(&target) {
        bail!(
            "unknown wrap target '{target}' (expected one of: {})",
            KNOWN.join(", ")
        );
    }
    let filter = |o: &str| match target {
        "all" => true,
        "cursor" => o.starts_with("cursor"),
        "claude-code" => o.starts_with("claude-code"),
        "claude-desktop" => o == "claude-desktop",
        "vscode" => o.starts_with("vscode"),
        "windsurf" => o == "windsurf",
        "kimi-code" => o.starts_with("kimi-code"),
        "antigravity" => o == "antigravity",
        _ => o == "muse", // "muse"
    };
    Ok(all.into_iter().filter(|l| filter(l.origin)).collect())
}

/// The key under which a config file holds its server table. Most clients use
/// `mcpServers`; current VS Code uses `servers`.
fn servers_key(doc: &Value) -> Option<&'static str> {
    if doc.get("mcpServers").is_some() {
        Some("mcpServers")
    } else if doc.get("servers").is_some() {
        Some("servers")
    } else {
        None
    }
}

fn mcp_servers_of(doc: &Value) -> Option<&Map<String, Value>> {
    doc.get(servers_key(doc)?).and_then(Value::as_object)
}

/// Stable short identifier for a config file, used to namespace Keychain
/// accounts so two configs can define the same server name without collision.
pub fn config_id(path: &Path) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(path.to_string_lossy().replace('\\', "/").as_bytes());
    crate::audit::hex_encode(&h.finalize())[..8].to_string()
}

fn is_shimmed(command: &str) -> bool {
    let lower = command.to_lowercase();
    lower.contains("mcp-shield") || lower.contains("mcp_shield")
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ServerFinding {
    origin: String,
    config_path: String,
    server: String,
    shimmed: bool,
    secrets: Vec<SecretFinding>,
}

#[derive(Debug, Serialize)]
struct SecretFinding {
    location: String, // "env:KEY" or "args[2]"
    kind: String,
    preview: String,
}

#[derive(Debug, Serialize)]
struct AuditReport {
    grade: String, // CRITICAL | WARN | PASS
    configs_scanned: usize,
    servers_found: usize,
    plaintext_secret_count: usize,
    unshimmed_count: usize,
    findings: Vec<ServerFinding>,
}

fn preview(value: &str) -> String {
    let mut p: String = value.chars().take(12).collect();
    p.push('…');
    p.push_str(&value.len().to_string());
    p.push_str("chars");
    p
}

pub fn run_audit(json_output: bool) -> Result<i32> {
    let locations = known_locations("all")?;
    let mut report = AuditReport {
        grade: "PASS".to_string(),
        configs_scanned: 0,
        servers_found: 0,
        plaintext_secret_count: 0,
        unshimmed_count: 0,
        findings: Vec::new(),
    };

    for loc in &locations {
        if !loc.path.exists() {
            continue;
        }
        let raw = match fs::read_to_string(&loc.path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[mcp-shield] cannot read {}: {e}", loc.path.display());
                continue;
            }
        };
        let doc: Value = match serde_json::from_str(&raw) {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "[mcp-shield] {} is not valid JSON ({e}); skipping",
                    loc.path.display()
                );
                continue;
            }
        };
        report.configs_scanned += 1;
        let Some(servers) = mcp_servers_of(&doc) else {
            continue;
        };
        for (name, server) in servers {
            report.servers_found += 1;
            let command = server.get("command").and_then(Value::as_str).unwrap_or("");
            let shimmed = is_shimmed(command);
            if !shimmed {
                report.unshimmed_count += 1;
            }
            let mut secrets = Vec::new();
            if let Some(env) = server.get("env").and_then(Value::as_object) {
                for (k, v) in env {
                    if let Some(s) = v.as_str() {
                        if s.starts_with(VAULT_PREFIX) {
                            continue;
                        }
                        if let Some(kind) = classify_secret(s) {
                            secrets.push(SecretFinding {
                                location: format!("env:{k}"),
                                kind: kind.to_string(),
                                preview: preview(s),
                            });
                        } else if sensitive_env_key(k) && !s.is_empty() && s.len() >= 4 {
                            secrets.push(SecretFinding {
                                location: format!("env:{k}"),
                                kind: "SENSITIVE_VALUE".to_string(),
                                preview: preview(s),
                            });
                        }
                    }
                }
            }
            // Remote servers keep credentials in `headers`; they cannot be
            // late-bound injected (no local child process), so flag EVERY
            // header (an opaque Authorization value is still a credential)
            // and any envFile indirection.
            if let Some(headers) = server.get("headers").and_then(Value::as_object) {
                for (k, v) in headers {
                    if let Some(sv) = v.as_str() {
                        if sv.starts_with(VAULT_PREFIX) {
                            continue;
                        }
                        let kind = classify_secret(sv)
                            .map(|c| format!("{c}_IN_HEADERS"))
                            .unwrap_or_else(|| "HEADER_VALUE".to_string());
                        secrets.push(SecretFinding {
                            location: format!("headers:{k}"),
                            kind,
                            preview: preview(sv),
                        });
                    }
                }
            }
            if server.get("envFile").is_some() || server.get("env_file").is_some() {
                secrets.push(SecretFinding {
                    location: "envFile".to_string(),
                    kind: "ENV_FILE_REFERENCE".to_string(),
                    preview: "external env file".to_string(),
                });
            }
            if let Some(args) = server.get("args").and_then(Value::as_array) {
                for (i, a) in args.iter().enumerate() {
                    if let Some(s) = a.as_str() {
                        if let Some(kind) = classify_secret(s) {
                            secrets.push(SecretFinding {
                                location: format!("args[{i}]"),
                                kind: kind.to_string(),
                                preview: preview(s),
                            });
                        }
                    }
                }
            }
            report.plaintext_secret_count += secrets.len();
            report.findings.push(ServerFinding {
                origin: loc.origin.to_string(),
                config_path: loc.path.display().to_string(),
                server: name.clone(),
                shimmed,
                secrets,
            });
        }

        // Backstop: scan sibling backup files (`<config>.bak.*`). Current
        // wrap writes them encrypted (binary — skipped); legacy plaintext
        // backups are flagged so "100% elimination" stays honest.
        if let Some(parent) = loc.path.parent().and_then(|p| p.canonicalize().ok()) {
            let stem = loc
                .path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if let Ok(rd) = fs::read_dir(&parent) {
                for e in rd.flatten() {
                    let fname = e.file_name().to_string_lossy().to_string();
                    if !fname.starts_with(&format!("{stem}.bak.")) {
                        continue;
                    }
                    let Ok(bytes) = fs::read(e.path()) else {
                        continue;
                    };
                    let Ok(text) = String::from_utf8(bytes) else {
                        continue;
                    }; // encrypted backups are binary
                    let mut backup_secrets = Vec::new();
                    if let Ok(bak) = serde_json::from_str::<Value>(&text) {
                        if let Some(servers) = mcp_servers_of(&bak) {
                            for (srv, entry) in servers {
                                let mut locations: Vec<String> = Vec::new();
                                collect_strings(entry, &mut locations);
                                for s in locations {
                                    if s.starts_with(VAULT_PREFIX) {
                                        continue;
                                    }
                                    if let Some(kind) = classify_secret(&s) {
                                        backup_secrets.push(SecretFinding {
                                            location: format!("server:{srv}"),
                                            kind: format!("{kind}_IN_BACKUP"),
                                            preview: preview(&s),
                                        });
                                    }
                                }
                            }
                        }
                    }
                    if !backup_secrets.is_empty() {
                        report.plaintext_secret_count += backup_secrets.len();
                        report.findings.push(ServerFinding {
                            origin: format!("{}-backup", loc.origin),
                            config_path: e.path().display().to_string(),
                            server: "(backup file)".to_string(),
                            shimmed: true,
                            secrets: backup_secrets,
                        });
                    }
                }
            }
        }
    }

    report.grade = if report.plaintext_secret_count > 0 {
        "CRITICAL".to_string()
    } else if report.unshimmed_count > 0 {
        "WARN".to_string()
    } else {
        "PASS".to_string()
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mcp-shield workstation audit");
        println!("============================");
        println!("configs scanned : {}", report.configs_scanned);
        println!("servers found   : {}", report.servers_found);
        println!("plaintext secrets: {}", report.plaintext_secret_count);
        println!("unshimmed servers: {}", report.unshimmed_count);
        println!();
        if report.findings.is_empty() {
            println!("No MCP config files found on standard paths — nothing to audit.");
        }
        for f in &report.findings {
            let status = if f.shimmed { "SHIMMED " } else { "EXPOSED " };
            println!(
                "[{status}] {} ({}) via {}",
                f.server, f.origin, f.config_path
            );
            for s in &f.secrets {
                println!("           - {} [{}] {}", s.location, s.kind, s.preview);
            }
        }
        println!();
        match report.grade.as_str() {
            "CRITICAL" => println!(
                "GRADE: CRITICAL — plaintext credentials found. Run `mcp-shield wrap` to move them into the OS Keychain."
            ),
            "WARN" => println!("GRADE: WARN — unshimmed MCP servers found. Run `mcp-shield wrap` to enable governance."),
            _ => println!("GRADE: PASS — no plaintext secrets, all servers governed by mcp-shield."),
        }
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// wrap
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct WrapStateEntry {
    config_path: String,
    backup_path: String,
    servers: Vec<WrappedServer>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WrappedServer {
    name: String,
    keychain_accounts: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WrapState {
    wrapped_at: String,
    entries: Vec<WrapStateEntry>,
}

/// Transform one server entry: extract env/args secrets to the store (under
/// an account namespaced by `config_id` so identical server names in different
/// config files never collide), replace them with `mcp-shield://keychain/…`
/// placeholders, and rewrite command/args so the shim is the entrypoint.
/// Remote entries (no local `command`) are left untouched — there is no local
/// child process to wrap.
pub fn shim_server_entry(
    config_id: &str,
    server_name: &str,
    entry: &mut Value,
    exe: &Path,
    store: &dyn SecretStore,
    dry_run: bool,
    accounts: &mut Vec<String>,
) -> Result<bool> {
    let Some(obj) = entry.as_object_mut() else {
        return Ok(false);
    };
    // Normalize `command`: string, or array whose first element is the binary
    // (a form current VS Code accepts).
    let (command, prefix_args): (String, Vec<Value>) = match obj.get("command") {
        Some(Value::String(s)) => (s.clone(), Vec::new()),
        Some(Value::Array(a)) => {
            let mut it = a.iter();
            match it.next() {
                Some(Value::String(c)) => (c.clone(), it.cloned().collect()),
                _ => return Ok(false),
            }
        }
        _ => return Ok(false), // remote (http/sse) entry — nothing local to wrap
    };
    if command.is_empty() || is_shimmed(&command) {
        return Ok(false);
    }

    let account_for = |what: &str| format!("{config_id}:{server_name}:{what}");
    let placeholder_for = |account: &str| format!("{VAULT_PREFIX}{}", account.replace(':', "/"));

    // 1) Extract env secrets.
    if let Some(env) = obj.get_mut("env").and_then(Value::as_object_mut) {
        let keys: Vec<String> = env.keys().cloned().collect();
        for key in keys {
            let Some(value) = env.get(&key).and_then(Value::as_str) else {
                continue;
            };
            if !is_extractable_secret(&key, value) {
                continue;
            }
            let account = account_for(&key);
            if !dry_run {
                store.set(&account, value).with_context(|| {
                    format!(
                        "cannot store secret '{account}' in the {}",
                        store.backend_name()
                    )
                })?;
            }
            accounts.push(account.clone());
            env.insert(key, Value::String(placeholder_for(&account)));
        }
    }

    // 2) Extract credential-bearing args (e.g. `postgresql://user:pass@host/db`
    //    passed directly on the command line) — required for 100% elimination.
    if let Some(args) = obj.get_mut("args").and_then(Value::as_array_mut) {
        for (i, a) in args.iter_mut().enumerate() {
            let Some(s) = a.as_str() else { continue };
            if s.starts_with(VAULT_PREFIX) {
                continue;
            }
            if crate::redactor::classify_secret(s).is_none() {
                continue;
            }
            let account = account_for(&format!("ARG{i}"));
            if !dry_run {
                store.set(&account, s).with_context(|| {
                    format!(
                        "cannot store secret '{account}' in the {}",
                        store.backend_name()
                    )
                })?;
            }
            accounts.push(account.clone());
            *a = Value::String(placeholder_for(&account));
        }
    }

    // 3) Rewrite command -> mcp-shield exec --server-name <name> -- <orig...>
    let mut new_args: Vec<Value> = vec![
        Value::String("exec".to_string()),
        Value::String("--server-name".to_string()),
        Value::String(server_name.to_string()),
        Value::String("--".to_string()),
        Value::String(command),
    ];
    new_args.extend(prefix_args);
    if let Some(old_args) = obj.get("args").and_then(Value::as_array) {
        new_args.extend(old_args.iter().cloned());
    }
    obj.insert(
        "command".to_string(),
        Value::String(exe.display().to_string()),
    );
    obj.insert("args".to_string(), Value::Array(new_args));
    Ok(true)
}

pub fn run_wrap(target: &str, dry_run: bool) -> Result<i32> {
    let locations = known_locations(target)?;
    let exe = std::env::current_exe().context("cannot determine own executable path")?;
    let store = keychain::open_store()?;
    let mut state = WrapState {
        wrapped_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        entries: Vec::new(),
    };
    let mut wrapped_servers = 0usize;
    let mut extracted = 0usize;

    for loc in &locations {
        if !loc.path.exists() {
            continue;
        }
        let raw = fs::read_to_string(&loc.path)
            .with_context(|| format!("cannot read {}", loc.path.display()))?;
        let mut doc: Value = serde_json::from_str(&raw)
            .with_context(|| format!("{} is not valid JSON", loc.path.display()))?;
        let Some(servers_key) = servers_key(&doc) else {
            continue;
        };
        let Some(servers) = doc.get_mut(servers_key).and_then(Value::as_object_mut) else {
            continue;
        };
        let cid = config_id(&loc.path);
        let server_names: Vec<String> = servers.keys().cloned().collect();
        let mut entry_state = WrapStateEntry {
            config_path: loc.path.display().to_string(),
            backup_path: String::new(),
            servers: Vec::new(),
        };
        let mut changed = false;
        for name in server_names {
            let Some(server_entry) = servers.get_mut(&name) else {
                continue;
            };
            let mut accounts = Vec::new();
            if shim_server_entry(
                &cid,
                &name,
                server_entry,
                &exe,
                store.as_ref(),
                dry_run,
                &mut accounts,
            )? {
                changed = true;
                wrapped_servers += 1;
                extracted += accounts.len();
                entry_state.servers.push(WrappedServer {
                    name,
                    keychain_accounts: accounts,
                });
            }
        }
        if !changed {
            continue;
        }
        if dry_run {
            println!(
                "[dry-run] would shim {} ({} server(s), {} secret(s))",
                loc.path.display(),
                entry_state.servers.len(),
                extracted
            );
            continue;
        }
        // Encrypted timestamped backup before rewriting. Backups live under
        // ~/.mcp-shield/backups/<config_id>/ (not beside the config), are
        // deleted by `unwrap` after a successful restore, and plaintext
        // secrets never survive on disk (pilot metric 1).
        let backup_dir = crate::util::shield_home().join("backups").join(cid.clone());
        crate::util::ensure_private_dir(&backup_dir)?;
        let backup = backup_dir.join(format!(
            "{}.bak.{}",
            loc.path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "config".to_string()),
            Utc::now().format("%Y%m%dT%H%M%S")
        ));
        let original_bytes =
            fs::read(&loc.path).with_context(|| format!("cannot read {}", loc.path.display()))?;
        let backup_key = keychain::backup_key(store.as_ref())
            .context("cannot obtain the backup encryption key")?;
        let encrypted = keychain::encrypt_file(&backup_key, &original_bytes)?;
        fs::write(&backup, encrypted)
            .with_context(|| format!("cannot write backup {}", backup.display()))?;
        entry_state.backup_path = backup.display().to_string();
        fs::write(&loc.path, serde_json::to_string_pretty(&doc)? + "\n")
            .with_context(|| format!("cannot write {}", loc.path.display()))?;
        println!(
            "[wrapped] {} -> shimmed {} server(s) (encrypted backup: {})",
            loc.path.display(),
            entry_state.servers.len(),
            entry_state.backup_path
        );
        state.entries.push(entry_state);
    }

    if dry_run {
        println!(
            "[dry-run] {} server(s) across target '{}' would be shimmed, {} secret(s) would move to the {}.",
            wrapped_servers,
            target,
            extracted,
            store.backend_name()
        );
        return Ok(0);
    }

    // Merge with any existing wrap-state (different targets wrapped earlier).
    let state_path = wrap_state_path();
    if state_path.exists() {
        let existing: WrapState = serde_json::from_str(&fs::read_to_string(&state_path)?)?;
        let mut merged = existing.entries;
        merged.extend(state.entries);
        state.entries = merged;
    }
    if !state.entries.is_empty() {
        if let Some(parent) = state_path.parent() {
            crate::util::ensure_private_dir(parent)?;
        }
        fs::write(&state_path, serde_json::to_string_pretty(&state)?)?;
        crate::util::set_private_file(&state_path);
    }
    println!(
        "wrap complete: {} server(s) shimmed, {} secret(s) moved to the {}.",
        wrapped_servers,
        extracted,
        store.backend_name()
    );
    Ok(0)
}

pub fn run_unwrap() -> Result<i32> {
    let state_path = wrap_state_path();
    if !state_path.exists() {
        bail!(
            "no wrap-state found at {} — nothing to unwrap. Restore .bak files manually if needed.",
            state_path.display()
        );
    }
    let state: WrapState = serde_json::from_str(&fs::read_to_string(&state_path)?)?;
    let store = keychain::open_store();
    let mut restored = 0usize;
    for entry in &state.entries {
        let backup = PathBuf::from(&entry.backup_path);
        let config = PathBuf::from(&entry.config_path);
        if !backup.exists() {
            eprintln!(
                "[mcp-shield] backup {} missing; skipping restore of {}",
                backup.display(),
                config.display()
            );
            continue;
        }
        // Backups are AES-256-GCM encrypted at rest; fall back to a raw copy
        // for legacy plaintext backups written by early versions.
        let backup_bytes = fs::read(&backup)?;
        let restored_bytes = match &store {
            Ok(store) => match keychain::backup_key(store.as_ref())
                .and_then(|key| keychain::decrypt_file(&key, &backup_bytes))
            {
                Ok(plaintext) => plaintext,
                Err(_) => backup_bytes,
            },
            Err(_) => backup_bytes,
        };
        fs::write(&config, &restored_bytes).with_context(|| {
            format!(
                "cannot restore {} from {}",
                config.display(),
                backup.display()
            )
        })?;
        println!("[restored] {} <- {}", config.display(), backup.display());
        restored += 1;
        // The backup has served its purpose: remove it so no copy of the
        // original (encrypted or not) lingers beside the restored config.
        let _ = fs::remove_file(&backup);
        if let Some(dir) = backup.parent() {
            let _ = fs::remove_dir(dir); // prune empty per-config backup dir
        }
        if let Ok(store) = &store {
            for server in &entry.servers {
                for account in &server.keychain_accounts {
                    if let Err(e) = store.delete(account) {
                        eprintln!("[mcp-shield] cannot delete keychain entry {account}: {e}");
                    }
                }
            }
        }
    }
    fs::remove_file(&state_path).ok();
    println!("unwrap complete: {restored} config(s) restored to pre-shim state.");
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::StoreError;

    /// In-memory store for transform tests.
    struct MemStore(std::sync::Mutex<std::collections::BTreeMap<String, String>>);
    impl SecretStore for MemStore {
        fn backend_name(&self) -> &'static str {
            "mem"
        }
        fn get(&self, account: &str) -> Result<String, StoreError> {
            self.0
                .lock()
                .map_err(|_| StoreError::Backend("lock".into()))?
                .get(account)
                .cloned()
                .ok_or(StoreError::NotFound)
        }
        fn set(&self, account: &str, secret: &str) -> Result<(), StoreError> {
            self.0
                .lock()
                .map_err(|_| StoreError::Backend("lock".into()))?
                .insert(account.to_string(), secret.to_string());
            Ok(())
        }
        fn delete(&self, account: &str) -> Result<(), StoreError> {
            self.0
                .lock()
                .map_err(|_| StoreError::Backend("lock".into()))?
                .remove(account)
                .map(|_| ())
                .ok_or(StoreError::NotFound)
        }
    }

    #[test]
    fn shim_entry_extracts_secrets_and_rewrites_command() {
        let store = MemStore(std::sync::Mutex::new(Default::default()));
        let exe = Path::new("C:/tools/mcp-shield.exe");
        let mut entry = serde_json::json!({
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/db"],
            "env": {
                "GITHUB_TOKEN": "ghp_abcdefghij0123456789abcdefghij0123456789",
                "SLACK_API_TOKEN": "xoxb-123456789012-abcdefghijkl",
                "PLAIN": "not-a-secret"
            }
        });
        let mut accounts = Vec::new();
        let changed = shim_server_entry(
            "c0ffee42",
            "github",
            &mut entry,
            exe,
            &store,
            false,
            &mut accounts,
        )
        .unwrap();
        assert!(changed);
        assert_eq!(
            accounts,
            vec![
                "c0ffee42:github:GITHUB_TOKEN",
                "c0ffee42:github:SLACK_API_TOKEN"
            ]
        );
        assert_eq!(
            entry["env"]["GITHUB_TOKEN"],
            "mcp-shield://keychain/c0ffee42/github/GITHUB_TOKEN"
        );
        assert_eq!(
            entry["env"]["SLACK_API_TOKEN"],
            "mcp-shield://keychain/c0ffee42/github/SLACK_API_TOKEN"
        );
        assert_eq!(entry["env"]["PLAIN"], "not-a-secret");
        assert_eq!(entry["command"], "C:/tools/mcp-shield.exe");
        let args = entry["args"].as_array().unwrap();
        assert_eq!(args[0], "exec");
        assert_eq!(args[1], "--server-name");
        assert_eq!(args[2], "github");
        assert_eq!(args[3], "--");
        assert_eq!(args[4], "npx");
        assert_eq!(args[5], "-y");
        // Secret actually landed in the store, under the namespaced account.
        assert_eq!(
            store.get("c0ffee42:github:GITHUB_TOKEN").unwrap(),
            "ghp_abcdefghij0123456789abcdefghij0123456789"
        );
    }

    #[test]
    fn shim_entry_is_idempotent() {
        let store = MemStore(std::sync::Mutex::new(Default::default()));
        let exe = Path::new("C:/tools/mcp-shield.exe");
        let mut entry = serde_json::json!({
            "command": "C:/tools/mcp-shield.exe",
            "args": ["exec", "--server-name", "x", "--", "npx"]
        });
        let mut accounts = Vec::new();
        let changed = shim_server_entry(
            "c0ffee42",
            "x",
            &mut entry,
            exe,
            &store,
            false,
            &mut accounts,
        )
        .unwrap();
        assert!(!changed);
        assert!(accounts.is_empty());
    }

    #[test]
    fn shim_entry_extracts_credential_bearing_args() {
        let store = MemStore(std::sync::Mutex::new(Default::default()));
        let exe = Path::new("C:/tools/mcp-shield.exe");
        let mut entry = serde_json::json!({
            "command": "npx",
            "args": ["-y", "mcp-server-db", "postgresql://svc:s3kret@db:5432/app", "--verbose"]
        });
        let mut accounts = Vec::new();
        let changed = shim_server_entry(
            "c0ffee42",
            "db",
            &mut entry,
            exe,
            &store,
            false,
            &mut accounts,
        )
        .unwrap();
        assert!(changed);
        assert_eq!(accounts, vec!["c0ffee42:db:ARG2"]);
        let args = entry["args"].as_array().unwrap();
        assert_eq!(args[0], "exec");
        assert_eq!(args[3], "--");
        assert_eq!(args[4], "npx");
        assert_eq!(args[7], "mcp-shield://keychain/c0ffee42/db/ARG2");
        assert_eq!(args[8], "--verbose");
        assert_eq!(
            store.get("c0ffee42:db:ARG2").unwrap(),
            "postgresql://svc:s3kret@db:5432/app"
        );
    }

    #[test]
    fn shim_entry_skips_remote_and_handles_command_array() {
        let store = MemStore(std::sync::Mutex::new(Default::default()));
        let exe = Path::new("C:/tools/mcp-shield.exe");
        // Remote http/sse entry: never rewritten.
        let mut remote = serde_json::json!({
            "type": "http",
            "url": "https://mcp.example.com/mcp",
            "headers": {"Authorization": "Bearer ghp_abcdefghij0123456789abcdefghij0123456789"}
        });
        let mut accounts = Vec::new();
        let changed = shim_server_entry(
            "c0ffee42",
            "remote",
            &mut remote,
            exe,
            &store,
            false,
            &mut accounts,
        )
        .unwrap();
        assert!(!changed, "remote entries must not be shimmed: {remote}");
        assert!(accounts.is_empty());
        // VS Code style: command as array.
        let mut arr = serde_json::json!({
            "type": "stdio",
            "command": ["npx", "-y", "some-server"],
            "env": {"API_KEY": "sk-abcdefghij0123456789ABCDEF"}
        });
        let changed = shim_server_entry(
            "c0ffee42",
            "arr",
            &mut arr,
            exe,
            &store,
            false,
            &mut accounts,
        )
        .unwrap();
        assert!(changed);
        assert_eq!(arr["command"], "C:/tools/mcp-shield.exe");
        let args = arr["args"].as_array().unwrap();
        assert_eq!(args[0], "exec");
        assert_eq!(args[3], "--");
        assert_eq!(args[4], "npx");
        assert_eq!(args[5], "-y");
        assert_eq!(args[6], "some-server");
        assert_eq!(arr["type"], "stdio", "extra fields must be preserved");
        assert_eq!(
            arr["env"]["API_KEY"],
            "mcp-shield://keychain/c0ffee42/arr/API_KEY"
        );
    }

    #[test]
    fn dry_run_does_not_touch_store() {
        let store = MemStore(std::sync::Mutex::new(Default::default()));
        let exe = Path::new("C:/tools/mcp-shield.exe");
        let mut entry = serde_json::json!({
            "command": "node",
            "args": ["server.js"],
            "env": { "API_KEY": "sk-abcdefghij0123456789ABCDEF" }
        });
        let mut accounts = Vec::new();
        let changed = shim_server_entry(
            "c0ffee42",
            "svc",
            &mut entry,
            exe,
            &store,
            true,
            &mut accounts,
        )
        .unwrap();
        assert!(changed);
        assert_eq!(accounts, vec!["c0ffee42:svc:API_KEY"]);
        assert!(store.get("c0ffee42:svc:API_KEY").is_err());
        // Placeholder still written in dry-run so the user can preview it.
        assert_eq!(
            entry["env"]["API_KEY"],
            "mcp-shield://keychain/c0ffee42/svc/API_KEY"
        );
    }
}
