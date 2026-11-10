//! End-to-end integration tests: spawn the real `mcp-shield` binary, drive a
//! mock MCP server through `exec`, and assert the pilot success criteria.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

use serde_json::{json, Value};

/// Minimal custom policy template used by exec-level integration tests.
const MINIMAL_POLICY: &str = r#"
version = 1

[block]
paths = []
sql = []
shell = []
env_dump = []

[prompt]
sql = []
shell = []

[taint]
sources = []
escalate_tools = []
escalation = "Prompt"

[settings]
hitl_enabled = true
hitl_timeout_secs = 30
sql_tools = '(?i)sql'
shell_tools = '(?i)shell'
delete_requires_where = true
allow_headless_hitl_override = false
__ALLOWLIST__
"#;

fn exe() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_mcp-shield"))
}

fn temp_home(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("mcp-shield-it-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Spawn `mcp-shield exec -- <self> mock-server` and drive JSON-RPC over stdio.
struct ShimSession {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<String>,
    next_id: u64,
    home: PathBuf,
}

impl ShimSession {
    fn start(name: &str, hitl: &str) -> Self {
        Self::start_with_home(temp_home(name), hitl)
    }

    fn start_with_home(home: PathBuf, hitl: &str) -> Self {
        let mut child = Command::new(exe())
            .args(["exec", "--server-name", "itest", "--"])
            .arg(exe())
            .arg("mock-server")
            .env("MCP_SHIELD_HOME", &home)
            .env("MCP_SHIELD_HITL", hitl)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn shim");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = channel::<String>();
        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if tx.send(line.clone()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        ShimSession {
            child,
            stdin,
            rx,
            next_id: 0,
            home,
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.send(&msg);
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let line = self
                .rx
                .recv_timeout(remaining)
                .unwrap_or_else(|e| panic!("timeout waiting for response to {method}: {e}"));
            let v: Value = serde_json::from_str(line.trim()).expect("valid JSON line");
            if v.get("id").and_then(Value::as_u64) == Some(id) {
                return v;
            }
        }
    }

    fn notify(&mut self, method: &str, params: Value) {
        let msg = json!({"jsonrpc": "2.0", "method": method, "params": params});
        self.send(&msg);
    }

    fn send(&mut self, msg: &Value) {
        let mut s = serde_json::to_string(msg).unwrap();
        s.push('\n');
        self.stdin.write_all(s.as_bytes()).unwrap();
        self.stdin.flush().unwrap();
    }

    fn finish(mut self) {
        drop(self.stdin);
        let _ = self.child.wait();
    }
}

fn tool_call(name: &str, args: Value) -> Value {
    json!({"name": name, "arguments": args})
}

fn is_tool_error(resp: &Value) -> bool {
    resp.pointer("/result/isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn text(resp: &Value) -> String {
    resp.pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

#[test]
fn exec_intercepts_blocks_redacts_and_audits() {
    let mut s = ShimSession::start("proxy", "auto-deny");

    // Handshake passthrough.
    let init = s.request(
        "initialize",
        json!({"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "it", "version": "0"}}),
    );
    assert_eq!(
        init.pointer("/result/serverInfo/name")
            .and_then(Value::as_str),
        Some(mcp_shield::mock_server::MOCK_SERVER_NAME)
    );
    s.notify("notifications/initialized", json!({}));
    let ping = s.request("ping", json!({}));
    assert!(ping.get("error").is_none(), "ping must succeed: {ping}");
    let tools = s.request("tools/list", json!({}));
    assert!(
        tools.pointer("/result/tools").is_some(),
        "tools/list must pass through"
    );

    // Safe call allowed end-to-end.
    let echo = s.request("tools/call", tool_call("echo", json!({"text": "hello"})));
    assert!(!is_tool_error(&echo), "echo must be allowed: {echo}");
    assert!(text(&echo).contains("hello"));

    // Red-team suite — every one of these must be blocked before the child sees it.
    let blocked_cases = [
        ("read_file", json!({"path": "~/.ssh/id_rsa"})),
        ("read_file", json!({"path": "file:///etc/%73hadow"})),
        ("run_sql", json!({"query": "DROP TABLE users;"})),
        ("run_sql", json!({"query": "DELETE FROM users;"})),
        ("run_sql", json!({"query": "DELETE FROM users WHERE 1=1"})),
        ("run_shell", json!({"cmd": "rm -rf /"})),
        ("run_shell", json!({"cmd": "bash -c \"rm -rf /\""})),
        ("run_shell", json!({"cmd": "rm --recursive --force /data"})),
        (
            "run_shell",
            json!({"cmd": "psql -c \"DROP TABLE users\" prod"}),
        ),
        ("run_shell", json!({"cmd": "printenv"})),
    ];
    for (tool, args) in blocked_cases {
        let resp = s.request("tools/call", tool_call(tool, args.clone()));
        assert!(
            is_tool_error(&resp),
            "{tool} {args} must be BLOCKED: {resp}"
        );
        assert!(
            text(&resp).contains("[mcp-shield]"),
            "denial must be marked: {resp}"
        );
    }

    // resources/read must inspect params.uri.
    let r = s.request("resources/read", json!({"uri": "file://~/.ssh/id_rsa"}));
    assert!(is_tool_error(&r), "resources/read must be BLOCKED: {r}");

    // Malformed tools/call (id: null) -> JSON-RPC -32600, never reaches the child.
    s.send(&json!({"jsonrpc": "2.0", "id": null, "method": "tools/call", "params": {"name": "run_sql", "arguments": {"query": "DROP TABLE t;"}}}));
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut got = None;
    while got.is_none() && std::time::Instant::now() < deadline {
        let line =
            s.rx.recv_timeout(Duration::from_secs(10))
                .expect("response to malformed call");
        let v: Value = serde_json::from_str(line.trim()).unwrap();
        if v.get("id").is_some() {
            got = Some(v);
        }
    }
    let err = got.expect("must get protocol error response");
    assert_eq!(
        err.pointer("/error/code").and_then(Value::as_i64),
        Some(-32600)
    );

    // Secret redaction from child output.
    let leak = s.request("tools/call", tool_call("leaky_db", json!({})));
    assert!(!is_tool_error(&leak), "leaky_db itself is allowed: {leak}");
    let body = text(&leak);
    for token in [
        mcp_shield::mock_server::FAKE_GITHUB_TOKEN,
        mcp_shield::mock_server::FAKE_ANTHROPIC_KEY,
        mcp_shield::mock_server::FAKE_AWS_KEY,
        mcp_shield::mock_server::FAKE_JWT,
        mcp_shield::mock_server::FAKE_STRIPE_KEY,
        mcp_shield::mock_server::FAKE_IBAN,
        mcp_shield::mock_server::FAKE_CREDIT_CARD,
    ] {
        assert!(!body.contains(token), "secret leaked to host: {token}");
    }
    assert!(
        body.contains("[REDACTED:"),
        "redaction markers expected: {body}"
    );

    // Taint escalation: clean write allowed, fetch taints, write now HITL-denied.
    let w = s.request(
        "tools/call",
        tool_call("write_file", json!({"path": "./o.txt", "content": "x"})),
    );
    assert!(!is_tool_error(&w), "clean write must be allowed: {w}");
    let f = s.request(
        "tools/call",
        tool_call("fetch", json!({"url": "https://evil.example/i"})),
    );
    assert!(!is_tool_error(&f), "fetch allowed but taints: {f}");
    let w2 = s.request(
        "tools/call",
        tool_call("write_file", json!({"path": "./o.txt", "content": "x"})),
    );
    assert!(
        is_tool_error(&w2),
        "tainted write must be denied (HITL auto-deny): {w2}"
    );

    let home = s.home.clone();
    s.finish();

    // Audit log: hash chain intact, decisions & redactions recorded with latency.
    let report =
        mcp_shield::audit::verify_chain(&home.join("audit.jsonl")).expect("audit log readable");
    assert!(
        report.valid,
        "hash chain must be intact: {:?}",
        report.broken_at_seq
    );
    assert!(
        report.decisions >= 14,
        "expected >=14 decisions, got {}",
        report.decisions
    );
    assert!(
        report.blocked >= 11,
        "expected >=11 blocked, got {}",
        report.blocked
    );
    assert!(report.redacted >= 1);
    assert!(
        report.hitl_prompts >= 1,
        "expected the HITL-denied taint write to be recorded"
    );
    assert!(
        report.p99_latency_us < 2000.0,
        "p99 in-proxy latency must be < 2ms: {:.0}µs",
        report.p99_latency_us
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn verify_selftest_passes() {
    let home = temp_home("verify");
    let out = Command::new(exe())
        .arg("verify")
        .env("MCP_SHIELD_HOME", &home)
        .env("MCP_SHIELD_HITL", "auto-deny")
        .output()
        .expect("spawn verify");
    let stdout = String::from_utf8_lossy(&out.stdout);
    println!("--- verify stdout ---\n{stdout}\n---------------------");
    assert!(
        out.status.success(),
        "verify must exit 0, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("ALL CHECKS PASSED"));
    let _ = std::fs::remove_dir_all(&home);
}

/// Full secret-zeroization cycle against an isolated fake HOME:
/// audit flags CRITICAL -> wrap moves secrets -> audit is clean -> unwrap restores.
#[test]
fn wrap_unwrap_cycle_eliminates_plaintext_secrets() {
    // Uses MCP_SHIELD_CONFIG_HOME so the real workstation configs are never touched.
    let home = temp_home("wraphome");
    let cursor_dir = home.join(".cursor");
    std::fs::create_dir_all(&cursor_dir).unwrap();
    let kimi_dir = home.join(".kimi-code");
    std::fs::create_dir_all(&kimi_dir).unwrap();
    #[cfg(target_os = "windows")]
    let vscode_user = home.join("AppData/Roaming/Code/User");
    #[cfg(target_os = "macos")]
    let vscode_user = home.join("Library/Application Support/Code/User");
    #[cfg(all(unix, not(target_os = "macos")))]
    let vscode_user = home.join(".config/Code/User");
    std::fs::create_dir_all(&vscode_user).unwrap();
    let muse_dir = home.join(".config/muse");
    std::fs::create_dir_all(&muse_dir).unwrap();
    let secret = "ghp_abcdefghij0123456789abcdefghij0123456789";
    let conn_secret = "postgresql://appuser:s3kret-pass@db.internal:5432/app";
    let config_path = cursor_dir.join("mcp.json");
    let original = json!({
        "mcpServers": {
            "github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github", "postgresql://appuser:s3kret-pass@db.internal:5432/app"],
                "env": {"GITHUB_TOKEN": secret}
            },
            "filesystem": {
                "command": "node",
                "args": ["/srv/mcp-fs.js"]
            }
        }
    });
    std::fs::write(
        &config_path,
        serde_json::to_string_pretty(&original).unwrap(),
    )
    .unwrap();
    // Kimi Code user-level config (~/.kimi-code/mcp.json).
    let kimi_path = kimi_dir.join("mcp.json");
    std::fs::write(
        &kimi_path,
        serde_json::to_string_pretty(&json!({
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": "ghp_kimi0123456789abcdef0123456789abcdef0123"}
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    // VS Code user-level config (…/Code/User/mcp.json).
    let vscode_path = vscode_user.join("mcp.json");
    std::fs::write(
        &vscode_path,
        serde_json::to_string_pretty(&json!({
            "mcpServers": {
                "postgres": {
                    "command": "npx",
                    "args": ["-y", "mcp-server-postgres"],
                    "env": {"DATABASE_URL": "postgresql://svc:vscode-secret@db:5432/app"}
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    // Meta Muse Code settings (~/.config/muse/settings.json, mcpServers block
    // alongside "schema_version" which must be preserved).
    let muse_path = muse_dir.join("settings.json");
    std::fs::write(
        &muse_path,
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": "ghp_muse0123456789abcdef0123456789abcdef0123"}
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();

    // Namespaced placeholder expectations: accounts are <config_id>:<server>:<KEY>.
    let cid_cursor = mcp_shield::config::config_id(&config_path);
    let cid_kimi = mcp_shield::config::config_id(&kimi_path);
    let cid_vscode = mcp_shield::config::config_id(&vscode_path);
    let cid_muse = mcp_shield::config::config_id(&muse_path);

    let mut cmd = Command::new(exe());
    cmd.arg("audit")
        .env("MCP_SHIELD_HOME", home.join("shield"))
        .env("MCP_SHIELD_VAULT_PASSWORD", "pw")
        .env("MCP_SHIELD_CONFIG_HOME", &home);
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("GRADE: CRITICAL"),
        "pre-wrap audit must be CRITICAL:\n{stdout}"
    );
    assert!(stdout.contains(secret.len().to_string().as_str()) || stdout.contains('…'));

    // wrap --target all (cursor + kimi-code + vscode fixtures)
    let mut cmd = Command::new(exe());
    cmd.args(["wrap", "--target", "all"])
        .env("MCP_SHIELD_HOME", home.join("shield"))
        .env("MCP_SHIELD_VAULT_PASSWORD", "pw")
        .env("MCP_SHIELD_CONFIG_HOME", &home);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "wrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let wrapped: Value = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    let gh = &wrapped["mcpServers"]["github"];
    assert_eq!(
        gh["env"]["GITHUB_TOKEN"],
        format!("mcp-shield://keychain/{cid_cursor}/github/GITHUB_TOKEN"),
        "plaintext must be replaced by placeholder: {wrapped}"
    );
    assert_eq!(
        gh["args"][7],
        format!("mcp-shield://keychain/{cid_cursor}/github/ARG2"),
        "credential-bearing arg must be replaced by placeholder: {wrapped}"
    );
    assert!(!serde_json::to_string(&wrapped)
        .unwrap()
        .contains(conn_secret));
    assert!(gh["command"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("mcp-shield"));
    assert_eq!(gh["args"][0], "exec");
    assert_eq!(gh["args"][3], "--");
    assert_eq!(gh["args"][4], "npx");
    // Every server is governed (shimmed), with or without secrets.
    let fs = &wrapped["mcpServers"]["filesystem"];
    assert!(fs["command"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("mcp-shield"));
    assert_eq!(fs["args"][0], "exec");
    assert_eq!(fs["args"][3], "--");
    assert_eq!(fs["args"][4], "node");
    assert_eq!(fs["args"][5], "/srv/mcp-fs.js");
    // Encrypted backup created under the state dir; `unwrap` must delete it.
    let backups_dir = home.join("shield").join("backups").join(cid_cursor.clone());
    let backup_path = std::fs::read_dir(&backups_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.to_string_lossy().contains(".bak."))
        .expect("encrypted backup must exist under the state dir");
    let backup_bytes = std::fs::read(&backup_path).unwrap();
    let backup_text = String::from_utf8_lossy(&backup_bytes);
    assert!(
        !backup_text.contains(conn_secret) && !backup_text.contains(secret),
        "backup must be encrypted at rest (no plaintext secrets)"
    );

    // Kimi Code and VS Code configs were governed too.
    let kimi_wrapped: Value = serde_json::from_slice(&std::fs::read(&kimi_path).unwrap()).unwrap();
    assert_eq!(
        kimi_wrapped["mcpServers"]["github"]["env"]["GITHUB_TOKEN"],
        format!("mcp-shield://keychain/{cid_kimi}/github/GITHUB_TOKEN"),
        "kimi-code config must be governed: {kimi_wrapped}"
    );
    assert!(kimi_wrapped["mcpServers"]["github"]["command"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("mcp-shield"));
    let vscode_wrapped: Value =
        serde_json::from_slice(&std::fs::read(&vscode_path).unwrap()).unwrap();
    assert_eq!(
        vscode_wrapped["mcpServers"]["postgres"]["env"]["DATABASE_URL"],
        format!("mcp-shield://keychain/{cid_vscode}/postgres/DATABASE_URL"),
        "vscode config must be governed: {vscode_wrapped}"
    );
    // Muse Code: mcpServers entry governed, schema_version preserved.
    let muse_wrapped: Value = serde_json::from_slice(&std::fs::read(&muse_path).unwrap()).unwrap();
    assert_eq!(
        muse_wrapped["schema_version"], 1,
        "muse schema_version must be preserved: {muse_wrapped}"
    );
    assert_eq!(
        muse_wrapped["mcpServers"]["github"]["env"]["GITHUB_TOKEN"],
        format!("mcp-shield://keychain/{cid_muse}/github/GITHUB_TOKEN"),
        "muse config must be governed: {muse_wrapped}"
    );
    // Same server name in two configs must NOT share one Keychain account.
    assert_ne!(
        gh["env"]["GITHUB_TOKEN"], kimi_wrapped["mcpServers"]["github"]["env"]["GITHUB_TOKEN"],
        "identical server names across configs must resolve to distinct accounts"
    );
    assert!(muse_wrapped["mcpServers"]["github"]["command"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("mcp-shield"));

    // post-wrap audit: no plaintext secrets remain.
    let mut cmd = Command::new(exe());
    cmd.arg("audit")
        .env("MCP_SHIELD_HOME", home.join("shield"))
        .env("MCP_SHIELD_VAULT_PASSWORD", "pw")
        .env("MCP_SHIELD_CONFIG_HOME", &home);
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("GRADE: PASS"),
        "post-wrap audit must be PASS (100% elimination):\n{stdout}"
    );
    assert!(!stdout.contains(secret));
    assert!(!stdout.contains("s3kret-pass"));

    // unwrap restores the original config.
    let mut cmd = Command::new(exe());
    cmd.arg("unwrap")
        .env("MCP_SHIELD_HOME", home.join("shield"))
        .env("MCP_SHIELD_VAULT_PASSWORD", "pw");
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "unwrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let restored: Value = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    assert_eq!(
        restored["mcpServers"]["github"]["env"]["GITHUB_TOKEN"],
        secret
    );
    let kimi_restored: Value = serde_json::from_slice(&std::fs::read(&kimi_path).unwrap()).unwrap();
    assert_eq!(
        kimi_restored["mcpServers"]["github"]["env"]["GITHUB_TOKEN"],
        "ghp_kimi0123456789abcdef0123456789abcdef0123",
        "kimi-code config must be restored: {kimi_restored}"
    );
    let vscode_restored: Value =
        serde_json::from_slice(&std::fs::read(&vscode_path).unwrap()).unwrap();
    assert_eq!(
        vscode_restored["mcpServers"]["postgres"]["env"]["DATABASE_URL"],
        "postgresql://svc:vscode-secret@db:5432/app",
        "vscode config must be restored: {vscode_restored}"
    );
    assert!(
        !backups_dir.exists() || std::fs::read_dir(&backups_dir).unwrap().next().is_none(),
        "unwrap must delete the encrypted backups"
    );
    let muse_restored: Value = serde_json::from_slice(&std::fs::read(&muse_path).unwrap()).unwrap();
    assert_eq!(muse_restored["schema_version"], 1);
    assert_eq!(
        muse_restored["mcpServers"]["github"]["env"]["GITHUB_TOKEN"],
        "ghp_muse0123456789abcdef0123456789abcdef0123",
        "muse config must be restored: {muse_restored}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn audit_handles_missing_configs_gracefully() {
    let home = temp_home("empty-audit");
    let out = Command::new(exe())
        .arg("audit")
        .env("MCP_SHIELD_HOME", &home)
        .output()
        .unwrap();
    assert!(out.status.success());
    let _ = std::fs::remove_dir_all(&home);
}

/// A tampered (re-signed-invalid) policy must fail closed: exec refuses to start.
#[test]
fn policy_tamper_fails_closed() {
    // First exec creates + signs the policy in the session's home.
    let mut s = ShimSession::start("tamper-seed", "auto-deny");
    let home = s.home.clone();
    let init = s.request(
        "initialize",
        json!({"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
    );
    assert!(
        init.get("error").is_none(),
        "first session must work: {init}"
    );
    s.finish();

    // Tamper with the signed policy.
    let policy = home.join("policy.toml");
    let mut raw = std::fs::read_to_string(&policy).unwrap();
    raw.push_str(
        "
# attacker: hitl_enabled = false
",
    );
    std::fs::write(&policy, raw).unwrap();

    // Next exec must refuse to start.
    let out = Command::new(exe())
        .args(["exec", "--server-name", "x", "--"])
        .arg(exe())
        .arg("mock-server")
        .env("MCP_SHIELD_HOME", &home)
        .env("MCP_SHIELD_HITL", "auto-deny")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "exec must fail closed on a tampered policy"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("SIGNATURE INVALID") || stderr.contains("signature"),
        "error must name the signature problem: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// Server pinning: a signed policy with a server_allowlist refuses unknown servers.
#[test]
fn server_pinning_fails_closed() {
    let home = temp_home("pinning");
    // Non-default path: the default-path policy would legitimately auto-sign.
    let policy_path = home.join("attacker-supplied.toml");
    std::fs::write(
        &policy_path,
        MINIMAL_POLICY.replace(
            "__ALLOWLIST__",
            "server_allowlist = [\"some-other-server\"]",
        ),
    )
    .unwrap();

    // An unsigned custom --policy is refused outright (no auto-sign).
    let out = Command::new(exe())
        .args(["exec", "--server-name", "not-allowed", "--policy"])
        .arg(&policy_path)
        .arg("--")
        .arg(exe())
        .arg("mock-server")
        .env("MCP_SHIELD_HOME", &home)
        .env("MCP_SHIELD_HITL", "auto-deny")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "unsigned custom policy must be refused"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to auto-sign") || stderr.contains("not signed"),
        "error must name the unsigned policy: {stderr}"
    );

    // The admin reviews and signs it explicitly.
    let out = Command::new(exe())
        .args(["resign-policy", "--policy"])
        .arg(&policy_path)
        .env("MCP_SHIELD_HOME", &home)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resign-policy --policy must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = Command::new(exe())
        .args(["exec", "--server-name", "not-allowed", "--policy"])
        .arg(&policy_path)
        .arg("--")
        .arg(exe())
        .arg("mock-server")
        .env("MCP_SHIELD_HOME", &home)
        .env("MCP_SHIELD_HITL", "auto-deny")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "pinning must refuse unlisted servers"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("server pinning"),
        "error must name server pinning: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// env_clear + allowlist: the child sees only what the signed policy allows.
#[test]
fn child_env_allowlist_restricts_child() {
    let home = temp_home("envallow");
    let policy_path = home.join("custom-policy.toml");
    std::fs::write(
        &policy_path,
        MINIMAL_POLICY.replace(
            "__ALLOWLIST__",
            "child_env_allowlist = [\"PATH\", \"SystemRoot\", \"WINDIR\", \"HOME\"]",
        ),
    )
    .unwrap();
    let out = Command::new(exe())
        .args(["resign-policy", "--policy"])
        .arg(&policy_path)
        .env("MCP_SHIELD_HOME", &home)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resign-policy --policy must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Spawn the shim directly with an extra secret in the environment.
    let mut child = Command::new(exe())
        .args(["exec", "--server-name", "envtest", "--policy"])
        .arg(&policy_path)
        .arg("--")
        .arg(exe())
        .arg("mock-server")
        .env("MCP_SHIELD_HOME", &home)
        .env("MCP_SHIELD_HITL", "auto-deny")
        .env("SENTINEL_SECRET", "top-secret-value")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = channel::<String>();
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(line.clone()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut next_id = 0u64;
    let mut request = |method: &str, params: Value, rx: &Receiver<String>| -> Value {
        next_id += 1;
        let msg = json!({"jsonrpc": "2.0", "id": next_id, "method": method, "params": params});
        let mut s = serde_json::to_string(&msg).unwrap();
        s.push('\n');
        stdin.write_all(s.as_bytes()).unwrap();
        stdin.flush().unwrap();
        loop {
            let line = rx.recv_timeout(Duration::from_secs(15)).unwrap();
            let v: Value = serde_json::from_str(line.trim()).unwrap();
            if v.get("id").and_then(Value::as_u64) == Some(next_id) {
                return v;
            }
        }
    };
    let init = request(
        "initialize",
        json!({"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        &rx,
    );
    assert!(init.get("error").is_none(), "session must start: {init}");
    let probe = request(
        "tools/call",
        json!({"name": "env_probe", "arguments": {"name": "SENTINEL_SECRET"}}),
        &rx,
    );
    let body = probe
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        body.contains("absent"),
        "allowlisted child must NOT see the parent secret: {body}"
    );
    let probe2 = request(
        "tools/call",
        json!({"name": "env_probe", "arguments": {"name": "PATH"}}),
        &rx,
    );
    let body2 = probe2
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        body2.contains("present"),
        "allowlisted var must reach the child: {body2}"
    );
    drop(stdin);
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&home);
}

/// Signature deletion is only benign when the policy is unchanged; a modified
/// policy with a missing signature refuses to start, and `resign-policy`
/// (admin review) recovers it.
#[test]
fn policy_sig_deletion_fails_closed_when_modified() {
    // Seed: first session signs + pins the policy.
    let mut s = ShimSession::start("sigseed", "auto-deny");
    let home = s.home.clone();
    let init = s.request(
        "initialize",
        json!({"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
    );
    assert!(
        init.get("error").is_none(),
        "seed session must work: {init}"
    );
    s.finish();

    let policy = home.join("policy.toml");
    let sig = home.join("policy.toml.sig");
    assert!(sig.exists(), "policy must be signed after first boot");

    // Case 1: benign - delete only the .sig, policy unchanged -> restored.
    std::fs::remove_file(&sig).unwrap();
    let mut s2 = ShimSession::start_with_home(home.clone(), "auto-deny");
    let init2 = s2.request(
        "initialize",
        json!({"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
    );
    assert!(
        init2.get("error").is_none(),
        "unchanged policy must recover its signature: {init2}"
    );
    s2.finish();
    assert!(
        sig.exists(),
        "signature must be restored for unchanged policy"
    );

    // Case 2: malicious - modify the policy AND delete the .sig -> refuse.
    let mut raw = std::fs::read_to_string(&policy).unwrap();
    raw.push_str("\n# attacker: hitl_enabled = false\n");
    std::fs::write(&policy, raw).unwrap();
    std::fs::remove_file(&sig).unwrap();
    let out = Command::new(exe())
        .args(["exec", "--server-name", "x", "--"])
        .arg(exe())
        .arg("mock-server")
        .env("MCP_SHIELD_HOME", &home)
        .env("MCP_SHIELD_HITL", "auto-deny")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "modified policy without signature must fail closed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to re-sign"),
        "error must name the re-sign refusal: {stderr}"
    );

    // Recovery: the admin reviews and re-signs explicitly.
    let out = Command::new(exe())
        .arg("resign-policy")
        .env("MCP_SHIELD_HOME", &home)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "resign-policy must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut s3 = ShimSession::start_with_home(home.clone(), "auto-deny");
    let init3 = s3.request(
        "initialize",
        json!({"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
    );
    assert!(
        init3.get("error").is_none(),
        "session must work after admin re-sign: {init3}"
    );
    s3.finish();
    let _ = std::fs::remove_dir_all(&home);
}
