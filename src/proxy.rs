//! The inline stdio JSON-RPC 2.0 interceptor (`mcp-shield exec`).
//!
//! Host (IDE agent) stdin  -> policy evaluation  -> child MCP server stdin
//! Host stdout            <- secret redaction   <- child MCP server stdout
//! Host stderr            <- non-blocking relay <- child MCP server stderr
//!
//! Environment hydration resolves `mcp-shield://keychain/...` placeholders
//! from the OS Keychain at the exact moment the child process is spawned, so
//! raw secrets never exist in the IDE config file or the LLM context window.

use std::io;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::audit::AuditLogger;
use crate::hitl::{self, HitlOutcome};
use crate::keychain::{self, SecretStore};
use crate::policy::{Action, PolicyEngine, SessionState};
use crate::redactor::{classify_secret, SecretScanner};
use crate::util::VAULT_PREFIX;

/// Safety cap for a single newline-delimited message (protects RAM; lines
/// larger than this are forwarded uninspected as opaque chunks).
const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

type SharedAudit = Arc<Mutex<AuditLogger>>;
type SharedState = Arc<Mutex<SessionState>>;

/// Entrypoint for `mcp-shield exec`. Returns the child exit code.
pub async fn run(
    server_name: String,
    policy_path: Option<PathBuf>,
    command: Vec<String>,
) -> Result<i32> {
    if command.is_empty() {
        anyhow::bail!("exec requires a command after `--`");
    }
    let policy = PolicyEngine::load_or_default(policy_path.as_deref())?;

    // Server pinning: when the signed policy lists allowed servers, anything
    // else in a wrapped config is refused outright (supply-chain control).
    if !policy.server_allowlist.is_empty() {
        let cmdline = command.join(" ");
        let allowed = policy
            .server_allowlist
            .iter()
            .any(|pat| match pat.split_once(':') {
                Some((name, prefix)) => server_name == name && cmdline.starts_with(prefix),
                None => server_name == pat.as_str(),
            });
        if !allowed {
            anyhow::bail!(
                "server pinning: '{}' (with this command line) is not in the policy server_allowlist",
                server_name
            );
        }
    }

    // -- Late-bound credential resolution --------------------------------------
    // Scan our own environment first: if any placeholder vars exist we must
    // open a secret store before spawning the child. Placeholders can also
    // appear directly in the wrapped command's argv (e.g. a postgres URL that
    // was extracted from `args` during `wrap`).
    let placeholders: Vec<(String, String)> = std::env::vars()
        .filter(|(_, v)| v.starts_with(VAULT_PREFIX))
        .collect();
    let arg_placeholders = command.iter().any(|a| a.starts_with(VAULT_PREFIX));
    let store: Option<Box<dyn SecretStore>> = if placeholders.is_empty() && !arg_placeholders {
        None
    } else {
        Some(keychain::open_store()?)
    };

    let mut dynamic_secrets: Vec<String> = Vec::new();
    let mut command = command;
    // Audit trail must never contain resolved secrets: capture the display
    // form (with placeholders) before hydration.
    let display_command = command.join(" ");
    // Fail closed: any placeholder that cannot be resolved aborts the spawn
    // — the server must never start with an unresolved secret in argv.
    let mut resolution_failures = 0usize;
    if arg_placeholders {
        for a in command.iter_mut() {
            if let Some(account) = keychain::placeholder_to_account(a) {
                match store.as_ref().unwrap().get(&account) {
                    Ok(secret) => {
                        dynamic_secrets.push(secret.clone());
                        *a = secret;
                    }
                    Err(e) => {
                        eprintln!("[mcp-shield] FATAL: cannot resolve {account}: {e}");
                        resolution_failures += 1;
                    }
                }
            }
        }
    }
    let mut cmd = tokio::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Env allowlist mode: the child receives only what the signed policy
    // permits (placeholder-resolved secrets always pass).
    let env_allow: Option<std::collections::HashSet<String>> =
        if policy.child_env_allowlist.is_empty() {
            None
        } else {
            // Critical: Command inherits the parent environment by default.
            // env_clear() first so the allowlist is a restriction, not a hint.
            cmd.env_clear();
            Some(policy.child_env_allowlist.iter().cloned().collect())
        };
    for (k, v) in std::env::vars() {
        if let Some(account) = keychain::placeholder_to_account(&v) {
            match store.as_ref().unwrap().get(&account) {
                Ok(s) => {
                    dynamic_secrets.push(s.clone());
                    cmd.env(k, s);
                }
                Err(e) => {
                    eprintln!("[mcp-shield] FATAL: cannot resolve {account}: {e}");
                    resolution_failures += 1;
                }
            }
        } else {
            if let Some(allow) = &env_allow {
                if !allow.contains(&k) {
                    continue;
                }
            }
            // Any plaintext secret already present in the parent environment is
            // added to the redaction dictionary so it can never leak back out.
            if classify_secret(&v).is_some() {
                dynamic_secrets.push(v.clone());
            }
            cmd.env(k, v);
        }
    }
    if resolution_failures > 0 {
        anyhow::bail!(
            "aborting: {resolution_failures} secret(s) could not be resolved from the secret store (fail-closed)"
        );
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn '{}'", command[0]))?;
    let child_stdin = child.stdin.take().context("child stdin not piped")?;
    let child_stdout = child.stdout.take().context("child stdout not piped")?;
    let child_stderr = child.stderr.take().context("child stderr not piped")?;

    // -- Audit session -----------------------------------------------------------
    let mut audit = AuditLogger::open_default()?;
    let session_id = uuid::Uuid::new_v4().to_string();
    let child_pid = child.id().unwrap_or(0);
    {
        let mut f = Map::new();
        f.insert("session_id".into(), session_id.clone().into());
        f.insert("server_name".into(), server_name.clone().into());
        f.insert("child_command".into(), display_command.into());
        f.insert("child_pid".into(), child_pid.into());
        f.insert("policy_signed".into(), policy.signed.into());
        f.insert(
            "child_env_mode".into(),
            if env_allow.is_some() {
                "allowlist"
            } else {
                "inherit"
            }
            .into(),
        );
        audit.log("session_start", f)?;
    }
    let audit: SharedAudit = Arc::new(Mutex::new(audit));
    let state: SharedState = Arc::new(Mutex::new(SessionState::default()));
    // tools/list request ids, tracked so the response path can pin the
    // advertised tool surface and scan descriptions for prompt injection.
    let tools_list_ids: Arc<Mutex<std::collections::HashSet<String>>> =
        Arc::new(Mutex::new(std::collections::HashSet::new()));

    // -- Non-blocking stderr relay (capped + redacted: secrets a child prints
    //    to stderr must not reach the IDE terminal) ------------------------------
    let redactor = Arc::new(SecretScanner::new(&dynamic_secrets));
    {
        let redactor = Arc::clone(&redactor);
        tokio::spawn(async move {
            const STDERR_CAP: usize = 1024 * 1024;
            let mut reader = tokio::io::BufReader::new(child_stderr);
            let mut err_out = tokio::io::stderr();
            let mut line = String::new();
            loop {
                line.clear();
                match read_line_capped(&mut reader, &mut line, STDERR_CAP).await {
                    Ok((0, _)) => break,
                    Ok((_, truncated)) => {
                        let (sanitized, _) = redactor.redact_line(&line);
                        let _ = err_out.write_all(sanitized.as_bytes()).await;
                        if truncated {
                            let _ = err_out.write_all(b"\n[mcp-shield: line truncated]\n").await;
                        } else if !sanitized.ends_with('\n') {
                            let _ = err_out.write_all(b"\n").await;
                        }
                        let _ = err_out.flush().await;
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // -- Heartbeat: daily-presence events for pilot retention metrics ------------
    {
        let audit = Arc::clone(&audit);
        let session_id = session_id.clone();
        let server_name = server_name.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30 * 60));
            ticker.tick().await; // first tick completes immediately; skip it
            loop {
                ticker.tick().await;
                let mut f = Map::new();
                f.insert("session_id".into(), session_id.clone().into());
                f.insert("server_name".into(), server_name.clone().into());
                if audit.lock().await.log("heartbeat", f).is_err() {
                    break;
                }
            }
        });
    }

    // -- Shared host stdout writer (request loop + response task serialize on it)
    let host_stdout = Arc::new(Mutex::new(tokio::io::stdout()));

    // -- Response path: child stdout -> redaction -> host stdout -----------------
    let tools_pin: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let response_task = {
        let host_stdout = Arc::clone(&host_stdout);
        let audit = Arc::clone(&audit);
        let session_id = session_id.clone();
        let tools_list_ids = Arc::clone(&tools_list_ids);
        let tools_pin = Arc::clone(&tools_pin);
        tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(child_stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match read_line_capped(&mut reader, &mut line, MAX_LINE_BYTES).await {
                    Ok((0, _)) => break, // EOF: child closed stdout
                    Ok((_, truncated)) => {
                        if truncated {
                            // Oversized response: still redact, restore framing.
                            let mut f = Map::new();
                            f.insert("session_id".into(), session_id.clone().into());
                            f.insert("direction".into(), "child_to_host".into());
                            let _ = audit.lock().await.log("oversized_frame", f);
                            if !line.ends_with('\n') {
                                line.push('\n');
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[mcp-shield] error reading child stdout: {e}");
                        break;
                    }
                }
                // tools/list responses: pin the advertised tool surface (rug-
                // pull defense) and scan descriptions for prompt injection.
                if let Ok(v) = serde_json::from_str::<Value>(line.trim()) {
                    if let Some(id) = v.get("id") {
                        let id_key = serde_json::to_string(id).unwrap_or_default();
                        let is_tools_list = tools_list_ids.lock().await.remove(&id_key);
                        if is_tools_list {
                            match process_tools_list(v, &tools_pin, &audit, &session_id).await {
                                Ok(Some(replacement)) => {
                                    line.clear();
                                    line.push_str(&replacement);
                                    line.push('\n');
                                }
                                Ok(None) => {}
                                Err(blocked) => {
                                    // Advertised tools changed mid-session:
                                    // refuse the listing instead of letting a
                                    // mutated tool surface reach the agent.
                                    line.clear();
                                    line.push_str(&blocked);
                                    if !line.ends_with('\n') {
                                        line.push('\n');
                                    }
                                }
                            }
                        }
                    }
                }
                let start = Instant::now();
                let (sanitized, kinds) = redactor.redact_line(&line);
                let latency = start.elapsed().as_micros() as u64;
                if !kinds.is_empty() {
                    let mut f = Map::new();
                    f.insert("session_id".into(), session_id.clone().into());
                    f.insert("direction".into(), "child_to_host".into());
                    f.insert("kinds".into(), kinds.into());
                    f.insert("latency_us".into(), latency.into());
                    let _ = audit.lock().await.log("redaction", f);
                }
                let mut out = host_stdout.lock().await;
                if out.write_all(sanitized.as_bytes()).await.is_err() {
                    break; // host gone
                }
                let _ = out.flush().await;
            }
        })
    };

    // -- Request path: host stdin -> policy -> child stdin ------------------------
    let mut host_stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut child_stdin = child_stdin;
    let mut line = String::new();
    loop {
        line.clear();
        match read_line_capped(&mut host_stdin, &mut line, MAX_LINE_BYTES).await {
            Ok((0, _)) => break, // EOF: IDE closed the session
            Ok((_, truncated)) => {
                if truncated {
                    // An oversized request frame is never forwarded: policy
                    // cannot evaluate a partial `tools/call`, so deny it.
                    let mut f = Map::new();
                    f.insert("session_id".into(), session_id.clone().into());
                    f.insert("direction".into(), "host_to_child".into());
                    f.insert("size_cap_bytes".into(), MAX_LINE_BYTES.into());
                    let _ = audit.lock().await.log("oversized_frame", f);
                    let err = jsonrpc_error(
                        &Value::Null,
                        -32600,
                        "Invalid Request: message exceeds the single-frame size cap and was not forwarded",
                    );
                    write_host_line(&host_stdout, &err).await;
                    continue;
                }
            }
            Err(e) => {
                eprintln!("[mcp-shield] error reading host stdin: {e}");
                break;
            }
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                // Never forward unparseable frames: MCP stdio is newline-
                // delimited JSON. Anything else (garbage, LSP-style
                // Content-Length framing, binary) is denied, not proxied.
                let reason = if trimmed.to_ascii_lowercase().starts_with("content-length") {
                    "Content-Length framing is not governed by this shim; send newline-delimited JSON-RPC"
                } else {
                    "not valid JSON-RPC; only newline-delimited JSON is governed"
                };
                deny_frame(&audit, &session_id, reason).await;
                let err = jsonrpc_error(&Value::Null, -32600, reason);
                write_host_line(&host_stdout, &err).await;
                continue;
            }
        };
        if msg.is_array() {
            // JSON-RPC batches: each element would need individual policy
            // evaluation and response correlation. Fail closed instead.
            deny_frame(&audit, &session_id, "JSON-RPC batch (array) denied").await;
            let err = jsonrpc_error(
                &Value::Null,
                -32600,
                "Invalid Request: JSON-RPC batches are not supported by the shim",
            );
            write_host_line(&host_stdout, &err).await;
            continue;
        }
        let method = msg
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        // Default-allow ONLY the MCP lifecycle; everything else is governed.
        let passthrough = method == "initialize"
            || method == "ping"
            || method.starts_with("notifications/")
            || method == "tools/list";
        if passthrough {
            if method == "tools/list" {
                if let Some(id) = msg.get("id") {
                    tools_list_ids
                        .lock()
                        .await
                        .insert(serde_json::to_string(id).unwrap_or_default());
                }
            }
            if child_stdin.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            let _ = child_stdin.flush().await;
            continue;
        }

        // tools/call and resources/read require a valid non-null request id.
        // Other governed methods may be notifications (no id): evaluate them,
        // but a denial silently drops them since there is nothing to answer.
        let is_call = method == "tools/call" || method == "resources/read";
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        if is_call && id.is_null() {
            let err = jsonrpc_error(
                &Value::Null,
                -32600,
                "Invalid Request: tools/call/resources.read requires a non-null id",
            );
            write_host_line(&host_stdout, &err).await;
            continue;
        }

        let start = Instant::now();
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let tool = if method == "tools/call" {
            params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        } else {
            // Governed non-call methods are evaluated under their own name.
            method.clone()
        };
        // resources/read carries its target in `params.uri` — merge it into
        // the evaluated arguments so path rules actually apply to it.
        let mut args = params.get("arguments").cloned().unwrap_or(Value::Null);
        if method == "resources/read" {
            if let Some(uri) = params.get("uri") {
                match args.as_object_mut() {
                    Some(obj) => {
                        obj.entry("uri".to_string()).or_insert_with(|| uri.clone());
                    }
                    _ => {
                        args = serde_json::json!({ "uri": uri });
                    }
                }
            }
        }
        if (method == "completion/complete" || method == "prompts/get") && args.is_null() {
            // These carry free-form arguments; evaluate the whole params object.
            args = params.clone();
        }

        let action = {
            let mut st = state.lock().await;
            policy.evaluate(&mut st, &method, &tool, &args)
        };
        let latency_us = start.elapsed().as_micros() as u64;

        {
            let mut f = Map::new();
            f.insert("session_id".into(), session_id.clone().into());
            f.insert("direction".into(), "host_to_child".into());
            f.insert("method".into(), method.clone().into());
            f.insert("tool".into(), tool.clone().into());
            match &action {
                Action::Allow => {
                    f.insert("action".into(), "allow".into());
                }
                Action::Block { violation, reason } => {
                    f.insert("action".into(), "block".into());
                    f.insert("violation".into(), violation.clone().into());
                    f.insert("detail".into(), reason.clone().into());
                }
                Action::Prompt { reason } => {
                    f.insert("action".into(), "prompt".into());
                    f.insert("detail".into(), reason.clone().into());
                }
            }
            f.insert("latency_us".into(), latency_us.into());
            // Spec field name: the per-message proxy processing time budget.
            f.insert("processing_time_us".into(), latency_us.into());
            let _ = audit.lock().await.log("request_decision", f);
        }

        match action {
            Action::Allow => {
                if child_stdin.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
                let _ = child_stdin.flush().await;
            }
            Action::Block { violation, reason } => {
                if is_call {
                    let resp = tool_error_response(&id, &violation, &reason);
                    write_host_line(&host_stdout, &resp).await;
                }
                // Notifications have no id: the denial is the drop itself.
            }
            Action::Prompt { reason } => {
                if !policy.hitl_enabled {
                    let resp = tool_error_response(
                        &id,
                        "REQUIRES_APPROVAL",
                        &format!("HITL disabled by policy; action denied: {reason}"),
                    );
                    write_host_line(&host_stdout, &resp).await;
                    continue;
                }
                let preview = serde_json::to_string(&args).unwrap_or_default();
                let outcome = hitl::ask(
                    &tool,
                    &preview,
                    Duration::from_secs(policy.hitl_timeout_secs),
                    policy.allow_headless_hitl_override,
                )
                .await;
                {
                    let mut f = Map::new();
                    f.insert("session_id".into(), session_id.clone().into());
                    f.insert("tool".into(), tool.clone().into());
                    f.insert(
                        "outcome".into(),
                        (match outcome {
                            HitlOutcome::Allow => "allow",
                            HitlOutcome::Deny => "deny",
                        })
                        .into(),
                    );
                    let _ = audit.lock().await.log("hitl", f);
                }
                match outcome {
                    HitlOutcome::Allow => {
                        if child_stdin.write_all(line.as_bytes()).await.is_err() {
                            break;
                        }
                        let _ = child_stdin.flush().await;
                    }
                    HitlOutcome::Deny => {
                        if is_call {
                            let resp = tool_error_response(&id, "HITL_DENIED", &reason);
                            write_host_line(&host_stdout, &resp).await;
                        }
                    }
                }
            }
        }
    }

    // -- Graceful shutdown -------------------------------------------------------
    drop(child_stdin);
    let exit_code = match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
        Ok(Ok(status)) => status.code().unwrap_or(0),
        _ => {
            let _ = child.kill().await;
            1
        }
    };
    response_task.abort();
    {
        let mut f = Map::new();
        f.insert("session_id".into(), session_id.into());
        f.insert("child_exit_code".into(), exit_code.into());
        let _ = audit.lock().await.log("session_end", f);
    }
    Ok(exit_code)
}

/// Read one newline-terminated line, capping total size so a misbehaving peer
/// can never exhaust RAM. Returns `(bytes_read, truncated)`: `truncated` is
/// true when the cap was hit before a newline — the buffer is then a partial
/// frame and MUST NOT be forwarded as if it were a complete message.
async fn read_line_capped<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut String,
    cap: usize,
) -> io::Result<(usize, bool)> {
    buf.clear();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok((buf.len(), false));
        }
        let nl = available.iter().position(|&b| b == b'\n');
        let take = match nl {
            Some(p) => p + 1,
            None => available.len(),
        };
        let remaining = cap.saturating_sub(buf.len());
        if remaining == 0 {
            return Ok((buf.len(), true));
        }
        let take = take.min(remaining);
        let had_newline = matches!(nl, Some(p) if p < take);
        let chunk = available[..take].to_vec();
        // Lossy decode keeps the proxy alive on pathological binary frames.
        buf.push_str(&String::from_utf8_lossy(&chunk));
        reader.consume(take);
        if had_newline || buf.len() >= cap {
            return Ok((buf.len(), !had_newline));
        }
    }
}

/// MCP tool error payload (isError: true) so the IDE agent handles the denial
/// gracefully without crashing the MCP session.
fn tool_error_response(id: &Value, violation: &str, reason: &str) -> String {
    let obj = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{
                "type": "text",
                "text": format!("[mcp-shield] BLOCKED ({violation}): {reason}")
            }],
            "isError": true
        }
    });
    serde_json::to_string(&obj).unwrap_or_else(|_| "{}\n".to_string())
}

fn jsonrpc_error(id: &Value, code: i64, message: &str) -> String {
    let obj = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    });
    serde_json::to_string(&obj).unwrap_or_else(|_| "{}\n".to_string())
}

/// Prompt-injection signatures in tool descriptions (CVE-class MCP tool
/// poisoning): instruct the model to bypass its operator.
fn poison_regexes() -> &'static [regex::Regex] {
    static RE: std::sync::OnceLock<Vec<regex::Regex>> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        [
            r"(?i)ignore (all |the |previous |above |your )?(instructions?|prompts?|directions?)",
            r"(?i)disregard .{0,24}(instructions?|prompts?|system prompt)",
            r"(?i)forget (everything|all|your instructions)",
            r"(?i)you must (call|use|run|invoke)",
            r"(?i)(new|updated|important|override) (system )?(instructions?|prompt)",
            r"(?i)do not (tell|inform|ask|warn) the (user|operator|human)",
            r"(?i)run (this|the following) (command|shell|code)",
            r"(?i)decode (this|the following) base64",
            r"(?i)your (system|initial) prompt",
        ]
        .iter()
        .map(|p| regex::Regex::new(p).expect("hardcoded poison regex must compile"))
        .collect()
    })
}

/// Pin the advertised tools and sanitize poisoned descriptions.
/// Returns Ok(Some(sanitized_line)) | Ok(None) | Err(blocked_response_line).
async fn process_tools_list(
    mut v: Value,
    tools_pin: &Arc<Mutex<Option<String>>>,
    audit: &SharedAudit,
    session_id: &str,
) -> Result<Option<String>, String> {
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    let tools = match v
        .pointer_mut("/result/tools")
        .and_then(serde_json::Value::as_array_mut)
    {
        Some(t) => t,
        None => return Ok(None),
    };
    let fingerprint = crate::audit::sha256_hex(&serde_json::to_string(tools).unwrap_or_default());
    let mut pin = tools_pin.lock().await;
    match pin.as_deref() {
        None => {
            *pin = Some(fingerprint);
        }
        Some(prev) if *prev == fingerprint => {}
        Some(_) => {
            let mut f = Map::new();
            f.insert("session_id".into(), session_id.into());
            f.insert(
                "detail".into(),
                "advertised tools changed mid-session".into(),
            );
            let _ = audit.lock().await.log("tools_list_mutation", f);
            return Err(serde_json::to_string(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "[mcp-shield] BLOCKED (TOOLS_LIST_MUTATION): the server changed its advertised tools mid-session"
                }
            }))
            .unwrap_or_default());
        }
    }
    // Description poisoning: mask instructive injections and audit them.
    let mut flagged = Vec::new();
    for tool in tools.iter_mut() {
        let name = tool
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(|s| s.to_string());
        let Some(desc_val) = tool.get_mut("description") else {
            continue;
        };
        let Some(desc) = desc_val.as_str().map(|s| s.to_string()) else {
            continue;
        };
        let mut clean = desc.clone();
        for re in poison_regexes() {
            clean = re
                .replace_all(&clean, "[mcp-shield: description flagged]")
                .into_owned();
        }
        if clean != desc {
            if let Some(name) = name {
                flagged.push(name);
            }
            *desc_val = Value::String(clean);
        }
    }
    if !flagged.is_empty() {
        let mut f = Map::new();
        f.insert("session_id".into(), session_id.into());
        f.insert("tools".into(), flagged.into());
        let _ = audit.lock().await.log("tool_poisoning_suspect", f);
        return Ok(Some(serde_json::to_string(&v).unwrap_or_default()));
    }
    Ok(None)
}

async fn deny_frame(audit: &SharedAudit, session_id: &str, reason: &str) {
    let mut f = Map::new();
    f.insert("session_id".into(), session_id.into());
    f.insert("reason".into(), reason.into());
    let _ = audit.lock().await.log("frame_denied", f);
}

async fn write_host_line(host_stdout: &Arc<Mutex<tokio::io::Stdout>>, line: &str) {
    let mut out = host_stdout.lock().await;
    if out.write_all(line.as_bytes()).await.is_err() {
        return;
    }
    if !line.ends_with('\n') {
        let _ = out.write_all(b"\n").await;
    }
    let _ = out.flush().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_error_response_is_valid_jsonrpc_with_is_error() {
        let s = tool_error_response(&serde_json::json!(7), "PATH_TRAVERSAL", "no");
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["result"]["isError"], true);
        assert!(v["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("PATH_TRAVERSAL"));
    }

    #[test]
    fn protocol_error_shape() {
        let s = jsonrpc_error(&Value::Null, -32600, "bad");
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["error"]["code"], -32600);
    }

    #[tokio::test]
    async fn capped_line_reader_handles_oversize() {
        let big = vec![b'a'; MAX_LINE_BYTES + 1000];
        let mut cursor = tokio::io::BufReader::new(std::io::Cursor::new(big));
        let mut buf = String::new();
        let (n, truncated) = read_line_capped(&mut cursor, &mut buf, MAX_LINE_BYTES)
            .await
            .unwrap();
        assert_eq!(n, MAX_LINE_BYTES);
        assert!(truncated, "cap hit before newline must be reported");
        // Small line works normally.
        let mut cursor = tokio::io::BufReader::new(std::io::Cursor::new(b"hi\nthere".to_vec()));
        let mut buf = String::new();
        let (n, truncated) = read_line_capped(&mut cursor, &mut buf, MAX_LINE_BYTES)
            .await
            .unwrap();
        assert_eq!(n, 3);
        assert!(!truncated);
        assert_eq!(buf, "hi\n");
        // Trailing partial line at EOF is not "truncated" (stream just ended).
        let mut cursor = tokio::io::BufReader::new(std::io::Cursor::new(b"tail".to_vec()));
        let mut buf = String::new();
        let (n, truncated) = read_line_capped(&mut cursor, &mut buf, MAX_LINE_BYTES)
            .await
            .unwrap();
        assert_eq!(n, 4);
        assert!(!truncated);
        assert_eq!(buf, "tail");
        assert_eq!(buf, "tail");
    }
}
