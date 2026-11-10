//! Human-in-the-Loop approval: native OS confirmation dialogs for risky
//! (non-destructive) tool calls.
//!
//! - macOS: `osascript` modal dialog (defaults to Deny, 30s give-up); the
//!   message is passed as an *argument* (`argv`), never interpolated into the
//!   script — tool arguments cannot alter the dialog program.
//! - Windows: PowerShell WPF MessageBox; the message arrives over **stdin**
//!   and is never embedded in the script text.
//! - Linux: `zenity --question` (exit code = decision; message is a data arg).
//! - Headless/CI: `MCP_SHIELD_HITL=auto-deny` always honored;
//!   `auto-allow` is honored ONLY when the signed policy explicitly allows it.
//!
//! Fail-closed: any dialog error, timeout, or missing helper defaults to Deny.

use std::time::Duration;

/// Outcome of a HITL prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitlOutcome {
    Allow,
    Deny,
}

/// Read the HITL mode from the environment.
pub fn hitl_mode() -> String {
    std::env::var("MCP_SHIELD_HITL")
        .unwrap_or_else(|_| "interactive".to_string())
        .to_ascii_lowercase()
}

/// Ask the user to approve a risky tool call.
///
/// `allow_auto_allow` comes from the signed policy: `MCP_SHIELD_HITL=auto-allow`
/// is ignored unless the policy explicitly permits it — an env var must not be
/// a kill switch for human approval. `auto-deny` is always honored.
pub async fn ask(
    tool: &str,
    args_preview: &str,
    timeout: Duration,
    allow_auto_allow: bool,
) -> HitlOutcome {
    match hitl_mode().as_str() {
        "auto-allow" | "allow" | "always-allow" if allow_auto_allow => {
            return HitlOutcome::Allow;
        }
        "auto-deny" | "deny" | "always-deny" => return HitlOutcome::Deny,
        _ => {}
    }
    interactive_ask(tool, args_preview, timeout).await
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max).collect();
        format!("{t}…")
    }
}

async fn interactive_ask(tool: &str, args_preview: &str, timeout: Duration) -> HitlOutcome {
    let args_preview = truncate(args_preview, 300);
    let message = format!(
        "mcp-shield approval required\n\nTool: {tool}\nArguments: {args_preview}\n\nAllow this action?"
    );

    #[cfg(target_os = "macos")]
    let cmd_result = run_dialog(
        "osascript",
        &[
            "-e".to_string(),
            format!(
                "on run argv\nset m to item 1 of argv\ndisplay dialog m buttons {{\"Deny\", \"Allow\"}} default button \"Deny\" cancel button \"Deny\" with icon caution giving up after {}\nend run",
                timeout.as_secs()
            ),
            "--".to_string(),
            message.clone(),
        ],
        None,
        timeout,
        |out, _status| out.contains("button returned:Allow") || out.contains("Allow"),
    )
    .await;

    #[cfg(target_os = "windows")]
    let cmd_result = run_dialog(
        "powershell.exe",
        &[
            "-NoProfile".to_string(),
            "-STA".to_string(),
            "-Command".to_string(),
            "Add-Type -AssemblyName PresentationFramework; \
             $msg = [Console]::In.ReadToEnd(); \
             $r = [System.Windows.MessageBox]::Show($msg, 'mcp-shield approval', 'YesNo', 'Warning', 'Button2', 'ServiceNotification'); \
             if ($r -eq 'Yes') { 'ALLOW' } else { 'DENY' }"
                .to_string(),
        ],
        Some(&message),
        timeout,
        |out, _status| out.contains("ALLOW"),
    )
    .await;

    #[cfg(target_os = "linux")]
    let cmd_result = run_dialog(
        "zenity",
        &[
            "--question".to_string(),
            "--title=mcp-shield approval".to_string(),
            format!("--text={message}"),
            "--ok-label=Allow".to_string(),
            "--cancel-label=Deny".to_string(),
        ],
        None,
        timeout,
        // zenity signals approval by EXIT CODE 0 and prints nothing.
        |_out, status| status.success(),
    )
    .await;

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    let cmd_result = {
        eprintln!(
            "[mcp-shield] HITL: no native dialog support on this platform; denying (fail-closed)"
        );
        HitlOutcome::Deny
    };

    cmd_result
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn run_dialog(
    program: &str,
    args: &[String],
    stdin_data: Option<&str>,
    timeout: Duration,
    is_allow: impl Fn(&str, &std::process::ExitStatus) -> bool,
) -> HitlOutcome {
    let spawn = tokio::process::Command::new(program)
        .args(args)
        .stdin(if stdin_data.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();
    let mut child = match spawn {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "[mcp-shield] HITL: cannot spawn '{program}' ({e}); denying (fail-closed). \
                 Set MCP_SHIELD_HITL=auto-allow|auto-deny for headless operation."
            );
            return HitlOutcome::Deny;
        }
    };
    // The dialog text is untrusted tool output: it travels as DATA (stdin or
    // argv), never interpolated into the dialog program itself.
    if let Some(data) = stdin_data {
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(data.as_bytes()).await;
            let _ = stdin.flush().await;
        }
    }
    // Read stdout on a separate task so a chatty child can never deadlock the wait.
    let stdout_pipe = child.stdout.take();
    let read_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stdout_pipe {
            use tokio::io::AsyncReadExt;
            let _ = pipe.read_to_end(&mut buf).await;
        }
        buf
    });
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => {
            let output = read_task.await.unwrap_or_default();
            let stdout = String::from_utf8_lossy(&output);
            if is_allow(&stdout, &status) {
                HitlOutcome::Allow
            } else {
                HitlOutcome::Deny
            }
        }
        Ok(Err(e)) => {
            read_task.abort();
            eprintln!("[mcp-shield] HITL dialog error: {e}; denying (fail-closed)");
            HitlOutcome::Deny
        }
        Err(_) => {
            // Timeout: kill the dialog and deny.
            let _ = child.kill().await;
            read_task.abort();
            eprintln!(
                "[mcp-shield] HITL dialog timed out after {}s; denying",
                timeout.as_secs()
            );
            HitlOutcome::Deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn auto_modes() {
        std::env::set_var("MCP_SHIELD_HITL", "auto-allow");
        // Without policy consent, auto-allow must NOT grant approval.
        assert_eq!(
            ask("write_file", "{}", Duration::from_secs(1), false).await,
            HitlOutcome::Deny
        );
        // With policy consent it may.
        assert_eq!(
            ask("write_file", "{}", Duration::from_secs(1), true).await,
            HitlOutcome::Allow
        );
        // auto-deny is always honored.
        std::env::set_var("MCP_SHIELD_HITL", "auto-deny");
        assert_eq!(
            ask("write_file", "{}", Duration::from_secs(1), true).await,
            HitlOutcome::Deny
        );
        std::env::remove_var("MCP_SHIELD_HITL");
    }

    #[test]
    fn truncate_long_args() {
        let long = "x".repeat(500);
        let t = truncate(&long, 300);
        assert!(t.chars().count() <= 301);
        assert!(t.ends_with('…'));
        assert_eq!(truncate("short", 300), "short");
    }
}
