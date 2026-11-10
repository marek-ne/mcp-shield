//! `mcp-shield doctor` — operational health check for IT/DevEx: secret-store
//! probe, policy signature, audit-chain integrity, config drift, HITL helper
//! availability. (`verify` is the red-team demo; `doctor` is what IT runs.)

use std::path::Path;

use anyhow::Result;

struct Check {
    name: String,
    ok: bool,
    detail: String,
}

pub fn run_doctor() -> Result<i32> {
    let mut checks: Vec<Check> = Vec::new();
    let exe = std::env::current_exe().ok();

    // 1) Secret store backend.
    match crate::keychain::open_store() {
        Ok(store) => checks.push(Check {
            name: "secret store".into(),
            ok: true,
            detail: format!("backend: {}", store.backend_name()),
        }),
        Err(e) => checks.push(Check {
            name: "secret store".into(),
            ok: false,
            detail: format!("UNAVAILABLE: {e:#}"),
        }),
    }

    // 2) Policy: exists, signed, permissions.
    let policy_path = crate::util::default_policy_path();
    if !policy_path.exists() {
        checks.push(Check {
            name: "policy".into(),
            ok: false,
            detail: format!(
                "missing: {} (created on first `exec`)",
                policy_path.display()
            ),
        });
    } else {
        let sig_path = policy_path.with_extension("toml.sig");
        let sig_ok = sig_path.exists() && {
            // Reuse the engine loader: it verifies the signature fail-closed.
            crate::policy::PolicyEngine::load_or_default(None)
                .map(|e| e.signed)
                .unwrap_or(false)
        };
        checks.push(Check {
            name: "policy".into(),
            ok: sig_ok,
            detail: format!(
                "{} (signature {})",
                policy_path.display(),
                if sig_ok {
                    "valid"
                } else {
                    "MISSING OR INVALID"
                }
            ),
        });
        // Upgrade drift: flag security defaults an older policy lacks.
        match std::fs::read_to_string(&policy_path)
            .ok()
            .and_then(|raw| toml::from_str::<crate::policy::PolicyFile>(&raw).ok())
        {
            Some(file) => {
                let missing = crate::policy::missing_security_paths(&file);
                checks.push(Check {
                    name: "policy security defaults".into(),
                    ok: missing.is_empty(),
                    detail: if missing.is_empty() {
                        "all security defaults present".to_string()
                    } else {
                        format!(
                            "missing since an older release: {} - run `mcp-shield resign-policy` after review",
                            missing.join(", ")
                        )
                    },
                });
            }
            None => checks.push(Check {
                name: "policy security defaults".into(),
                ok: false,
                detail: "policy does not parse".to_string(),
            }),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(md) = std::fs::metadata(&policy_path) {
                let mode = md.permissions().mode() & 0o777;
                checks.push(Check {
                    name: "policy permissions".into(),
                    ok: mode & 0o077 == 0,
                    detail: format!("mode {mode:04o} (want 0600)"),
                });
            }
        }
    }

    // 3) Audit log: chain + MAC coverage.
    let audit_path = crate::util::audit_path();
    if !audit_path.exists() {
        checks.push(Check {
            name: "audit log".into(),
            ok: true,
            detail: "no events yet".to_string(),
        });
    } else {
        match crate::audit::verify_chain(&audit_path) {
            Ok(report) => {
                let keyed = report.macs_present == report.events && report.events > 0;
                checks.push(Check {
                    name: "audit log".into(),
                    ok: report.valid,
                    detail: format!(
                        "{} events, chain {}, {} HMAC-MACed",
                        report.events,
                        if report.valid { "INTACT" } else { "BROKEN" },
                        report.macs_present
                    ),
                });
                checks.push(Check {
                    name: "audit keying".into(),
                    ok: keyed,
                    detail: if keyed {
                        "every event HMAC-verified".to_string()
                    } else {
                        "events lack valid HMACs — a full rewrite from genesis would be undetectable".to_string()
                    },
                });
            }
            Err(e) => checks.push(Check {
                name: "audit log".into(),
                ok: false,
                detail: format!("{e:#}"),
            }),
        }
    }

    // 4) Config drift: shimmed entries whose command no longer points at this
    // binary (e.g. after moving/upgrading mcp-shield).
    let mut drift = Vec::new();
    let mut governed = 0usize;
    if let Ok(locations) = known_config_paths() {
        for path in locations {
            let Ok(raw) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(doc) = serde_json::from_str::<serde_json::Value>(&raw) else {
                continue;
            };
            let key = if doc.get("mcpServers").is_some() {
                "mcpServers"
            } else if doc.get("servers").is_some() {
                "servers"
            } else {
                continue;
            };
            let Some(servers) = doc.get(key).and_then(serde_json::Value::as_object) else {
                continue;
            };
            for (name, entry) in servers {
                let cmd = entry
                    .get("command")
                    .and_then(|c| c.as_str().map(|s| s.to_string()))
                    .or_else(|| {
                        entry
                            .get("command")
                            .and_then(serde_json::Value::as_array)
                            .and_then(|a| a.first())
                            .and_then(serde_json::Value::as_str)
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_default();
                if cmd.to_lowercase().contains("mcp-shield") {
                    governed += 1;
                    let same = exe
                        .as_ref()
                        .is_some_and(|e| normalize(e) == normalize(Path::new(&cmd)));
                    if !same {
                        drift.push(format!("{name} in {}", path.display()));
                    }
                }
            }
        }
    }
    checks.push(Check {
        name: "governed servers".into(),
        ok: true,
        detail: format!("{governed} shimmed"),
    });
    checks.push(Check {
        name: "config drift".into(),
        ok: drift.is_empty(),
        detail: if drift.is_empty() {
            "all shimmed entries point at this binary".to_string()
        } else {
            format!("stale shim path (re-run `wrap`): {}", drift.join(", "))
        },
    });

    // 5) HITL helper + env override posture.
    let helper = helper_present();
    checks.push(Check {
        name: "HITL dialog helper".into(),
        ok: helper.0,
        detail: helper.1,
    });
    let env_mode = std::env::var("MCP_SHIELD_HITL").unwrap_or_else(|_| "interactive".into());
    checks.push(Check {
        name: "HITL env override".into(),
        ok: env_mode != "auto-allow",
        detail: format!(
            "MCP_SHIELD_HITL={env_mode}{}",
            if env_mode == "auto-allow" {
                " (auto-allow requires allow_headless_hitl_override in the signed policy)"
            } else {
                ""
            }
        ),
    });

    // Report.
    println!("mcp-shield doctor — operational health");
    println!("======================================");
    let mut all_ok = true;
    for c in &checks {
        if !c.ok {
            all_ok = false;
        }
        println!(
            "[{:<4}] {:<24} {}",
            if c.ok { "OK" } else { "FAIL" },
            c.name,
            c.detail
        );
    }
    println!();
    if all_ok {
        println!("RESULT: healthy");
        Ok(0)
    } else {
        println!("RESULT: problems found — see FAIL lines above");
        Ok(1)
    }
}

fn normalize(p: &Path) -> String {
    p.to_string_lossy()
        .to_lowercase()
        .replace('\\', "/")
        .trim_end_matches(".exe")
        .to_string()
}

fn known_config_paths() -> Result<Vec<std::path::PathBuf>> {
    // Reuse the discovery list via a throwaway audit run over known locations:
    // simplest is to re-derive the standard paths here.
    let home = dirs::home_dir().unwrap_or_else(|| Path::new(".").to_path_buf());
    let cwd = std::env::current_dir()?;
    let mut v = vec![
        home.join(".cursor/mcp.json"),
        cwd.join(".cursor/mcp.json"),
        home.join(".claude.json"),
        cwd.join(".mcp.json"),
        dirs::config_dir()
            .unwrap_or_else(|| home.clone())
            .join("Claude/claude_desktop_config.json"),
        home.join(".gemini/config/mcp_config.json"),
        dirs::config_dir()
            .unwrap_or_else(|| home.clone())
            .join("Code/User/mcp.json"),
        cwd.join(".vscode/mcp.json"),
        home.join(".codeium/windsurf/mcp_config.json"),
        home.join(".kimi-code/mcp.json"),
        cwd.join(".kimi-code/mcp.json"),
        home.join(".config/muse/settings.json"),
    ];
    v.sort();
    v.dedup();
    Ok(v)
}

fn helper_present() -> (bool, String) {
    #[cfg(target_os = "macos")]
    {
        if std::process::Command::new("osascript")
            .arg("-e")
            .arg("1")
            .output()
            .is_ok()
        {
            (true, "osascript available".to_string())
        } else {
            (false, "osascript NOT found".to_string())
        }
    }
    #[cfg(target_os = "windows")]
    {
        if std::process::Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-Command")
            .arg("1")
            .output()
            .is_ok()
        {
            (true, "powershell.exe available".to_string())
        } else {
            (false, "powershell.exe NOT found".to_string())
        }
    }
    #[cfg(target_os = "linux")]
    {
        if std::process::Command::new("zenity")
            .arg("--version")
            .output()
            .is_ok()
        {
            (true, "zenity available".to_string())
        } else {
            (
                false,
                "zenity NOT found (install zenity or use MCP_SHIELD_HITL)".to_string(),
            )
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        (
            false,
            "no native dialog helper on this platform".to_string(),
        )
    }
}
