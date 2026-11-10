//! Append-only, tamper-evident JSONL audit log with a SHA-256 hash chain.
//!
//! Every event links `event_hash = SHA256(prev_hash || canonical_json)` so any
//! modification, deletion, or reordering of log entries is detectable offline.
//! Compatible with OpenTelemetry-style structured log ingestion (Splunk,
//! Datadog, etc. via file/OTel collectors).

use std::fs::{File, OpenOptions};
use std::io::{BufRead, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::util::audit_path;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex_encode(&hasher.finalize())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Append-only hash-chained audit logger.
///
/// Multi-process safety: every append is serialized with an atomic lock
/// directory (mkdir is atomic on all supported platforms) and the chain head
/// is re-read from the file tail before writing, so any number of concurrent
/// shim processes can share one audit log without forking the chain.
pub struct AuditLogger {
    path: PathBuf,
    prev_hash: String,
    seq: u64,
    hmac_key: Option<[u8; 32]>,
}

fn hmac_hex(key: &[u8; 32], data: &str) -> String {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

/// Load the audit HMAC key. Logging works without it, but events are then
/// only hash-chained (a full rewrite from genesis stays undetectable), so
/// `verify` reports the log as UNKEYED. Never panics.
pub fn audit_hmac_key() -> Option<[u8; 32]> {
    static KEY: std::sync::OnceLock<Option<[u8; 32]>> = std::sync::OnceLock::new();
    *KEY.get_or_init(|| {
        let store = crate::keychain::open_store().ok()?;
        crate::keychain::stored_random_key(store.as_ref(), "__audit_hmac_key__")
    })
}

impl AuditLogger {
    /// Open (or create) the audit log, resuming the hash chain from the last entry.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            crate::util::ensure_private_dir(parent)?;
        }
        let (prev_hash, seq) = read_tail(path)?.unwrap_or_else(|| (GENESIS.to_string(), 0));
        // Touch the file so the append handle exists.
        OpenOptions::new().create(true).append(true).open(path)?;
        crate::util::set_private_file(path);
        Ok(AuditLogger {
            path: path.to_path_buf(),
            prev_hash,
            seq,
            hmac_key: audit_hmac_key(),
        })
    }

    /// Open the default audit log (`$MCP_SHIELD_HOME/audit.jsonl`).
    pub fn open_default() -> Result<Self> {
        Self::open(&audit_path())
    }

    /// Append an event to the log. `fields` are merged into the event object.
    pub fn log(&mut self, kind: &str, fields: Map<String, Value>) -> Result<()> {
        let _guard = LockGuard::acquire(&self.path)?;
        // Re-sync the chain head in case another process appended since we opened.
        if let Some((hash, seq)) = read_tail(&self.path)? {
            self.prev_hash = hash;
            self.seq = seq;
        }
        let mut file = OpenOptions::new().append(true).open(&self.path)?;
        self.seq += 1;
        let mut obj = Map::new();
        obj.insert(
            "ts".to_string(),
            Value::String(Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)),
        );
        obj.insert("seq".to_string(), Value::from(self.seq));
        obj.insert(
            "prev_hash".to_string(),
            Value::String(self.prev_hash.clone()),
        );
        obj.insert("kind".to_string(), Value::String(kind.to_string()));
        for (k, v) in fields {
            obj.insert(k, v);
        }
        // Canonical JSON: serde_json::Map is a BTreeMap (sorted keys) by default.
        let payload = serde_json::to_string(&obj)?;
        let hash = sha256_hex(&format!("{}:{payload}", self.prev_hash));
        obj.insert("event_hash".to_string(), Value::String(hash.clone()));
        if let Some(key) = &self.hmac_key {
            obj.insert("event_mac".to_string(), Value::String(hmac_hex(key, &hash)));
        }
        let line = serde_json::to_string(&obj)?;
        writeln!(file, "{line}")?;
        file.flush()?;
        self.prev_hash = hash;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Read the last well-formed event's `(event_hash, seq)` by walking backwards
/// from the end of the file.
fn read_tail(path: &Path) -> Result<Option<(String, u64)>> {
    Ok(read_tail_opt(path))
}

fn read_tail_opt(path: &Path) -> Option<(String, u64)> {
    if !path.exists() {
        return None;
    }
    let mut file = File::open(path).ok()?;
    let file_len = file.metadata().ok()?.len();
    if file_len == 0 {
        return None;
    }
    const CHUNK: u64 = 4096;
    let mut cursor = file_len;
    let mut tail: Vec<u8> = Vec::new();
    loop {
        let take = CHUNK.min(cursor);
        cursor -= take;
        file.seek(std::io::SeekFrom::Start(cursor)).ok()?;
        let mut buf = vec![0u8; take as usize];
        file.read_exact(&mut buf).ok()?;
        tail.splice(0..0, buf);
        if tail.contains(&b'\n') || cursor == 0 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&tail);
    let last_line = text.lines().rev().find(|l| !l.trim().is_empty())?;
    let v: Value = serde_json::from_str(last_line.trim()).ok()?;
    let hash = v.get("event_hash").and_then(Value::as_str)?.to_string();
    let seq = v.get("seq").and_then(Value::as_u64).unwrap_or(0);
    Some((hash, seq))
}

/// Poor-man's advisory lock: atomic directory creation. Stale locks (crashed
/// holder) are stolen after two minutes.
struct LockGuard {
    dir: PathBuf,
}

impl LockGuard {
    fn acquire(path: &Path) -> Result<Self> {
        let dir = path.with_extension("lock");
        let start = std::time::Instant::now();
        loop {
            match std::fs::create_dir(&dir) {
                Ok(()) => return Ok(LockGuard { dir }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = std::fs::metadata(&dir)
                        .and_then(|m| m.modified())
                        .map(|t| t.elapsed().unwrap_or_default() > Duration::from_secs(120))
                        .unwrap_or(false);
                    if stale {
                        let _ = std::fs::remove_dir(&dir);
                        continue;
                    }
                    if start.elapsed() > Duration::from_secs(10) {
                        anyhow::bail!("timed out acquiring audit log lock {}", dir.display());
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => return Err(e).with_context(|| format!("cannot lock {}", dir.display())),
            }
        }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Result of an offline chain-integrity verification pass.
#[derive(Debug, Clone)]
pub struct ChainReport {
    pub events: u64,
    pub valid: bool,
    pub broken_at_seq: Option<u64>,
    pub macs_present: u64,
    pub macs_invalid: u64,
    pub decisions: u64,
    pub blocked: u64,
    pub redacted: u64,
    pub hitl_prompts: u64,
    pub max_latency_us: u64,
    pub p99_latency_us: f64,
}

/// Recompute the full SHA-256 hash chain of an audit log.
pub fn verify_chain(path: &Path) -> Result<ChainReport> {
    let f =
        File::open(path).with_context(|| format!("cannot open audit log {}", path.display()))?;
    let reader = std::io::BufReader::new(f);
    let mut prev = GENESIS.to_string();
    let mut seq: u64 = 0;
    let mut events: u64 = 0;
    let mut broken: Option<u64> = None;
    let mut decisions = 0u64;
    let mut blocked = 0u64;
    let mut redacted = 0u64;
    let mut hitl = 0u64;
    let mut latencies: Vec<u64> = Vec::new();
    let hmac_key = audit_hmac_key();
    let mut macs_present = 0u64;
    let mut macs_invalid = 0u64;
    // Upgrades: events written before HMAC keying existed form a legacy
    // prefix. MACs are enforced from the first MACed event onward; a rewrite
    // of history is still caught because the hash chain covers the prefix.
    let mut seen_mac = false;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut v: Map<String, Value> = match serde_json::from_str(trimmed) {
            Ok(Value::Object(m)) => m,
            _ => {
                broken.get_or_insert(seq + 1);
                continue;
            }
        };
        let stored_hash = v
            .get("event_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let stored_prev = v
            .get("prev_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        seq = v.get("seq").and_then(Value::as_u64).unwrap_or(seq + 1);
        let stored_mac = v
            .get("event_mac")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        v.remove("event_hash");
        v.remove("event_mac");
        let payload = serde_json::to_string(&v)?;
        let expected = sha256_hex(&format!("{prev}:{payload}"));
        let hash_ok = stored_hash == expected && stored_prev == prev;
        if let Some(key) = &hmac_key {
            match &stored_mac {
                Some(mac) => {
                    seen_mac = true;
                    macs_present += 1;
                    if mac != &hmac_hex(key, &expected) {
                        macs_invalid += 1;
                        if broken.is_none() {
                            broken = Some(seq);
                        }
                    }
                }
                None if seen_mac
                    // An event AFTER keying began with no MAC: either an
                    // editor's rewrite or log truncation — treat as broken.
                    && broken.is_none() =>
                {
                    broken = Some(seq);
                }
                None => {
                    // Legacy prefix (written before HMAC keying): the hash
                    // chain still covers it.
                }
            }
        }
        if !hash_ok && broken.is_none() {
            broken = Some(seq);
        }
        // Gather stats from well-formed events.
        if let Some(kind) = v.get("kind").and_then(Value::as_str) {
            match kind {
                "request_decision" => {
                    decisions += 1;
                    if v.get("action").and_then(Value::as_str) == Some("block") {
                        blocked += 1;
                    }
                    if let Some(lat) = v.get("latency_us").and_then(Value::as_u64) {
                        latencies.push(lat);
                    }
                }
                "redaction" => redacted += 1,
                "hitl" => hitl += 1,
                _ => {}
            }
        }
        events += 1;
        prev = stored_hash;
    }

    latencies.sort_unstable();
    let max_latency_us = latencies.last().copied().unwrap_or(0);
    let p99_latency_us = if latencies.is_empty() {
        0.0
    } else {
        let idx = ((latencies.len() as f64) * 0.99).ceil() as usize;
        latencies[idx.saturating_sub(1).min(latencies.len() - 1)] as f64
    };

    Ok(ChainReport {
        events,
        valid: broken.is_none(),
        broken_at_seq: broken,
        macs_present,
        macs_invalid,
        decisions,
        blocked,
        redacted,
        hitl_prompts: hitl,
        max_latency_us,
        p99_latency_us,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn temp_log(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "mcp-shield-audit-test-{name}-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn chain_is_valid_and_tamper_evident() {
        let path = temp_log("chain");
        {
            let mut log = AuditLogger::open(&path).unwrap();
            let mut f = Map::new();
            f.insert("detail".to_string(), Value::String("a".to_string()));
            log.log("session_start", f.clone()).unwrap();
            log.log("request_decision", {
                let mut m = Map::new();
                m.insert("action".to_string(), Value::String("block".to_string()));
                m.insert("latency_us".to_string(), Value::from(42u64));
                m
            })
            .unwrap();
            log.log("session_end", f).unwrap();
        }
        let report = verify_chain(&path).unwrap();
        assert!(report.valid);
        assert_eq!(report.events, 3);
        assert_eq!(report.decisions, 1);
        assert_eq!(report.blocked, 1);

        // Append a forged line -> chain must break.
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(f, "{{\"seq\":4,\"prev_hash\":\"{GENESIS}\",\"event_hash\":\"{GENESIS}\",\"kind\":\"forged\"}}").unwrap();
        }
        let report = verify_chain(&path).unwrap();
        assert!(!report.valid);

        // Mutate an existing line -> chain must break.
        let mut contents = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        let mut f = File::create(&path).unwrap();
        for (i, line) in lines.iter().enumerate() {
            if i == 1 {
                writeln!(f, "{}", line.replace("\"a\"", "\"tampered\"")).unwrap();
            } else {
                writeln!(f, "{line}").unwrap();
            }
        }
        drop(f);
        let report = verify_chain(&path).unwrap();
        assert!(!report.valid);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn logger_resumes_chain_across_reopen() {
        let path = temp_log("resume");
        {
            let mut log = AuditLogger::open(&path).unwrap();
            log.log("session_start", Map::new()).unwrap();
        }
        {
            let mut log = AuditLogger::open(&path).unwrap();
            log.log("session_end", Map::new()).unwrap();
        }
        let report = verify_chain(&path).unwrap();
        assert!(report.valid);
        assert_eq!(report.events, 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn hex_roundtrip() {
        let data = [0xde, 0xad, 0xbe, 0xef, 0x00, 0xff];
        assert_eq!(hex_decode(&hex_encode(&data)).unwrap(), data);
        assert!(hex_decode("xyz").is_none());
    }
}
