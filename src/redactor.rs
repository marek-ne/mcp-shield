//! Deterministic secret detection & redaction (outbound DLP).
//!
//! Scans child MCP server responses before they reach the host (LLM context
//! window) and replaces leaked credentials with `[REDACTED:<KIND>]`.
//! Detection is 100% deterministic: compiled regexes, checksum validation
//! (Luhn, Mod-97) and Shannon entropy — zero ML, zero LLM.

use std::sync::OnceLock;

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::util::sensitive_env_key;

/// A labeled detection pattern. `template`, when set, is a regex replacement
/// template (may reference capture groups) instead of the plain redaction tag.
struct Pattern {
    re: Regex,
    kind: &'static str,
    template: Option<&'static str>,
}

fn patterns() -> &'static Vec<Pattern> {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let defs: Vec<(&str, &str, Option<&'static str>)> = vec![
            // PEM private keys (also matches \n-escaped PEM inside JSON strings).
            (
                r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
                "PEM_PRIVATE_KEY",
                None,
            ),
            (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "AWS_ACCESS_KEY", None),
            (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "GITHUB_TOKEN", None),
            // Fine-grained GitHub PATs.
            (r"\bgithub_pat_[A-Za-z0-9_]{22,}\b", "GITHUB_TOKEN", None),
            // OpenAI/Anthropic (sk-ant-...), Stripe (sk_live_...), etc.
            (r"\bsk[-_][A-Za-z0-9_-]{16,}\b", "SECRET_KEY", None),
            (r"\bxox[baprs]-[A-Za-z0-9-]{8,}\b", "SLACK_TOKEN", None),
            (
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
                "JWT",
                None,
            ),
            (
                r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}",
                "BEARER_TOKEN",
                None,
            ),
            // DB connection strings with an embedded password: keep scheme+user,
            // redact only the password portion.
            (
                r#"((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s"]+):[^@\s"]+@"#,
                "DB_PASSWORD",
                Some("${1}:[REDACTED:DB_PASSWORD]@"),
            ),
        ];
        defs.into_iter()
            .map(|(src, kind, template)| Pattern {
                re: Regex::new(src).expect("hardcoded redaction regex must compile"),
                kind,
                template,
            })
            .collect()
    })
}

fn cc_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:\d[ -]?){13,19}\b").unwrap())
}

fn iban_candidate_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9 ]{11,40}").unwrap())
}

fn entropy_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[A-Za-z0-9+/=_-]{32,}\b").unwrap())
}

/// Luhn checksum validation.
pub fn luhn_valid(digits: &str) -> bool {
    let digits: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut d = *d;
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum % 10 == 0
}

/// IBAN Mod-97 checksum validation.
pub fn iban_valid(iban: &str) -> bool {
    let compact: String = iban.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 15 || compact.len() > 34 {
        return false;
    }
    if !compact.chars().take(2).all(|c| c.is_ascii_uppercase()) {
        return false;
    }
    // Move first 4 chars to the end, convert letters to digits (A=10..Z=35).
    let mut rearranged = String::with_capacity(compact.len() * 2);
    rearranged.push_str(&compact[4..]);
    rearranged.push_str(&compact[..4]);
    let mut rem: u32 = 0;
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            rem = (rem * 10 + (c as u32 - '0' as u32)) % 97;
        } else if c.is_ascii_uppercase() {
            let n = (c as u32 - 'A' as u32) + 10;
            rem = (rem * 100 + n) % 97;
        } else {
            return false;
        }
    }
    rem == 1
}

/// Shannon entropy (bits per char) of a string.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for c in counts.iter().filter(|c| **c > 0) {
        let p = *c as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// High-entropy candidate token (e.g. opaque API keys without a known prefix).
fn looks_like_entropy_token(s: &str) -> bool {
    if s.len() < 32 {
        return false;
    }
    let distinct = s.bytes().collect::<std::collections::BTreeSet<_>>().len();
    if distinct < 16 {
        return false;
    }
    let has_alpha = s.bytes().any(|b| b.is_ascii_alphabetic());
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    has_alpha && has_digit && shannon_entropy(s) >= 4.8
}

/// Redact IBANs with Mod-97 validation. A greedy candidate may swallow tokens
/// that follow the IBAN (e.g. an adjacent credit-card number), which would
/// fail validation and redact nothing — so try the longest space-separated
/// prefix of the candidate that validates instead.
fn redact_ibans(haystack: &str) -> (String, bool) {
    let re = iban_candidate_regex();
    let mut out = String::with_capacity(haystack.len());
    let mut last = 0usize;
    let mut any = false;
    for m in re.find_iter(haystack) {
        let span = m.as_str();
        let tokens: Vec<&str> = span.split(' ').collect();
        let mut replaced_len = 0usize;
        let mut k = tokens.len();
        while k > 0 {
            let cand = tokens[..k].join(" ");
            if iban_valid(&cand) {
                replaced_len = cand.len();
                break;
            }
            k -= 1;
        }
        if k > 0 {
            let start = m.start();
            out.push_str(&haystack[last..start]);
            out.push_str("[REDACTED:IBAN]");
            last = start + replaced_len;
            any = true;
        }
    }
    if any {
        out.push_str(&haystack[last..]);
        (out, true)
    } else {
        (haystack.to_string(), false)
    }
}

/// Replace regex matches validated by `keep` with `[REDACTED:<label>]`.
fn replace_validated(
    re: &Regex,
    haystack: &str,
    keep: impl Fn(&str) -> bool,
    label: &str,
) -> (String, bool) {
    let mut out = String::with_capacity(haystack.len());
    let mut last = 0usize;
    let mut any = false;
    for m in re.find_iter(haystack) {
        if keep(m.as_str()) {
            out.push_str(&haystack[last..m.start()]);
            out.push_str("[REDACTED:");
            out.push_str(label);
            out.push(']');
            last = m.end();
            any = true;
        }
    }
    if any {
        out.push_str(&haystack[last..]);
        (out, true)
    } else {
        (haystack.to_string(), false)
    }
}

/// Classify a single value as a known secret kind (used by `audit`/`wrap`).
pub fn classify_secret(value: &str) -> Option<&'static str> {
    for p in patterns() {
        if p.re.is_match(value) {
            return Some(p.kind);
        }
    }
    if luhn_valid(&value.replace([' ', '-'], ""))
        && value.chars().filter(|c| c.is_ascii_digit()).count() >= 13
    {
        return Some("CREDIT_CARD");
    }
    if iban_valid(value) {
        return Some("IBAN");
    }
    None
}

/// True if an env entry should be extracted into the Keychain during `wrap`.
pub fn is_extractable_secret(key: &str, value: &str) -> bool {
    if value.is_empty() || value.len() < 4 {
        return false;
    }
    if value.starts_with(crate::util::VAULT_PREFIX) {
        return false;
    }
    classify_secret(value).is_some() || sensitive_env_key(key)
}

/// Inbound DLP scanner: redacts secrets from a single JSON-RPC line.
pub struct SecretScanner {
    exact: Option<AhoCorasick>,
    dynamic_count: usize,
}

impl SecretScanner {
    /// Build a scanner; `dynamic_secrets` are exact values resolved from the
    /// Keychain at startup (and any plaintext env secrets seen at spawn time).
    pub fn new(dynamic_secrets: &[String]) -> Self {
        let uniq: Vec<String> = {
            let mut seen = std::collections::BTreeSet::new();
            dynamic_secrets
                .iter()
                .filter(|s| !s.is_empty())
                .filter(|s| seen.insert((*s).clone()))
                .cloned()
                .collect()
        };
        let dynamic_count = uniq.len();
        let exact = if uniq.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .build(uniq)
                    .expect("aho-corasick build"),
            )
        };
        Self {
            exact,
            dynamic_count,
        }
    }

    /// Number of dynamic (exact-match) secrets loaded.
    pub fn dynamic_secret_count(&self) -> usize {
        self.dynamic_count
    }

    /// Redact a line. Returns the sanitized line and the distinct kinds redacted.
    pub fn redact_line(&self, line: &str) -> (String, Vec<String>) {
        let mut kinds: Vec<String> = Vec::new();
        let mut out = line.to_string();

        // 1) Exact dynamic secrets first (Keychain-resolved values, env secrets).
        if let Some(ac) = &self.exact {
            let replacements = vec!["[REDACTED:SECRET]"; self.dynamic_count];
            let replaced = ac.replace_all(&out, &replacements);
            if replaced != out {
                kinds.push("SECRET".to_string());
                out = replaced;
            }
        }

        // 2) Labeled regex patterns.
        for p in patterns() {
            let replacement = match p.template {
                Some(t) => t.to_string(),
                None => format!("[REDACTED:{}]", p.kind),
            };
            let replaced = p.re.replace_all(&out, replacement.as_str());
            if replaced != out {
                kinds.push(p.kind.to_string());
                out = replaced.into_owned();
            }
        }

        // 3) IBANs (Mod-97, token-trimmed) then credit cards (Luhn). IBANs go
        //    first so a greedy candidate cannot swallow an adjacent card number.
        let (next, hit) = redact_ibans(&out);
        if hit {
            kinds.push("IBAN".to_string());
            out = next;
        }
        let (next, hit) = replace_validated(
            cc_regex(),
            &out,
            |s| luhn_valid(&s.replace([' ', '-'], "")),
            "CREDIT_CARD",
        );
        if hit {
            kinds.push("CREDIT_CARD".to_string());
            out = next;
        }

        // 4) High-entropy opaque tokens.
        let (next, hit) = replace_validated(
            entropy_regex(),
            &out,
            looks_like_entropy_token,
            "HIGH_ENTROPY_TOKEN",
        );
        if hit {
            kinds.push("HIGH_ENTROPY_TOKEN".to_string());
            out = next;
        }

        kinds.sort();
        kinds.dedup();
        (out, kinds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_token_formats() {
        let scanner = SecretScanner::new(&[]);
        let line = r#"{"text":"key=AKIAIOSFODNN7EXAMPLE and ghp_abcdefghij0123456789abcdefghij0123456789 done"}"#;
        let (out, kinds) = scanner.redact_line(line);
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!out.contains("ghp_abcdefghij"));
        assert!(out.contains("[REDACTED:AWS_ACCESS_KEY]"));
        assert!(out.contains("[REDACTED:GITHUB_TOKEN]"));
        assert!(kinds.contains(&"AWS_ACCESS_KEY".to_string()));
        assert!(kinds.contains(&"GITHUB_TOKEN".to_string()));
    }

    #[test]
    fn redacts_pem_inside_json_escaped_string() {
        let scanner = SecretScanner::new(&[]);
        let line = r#"{"content":"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"}"#;
        let (out, kinds) = scanner.redact_line(line);
        assert!(out.contains("[REDACTED:PEM_PRIVATE_KEY]"));
        assert!(!out.contains("b3BlbnNzaC1rZXktdjE"));
        assert!(kinds.contains(&"PEM_PRIVATE_KEY".to_string()));
    }

    #[test]
    fn redacts_dynamic_keychain_secret_exactly() {
        let scanner = SecretScanner::new(&["sup3r-s3cret-postgres-password".to_string()]);
        let line = r#"{"text":"the password is sup3r-s3cret-postgres-password ok"}"#;
        let (out, _kinds) = scanner.redact_line(line);
        assert!(out.contains("[REDACTED:SECRET]"));
        assert!(!out.contains("sup3r-s3cret"));
    }

    #[test]
    fn luhn_and_iban_validation() {
        assert!(luhn_valid("4111111111111111"));
        assert!(luhn_valid("4111 1111 1111 1111"));
        assert!(!luhn_valid("4111111111111112"));
        assert!(iban_valid("GB82WEST12345698765432"));
        assert!(!iban_valid("GB82WEST12345698765433"));
    }

    #[test]
    fn redacts_validated_cc_and_iban_only() {
        let scanner = SecretScanner::new(&[]);
        let line = r#"{"text":"card 4111 1111 1111 1111 iban GB82 WEST 1234 5698 7654 32 noise 123456789012345678901234"}"#;
        let (out, kinds) = scanner.redact_line(line);
        assert!(out.contains("[REDACTED:CREDIT_CARD]"));
        assert!(out.contains("[REDACTED:IBAN]"));
        // 24-digit non-Luhn number must survive.
        assert!(out.contains("123456789012345678901234"));
        assert!(kinds.contains(&"CREDIT_CARD".to_string()));
        assert!(kinds.contains(&"IBAN".to_string()));
    }

    #[test]
    fn redacts_db_url_password_but_keeps_user_and_host() {
        let scanner = SecretScanner::new(&[]);
        let line = r#"{"text":"conn=postgresql://svc:s3cr3tp4ssword@db.internal:5432/app"}"#;
        let (out, kinds) = scanner.redact_line(line);
        assert!(out.contains("postgresql://svc:[REDACTED:DB_PASSWORD]@db.internal:5432/app"));
        assert!(kinds.contains(&"DB_PASSWORD".to_string()));
    }

    #[test]
    fn leaves_safe_content_untouched() {
        let scanner = SecretScanner::new(&[]);
        let line = r#"{"content":[{"type":"text","text":"SELECT id, name FROM users LIMIT 5;"}]}"#;
        let (out, kinds) = scanner.redact_line(line);
        assert_eq!(out, line);
        assert!(kinds.is_empty());
    }

    #[test]
    fn entropy_token_detection() {
        assert!(looks_like_entropy_token(
            "aZ9xQ7vB3nM1kL0pO5wR8sT2yU4iE6oP1"
        ));
        assert!(!looks_like_entropy_token("SELECT id name FROM users LIMIT"));
    }
}
