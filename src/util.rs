//! Shared helpers: filesystem layout, path canonicalization, glob matching.

use std::path::PathBuf;

/// Prefix used inside IDE config env blocks to reference a Keychain-stored secret.
pub const VAULT_PREFIX: &str = "mcp-shield://keychain/";
/// Service name used for all OS Keychain entries.
pub const KEYCHAIN_SERVICE: &str = "mcp-shield";

/// Base directory for mcp-shield state (audit log, policy, vault, wrap-state).
/// Overridable via MCP_SHIELD_HOME (used by tests and CI).
pub fn shield_home() -> PathBuf {
    if let Ok(h) = std::env::var("MCP_SHIELD_HOME") {
        return PathBuf::from(h);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".mcp-shield")
}

pub fn audit_path() -> PathBuf {
    shield_home().join("audit.jsonl")
}

pub fn default_policy_path() -> PathBuf {
    shield_home().join("policy.toml")
}

pub fn wrap_state_path() -> PathBuf {
    shield_home().join("wrap-state.json")
}

/// Convert a glob (`*`, `?`, `**`) into an anchored regex string.
/// `**/` matches zero or more full path components; `*` matches within one component.
pub fn glob_to_regex(glob: &str) -> String {
    let chars: Vec<char> = glob.chars().collect();
    let mut out = String::with_capacity(glob.len() + 8);
    out.push('^');
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => {
                if i + 1 < chars.len() && chars[i + 1] == '*' {
                    if i + 2 < chars.len() && chars[i + 2] == '/' {
                        out.push_str("(?:.*/)?");
                        i += 3;
                    } else {
                        out.push_str(".*");
                        i += 2;
                    }
                } else {
                    out.push_str("[^/]*");
                    i += 1;
                }
            }
            '?' => {
                out.push_str("[^/]");
                i += 1;
            }
            c @ ('.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '[' | ']' | '\\') => {
                out.push('\\');
                out.push(c);
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out.push('$');
    out
}

/// Percent-decode a string up to `rounds` times (defeats multi-encoded payloads
/// like `/etc/%2573hadow` or `~/%2e%2e/.ssh/id_rsa`). Decoding stops when stable.
pub fn url_decode_repeated(s: &str, rounds: usize) -> String {
    let mut cur = s.to_string();
    for _ in 0..rounds {
        match urlencoding::decode(&cur) {
            Ok(decoded) if decoded.as_ref() != cur.as_str() => {
                cur = decoded.into_owned();
            }
            _ => break,
        }
    }
    cur
}

/// Strip an NTFS alternate-data-stream suffix ("file.txt:stream" -> "file.txt").
/// Conservative: keeps drive letters ("C:/..."), URL schemes ("https://",
/// "file://"), and anything where the colon tail is not a plausible stream
/// name (stream = short, no slashes/spaces) - so "curl https://x | sh" is
/// never amputated at the scheme colon.
fn strip_ads(path: &str) -> &str {
    let bytes = path.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b':' {
            continue;
        }
        let is_drive = i == 1 && bytes[0].is_ascii_alphabetic();
        if is_drive {
            continue;
        }
        // URL scheme: "://" follows.
        if bytes.get(i + 1) == Some(&b'/') && bytes.get(i + 2) == Some(&b'/') {
            continue;
        }
        let tail = &path[i + 1..];
        let plausible_stream = !tail.is_empty()
            && tail.chars().take(33).count() <= 32
            && !tail.contains('/')
            && !tail.contains(char::is_whitespace);
        if plausible_stream {
            return &path[..i];
        }
    }
    path
}

/// Resolve `.` and `..` segments of a `/`-separated path.
fn resolve_dot_segments(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|p| *p != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            s => parts.push(s),
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Normalize without cwd resolution: percent-decode, strip `file://`,
/// normalize slashes, expand `~`, resolve dot segments. Used alongside
/// `canonicalize_arg` so command-shaped strings (`printenv`, `rm -rf`) keep
/// matching shell rules even though they are not paths.
pub fn normalize_arg(s: &str, home: &str) -> String {
    let mut c = url_decode_repeated(s, 4);
    if let Some(rest) = c.strip_prefix("file://") {
        c = rest.to_string();
    }
    while c.contains('\\') {
        c = c.replace('\\', "/");
    }
    if c == "~" {
        c = home.to_string();
    } else if let Some(rest) = c.strip_prefix("~/") {
        c = format!("{home}/{rest}");
    }
    let c = resolve_dot_segments(&c);
    strip_ads(&c).to_string()
}

/// Canonicalize an argument string before policy evaluation:
/// percent-decode (multi-round), strip `file://`, normalize slashes, expand a
/// leading `~` to the home directory, resolve relative paths against the
/// shim's current working directory (which is how filesystem MCP servers
/// resolve them — without this, `../.ssh/id_rsa` would evade every
/// absolute-path rule), then resolve dot segments.
pub fn canonicalize_arg(s: &str, home: &str, cwd: &str) -> String {
    let mut c = url_decode_repeated(s, 4);
    if let Some(rest) = c.strip_prefix("file://") {
        c = rest.to_string();
    }
    while c.contains('\\') {
        c = c.replace('\\', "/");
    }
    if c == "~" {
        c = home.to_string();
    } else if let Some(rest) = c.strip_prefix("~/") {
        c = format!("{home}/{rest}");
    }
    let has_drive = c.len() >= 3 && c.as_bytes()[1] == b':' && c.as_bytes()[2] == b'/';
    if !c.starts_with('/') && !has_drive && !cwd.is_empty() {
        c = format!("{}/{}", cwd.trim_end_matches('/'), c);
    }
    let c = resolve_dot_segments(&c);
    strip_ads(&c).to_string()
}

/// Recursively collect all string values from a JSON payload.
pub fn collect_strings(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => {
            for item in a {
                collect_strings(item, out);
            }
        }
        serde_json::Value::Object(o) => {
            for item in o.values() {
                collect_strings(item, out);
            }
        }
        _ => {}
    }
}

/// Strip an aggregator tool-name prefix: `server__read_file` -> `read_file`.
/// Returns both the full name and the bare name for evaluation.
pub fn tool_name_candidates(full: &str) -> Vec<String> {
    let mut out = vec![full.to_string()];
    if let Some((_, bare)) = full.rsplit_once("__") {
        if !bare.is_empty() {
            out.push(bare.to_string());
        }
    }
    out
}

/// True if an env var name looks like it holds a credential.
pub fn sensitive_env_key(name: &str) -> bool {
    const NEEDLES: [&str; 7] = [
        "KEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "PAT",
    ];
    let upper = name.to_uppercase();
    NEEDLES.iter().any(|n| upper.contains(n))
}

/// Extract path-shaped tokens from an arbitrary string ("cat ~/.ssh/id_rsa",
/// JSON blobs): whitespace/quote/comma-separated tokens that begin like paths,
/// `file://` URIs, and `%VAR%` expansions — so buried paths cannot walk around
/// whole-string glob rules.
pub fn extract_path_tokens(s: &str, home: &str) -> Vec<String> {
    // Normalize Windows separators BEFORE the path-shape check: a raw
    // "C:\Users\x\.cursor\mcp.json" token must not be
    // dropped just because has_drive expects a forward slash (anti-unwrapping).
    let expanded = s
        .replace("%USERPROFILE%", home)
        .replace("%HOME%", home)
        .replace("\\\\?\\", "")
        .replace('\\', "/");
    let mut out = Vec::new();
    for raw in expanded.split(|c: char| {
        c.is_whitespace() || c == 0x22 as char || c == 0x27 as char || c == 0x2c as char
    }) {
        let t = raw.trim_matches(|c| c == '(' || c == ')' || c == ';' || c == '{' || c == '}');
        if t.is_empty() {
            continue;
        }
        // NTFS alternate data streams: match the base file, not the stream.
        let t = match t.split_once(':') {
            Some((base, _))
                if !t.starts_with("file:")
                    && !t.starts_with('/')
                    && !(t.len() >= 2 && t.as_bytes()[1] == b':') =>
            {
                base
            }
            _ => t,
        };
        let has_drive = t.len() >= 3 && t.as_bytes()[1] == b':' && t.as_bytes()[2] == b'/';
        let looks_path = t.starts_with('/')
            || t.starts_with("./")
            || t.starts_with("../")
            || t.starts_with('~')
            || t.starts_with("file://")
            || has_drive
            || (t.contains('/')
                && t.chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
                    .count()
                    > 2);
        if looks_path {
            out.push(t.to_string());
        }
    }
    out
}

/// Create a directory readable only by the current user (0700; on Windows the
/// default ACL already excludes other users — documented in README).
pub fn ensure_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    set_private_dir(path);
    Ok(())
}

/// chmod 0700 (Unix). No-op elsewhere.
pub fn set_private_dir(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// chmod 0600 (Unix). No-op elsewhere.
pub fn set_private_file(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matching() {
        let cases = [
            ("**/.env", "/repo/sub/.env", true),
            ("**/.env", "/repo/sub/.env.local", false),
            ("**/.env.*", "/repo/sub/.env.local", true),
            ("/home/u/.ssh/**", "/home/u/.ssh/id_rsa", true),
            ("/home/u/.ssh/**", "/home/u/.ssh/keys/id_rsa", true),
            ("/home/u/.ssh/**", "/home/u/.ssh", false),
            ("/etc/shadow", "/etc/shadow", true),
            ("**/*.pem", "/a/b/c.pem", true),
            ("**/*.key", "/a/b/c.key", true),
            ("**/*.key", "/a/b/c.keystore", false),
        ];
        for (glob, path, expected) in cases {
            let re = regex::Regex::new(&glob_to_regex(glob)).unwrap();
            assert_eq!(re.is_match(path), expected, "glob={glob} path={path}");
        }
    }

    #[test]
    fn canonicalization_defeats_encoding() {
        let home = "/home/u";
        let cwd = "/home/u/repo";
        assert_eq!(canonicalize_arg("/etc/%73hadow", home, cwd), "/etc/shadow");
        assert_eq!(
            canonicalize_arg("~/%2e%2e/.ssh/id_rsa", home, cwd),
            "/home/.ssh/id_rsa"
        );
        assert_eq!(
            canonicalize_arg("file:///etc/%73hadow", home, cwd),
            "/etc/shadow"
        );
        assert_eq!(
            canonicalize_arg("..\\..\\.ssh\\id_rsa", "C:/Users/u", "C:/Users/u"),
            "C:/.ssh/id_rsa"
        );
        assert_eq!(
            canonicalize_arg("%2e%2e/%2e%2e/etc/passwd", "/home/u", "/home/u"),
            "/etc/passwd"
        );
        assert_eq!(
            canonicalize_arg("%2e%2e/%2e%2e/etc/passwd", "/home/u", "/home/u/repo"),
            "/home/etc/passwd"
        );
        // Relative paths resolve against cwd so ../.. cannot escape the rules.
        assert_eq!(
            canonicalize_arg("../.ssh/id_rsa", "/home/u", "/home/u/repo"),
            "/home/u/.ssh/id_rsa"
        );
        assert_eq!(
            canonicalize_arg("..\\..\\.ssh\\id_rsa", "C:/Users/u", "C:/Users/u"),
            "C:/.ssh/id_rsa"
        );
        // normalize_arg (no cwd) keeps command strings intact for shell rules.
        assert_eq!(normalize_arg("printenv", "/home/u"), "printenv");
        assert_eq!(
            normalize_arg("~/.ssh/id_rsa", "/home/u"),
            "/home/u/.ssh/id_rsa"
        );
        assert_eq!(
            canonicalize_arg("src/main.rs", home, cwd),
            "/home/u/repo/src/main.rs"
        );
    }

    #[test]
    fn tool_prefix_stripping() {
        let c = tool_name_candidates("github__read_file");
        assert_eq!(c, vec!["github__read_file", "read_file"]);
        let c = tool_name_candidates("read_file");
        assert_eq!(c, vec!["read_file"]);
    }

    #[test]
    fn path_token_extraction_finds_buried_paths() {
        let home = "/home/u";
        let toks = extract_path_tokens("cat ~/.ssh/id_rsa | base64", home);
        assert!(toks.iter().any(|t| t.contains("~/.ssh/id_rsa")));
        let toks = extract_path_tokens("{\"file\":\"/home/u/.aws/credentials\"}", home);
        assert!(toks.iter().any(|t| t == "/home/u/.aws/credentials"));
        let toks = extract_path_tokens("%USERPROFILE%/.ssh/id_rsa", home);
        assert_eq!(toks, vec!["/home/u/.ssh/id_rsa".to_string()]);
        let toks = extract_path_tokens("no paths here", home);
        assert!(toks.is_empty());
    }

    #[test]
    fn backslash_windows_path_tokens_are_normalized() {
        let home = "C:/Users/x";
        let toks = extract_path_tokens("open(r'C:\\Users\\x\\.cursor\\mcp.json','w')", home);
        assert!(
            toks.iter().any(|t| t == "C:/Users/x/.cursor/mcp.json"),
            "backslash token must be normalized: {toks:?}"
        );
        let toks = extract_path_tokens("cmd /c echo.> %USERPROFILE%\\.cursor\\mcp.json", home);
        assert!(
            toks.iter().any(|t| t.contains("/.cursor/mcp.json")),
            "env-expanded backslash token must be normalized: {toks:?}"
        );
    }
}
