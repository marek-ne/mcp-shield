//! Late-bound credential storage: OS-native Keychain (macOS Secure Enclave /
//! Keychain, Windows Credential Manager + DPAPI, Linux Secret Service) with an
//! AES-256-GCM encrypted file vault fallback (Argon2id-derived key) for
//! headless/CI environments where no OS keyring is available.

use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::audit::{hex_decode, hex_encode};
use crate::util::{shield_home, KEYCHAIN_SERVICE, VAULT_PREFIX};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("entry not found")]
    NotFound,
    #[error("keychain backend error: {0}")]
    Backend(String),
    #[error("encrypted vault error: {0}")]
    Vault(String),
}

pub trait SecretStore: Send + Sync {
    fn backend_name(&self) -> &'static str;
    fn get(&self, account: &str) -> Result<String, StoreError>;
    fn set(&self, account: &str, secret: &str) -> Result<(), StoreError>;
    fn delete(&self, account: &str) -> Result<(), StoreError>;
}

/// CSPRNG bytes for nonces, salts, and key material — never UUID-derived.
pub fn rand_bytes<const N: usize>() -> [u8; N] {
    use aes_gcm::aead::rand_core::RngCore;
    let mut b = [0u8; N];
    aes_gcm::aead::OsRng.fill_bytes(&mut b);
    b
}

/// Get (or create) a CSPRNG key stored in the secret store under `account`.
/// Used for the audit HMAC key, the policy signing key, and backup encryption.
pub fn stored_random_key(store: &dyn SecretStore, account: &str) -> Option<[u8; 32]> {
    if let Ok(hex) = store.get(account) {
        if let Some(bytes) = crate::audit::hex_decode(&hex) {
            if let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Some(key);
            }
        }
    }
    let key: [u8; 32] = rand_bytes();
    store.set(account, &crate::audit::hex_encode(&key)).ok()?;
    Some(key)
}

/// ed25519 policy-signing key, held in the secret store (or MDM-provisioned
/// equivalent). None when no secret store is available.
pub fn policy_signing_key() -> Option<[u8; 32]> {
    let store = open_store().ok()?;
    stored_random_key(store.as_ref(), "__policy_signing_key__")
}

/// OS-native Keychain via the `keyring` crate.
pub struct KeychainStore;

impl SecretStore for KeychainStore {
    fn backend_name(&self) -> &'static str {
        "os-keychain"
    }

    fn get(&self, account: &str) -> Result<String, StoreError> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(keyring_err)?;
        entry.get_password().map_err(keyring_err)
    }

    fn set(&self, account: &str, secret: &str) -> Result<(), StoreError> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(keyring_err)?;
        entry.set_password(secret).map_err(keyring_err)
    }

    fn delete(&self, account: &str) -> Result<(), StoreError> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(keyring_err)?;
        entry.delete_password().map_err(keyring_err)
    }
}

fn keyring_err(e: keyring::Error) -> StoreError {
    match e {
        keyring::Error::NoEntry => StoreError::NotFound,
        keyring::Error::TooLong(what, limit) => StoreError::Backend(format!(
            "{what} exceeds the OS credential store limit ({limit} bytes; \
             Windows Credential Manager caps around 2560). Store large secrets \
             (e.g. PEM keys) in the encrypted file vault instead: set \
             MCP_SHIELD_VAULT_PASSWORD so mcp-shield falls back to it"
        )),
        other => StoreError::Backend(format!("{other:?}")),
    }
}

const VAULT_ENV_PASSWORD: &str = "MCP_SHIELD_VAULT_PASSWORD";

/// Encrypted file vault: one file per entry under
/// `$MCP_SHIELD_HOME/vault/entries/`, AES-256-GCM with random nonces,
/// Argon2id-derived master key from `MCP_SHIELD_VAULT_PASSWORD`.
pub struct FileVault {
    entries_dir: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

impl FileVault {
    pub fn open() -> Result<Self, StoreError> {
        let password = std::env::var(VAULT_ENV_PASSWORD).map_err(|_| {
            StoreError::Vault(format!(
                "{VAULT_ENV_PASSWORD} is not set; required for the encrypted file vault fallback"
            ))
        })?;
        let dir = shield_home().join("vault");
        let entries_dir = dir.join("entries");
        crate::util::ensure_private_dir(&entries_dir)
            .map_err(|e| StoreError::Vault(format!("cannot create vault dir: {e}")))?;

        // Random per-machine salt, stored next to the vault.
        let salt_path = dir.join("salt.bin");
        let salt: [u8; 16] = if salt_path.exists() {
            let raw = std::fs::read(&salt_path)
                .map_err(|e| StoreError::Vault(format!("cannot read vault salt: {e}")))?;
            let bytes = hex_decode(&String::from_utf8_lossy(&raw))
                .ok_or_else(|| StoreError::Vault("corrupt vault salt".to_string()))?;
            <[u8; 16]>::try_from(bytes.as_slice())
                .map_err(|_| StoreError::Vault("corrupt vault salt length".to_string()))?
        } else {
            let salt: [u8; 16] = rand_bytes();
            std::fs::write(&salt_path, hex_encode(&salt))
                .map_err(|e| StoreError::Vault(format!("cannot write vault salt: {e}")))?;
            crate::util::set_private_file(&salt_path);
            salt
        };

        let mut key = Zeroizing::new([0u8; 32]);
        argon2::Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, key.as_mut())
            .map_err(|e| StoreError::Vault(format!("argon2 key derivation failed: {e}")))?;
        Ok(FileVault { entries_dir, key })
    }

    fn entry_path(&self, account: &str) -> PathBuf {
        // Hashed filename: the naive char-sanitizer could map distinct
        // accounts ("a:b" vs "a_b") onto the same file.
        let hash = {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(account.as_bytes());
            crate::audit::hex_encode(&h.finalize())
        };
        self.entries_dir.join(format!("{hash}.entry"))
    }
}

impl SecretStore for FileVault {
    fn backend_name(&self) -> &'static str {
        "encrypted-file-vault"
    }

    fn get(&self, account: &str) -> Result<String, StoreError> {
        let path = self.entry_path(account);
        let raw = std::fs::read_to_string(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => StoreError::NotFound,
            _ => StoreError::Vault(format!("cannot read entry: {e}")),
        })?;
        let bytes = hex_decode(raw.trim())
            .ok_or_else(|| StoreError::Vault("corrupt entry encoding".to_string()))?;
        if bytes.len() < 12 {
            return Err(StoreError::Vault("corrupt entry length".to_string()));
        }
        let (nonce_bytes, ciphertext) = bytes.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(self.key.as_slice())
            .map_err(|e| StoreError::Vault(format!("cipher init failed: {e}")))?;
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            StoreError::Vault("decryption failed (wrong password or tampered entry)".to_string())
        })?;
        String::from_utf8(plaintext)
            .map_err(|_| StoreError::Vault("entry is not valid UTF-8".to_string()))
    }

    fn set(&self, account: &str, secret: &str) -> Result<(), StoreError> {
        // AES-256-GCM uses a 96-bit nonce from the CSPRNG.
        let nonce_bytes: [u8; 12] = rand_bytes();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(self.key.as_slice())
            .map_err(|e| StoreError::Vault(format!("cipher init failed: {e}")))?;
        let ciphertext = cipher
            .encrypt(nonce, secret.as_bytes())
            .map_err(|e| StoreError::Vault(format!("encryption failed: {e}")))?;
        let mut blob = nonce_bytes.to_vec();
        blob.extend_from_slice(&ciphertext);
        let path = self.entry_path(account);
        std::fs::write(&path, hex_encode(&blob))
            .map_err(|e| StoreError::Vault(format!("cannot write entry: {e}")))?;
        crate::util::set_private_file(&path);
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<(), StoreError> {
        match std::fs::remove_file(self.entry_path(account)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StoreError::NotFound),
            Err(e) => Err(StoreError::Vault(format!("cannot delete entry: {e}"))),
        }
    }
}

/// Probe the OS Keychain; fall back to the encrypted vault when unavailable.
pub fn open_store() -> anyhow::Result<Box<dyn SecretStore>> {
    match probe_keychain() {
        Ok(()) => Ok(Box::new(KeychainStore)),
        Err(probe_err) => {
            if std::env::var(VAULT_ENV_PASSWORD).is_ok() {
                eprintln!("[mcp-shield] OS keychain unavailable ({probe_err}); using encrypted file vault");
                Ok(Box::new(FileVault::open()?))
            } else {
                Err(anyhow::anyhow!(
                    "OS keychain is unavailable ({probe_err}) and {VAULT_ENV_PASSWORD} is not set; \
                     cannot open a secret store. Set {VAULT_ENV_PASSWORD} to use the encrypted vault fallback."
                ))
            }
        }
    }
}

fn probe_keychain() -> std::result::Result<(), String> {
    // Unique probe account per process: parallel mcp-shield processes must not
    // race on the same entry (one process's probe-delete would fail another's
    // probe-get and cascade into the vault fallback).
    let probe_account = format!("__mcp_shield_probe__{}", std::process::id());
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &probe_account)
        .map_err(|e| format!("entry init: {e:?}"))?;
    entry
        .set_password("probe")
        .map_err(|e| format!("set_password: {e:?}"))?;
    let got = entry
        .get_password()
        .map_err(|e| format!("get_password: {e:?}"))?;
    let _ = entry.delete_password();
    if got == "probe" {
        Ok(())
    } else {
        Err("keychain probe roundtrip mismatch".to_string())
    }
}

/// Map a placeholder value to the Keychain account name.
///
/// Current format: `mcp-shield://keychain/<config_id>/<server>/<KEY>` →
/// `<config_id>:<server>:<KEY>` (the config id namespaces accounts so two
/// config files can define the same server name without collision).
/// Legacy two-segment placeholders `<server>/<KEY>` → `<server>:<KEY>` are
/// still resolved for backwards compatibility.
pub fn placeholder_to_account(placeholder: &str) -> Option<String> {
    let rest = placeholder.strip_prefix(VAULT_PREFIX)?;
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.as_slice() {
        [server, key] if !server.is_empty() && !key.is_empty() => Some(format!("{server}:{key}")),
        [config_id, server, key]
            if !config_id.is_empty() && !server.is_empty() && !key.is_empty() =>
        {
            Some(format!("{config_id}:{server}:{key}"))
        }
        _ => None,
    }
}

/// Get (or create) the machine-local key used to encrypt `wrap` backups at
/// rest, so plaintext secrets never survive on disk next to the config.
/// The key itself lives in the secret store — never on disk.
pub fn backup_key(store: &dyn SecretStore) -> Result<[u8; 32], StoreError> {
    const ACCOUNT: &str = "__backup_key__";
    if let Ok(hex) = store.get(ACCOUNT) {
        if let Some(bytes) = crate::audit::hex_decode(&hex) {
            if let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Ok(key);
            }
        }
    }
    let key: [u8; 32] = rand_bytes();
    store.set(ACCOUNT, &crate::audit::hex_encode(&key))?;
    Ok(key)
}

/// Encrypt a file for at-rest backup: `nonce(12) || ciphertext`, AES-256-GCM.
pub fn encrypt_file(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
    use aes_gcm::aead::Aead;
    let nonce_bytes: [u8; 12] = rand_bytes();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher =
        Aes256Gcm::new_from_slice(key.as_slice()).map_err(|e| StoreError::Vault(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| StoreError::Vault(format!("backup encryption failed: {e}")))?;
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a backup written by `encrypt_file`. Fails for legacy plaintext
/// backups (callers fall back to a raw copy).
pub fn decrypt_file(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, StoreError> {
    use aes_gcm::aead::Aead;
    if blob.len() < 13 {
        return Err(StoreError::Vault("not an encrypted backup".to_string()));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher =
        Aes256Gcm::new_from_slice(key.as_slice()).map_err(|e| StoreError::Vault(e.to_string()))?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| StoreError::Vault("backup decryption failed".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_mapping() {
        assert_eq!(
            placeholder_to_account("mcp-shield://keychain/postgres/DATABASE_URL"),
            Some("postgres:DATABASE_URL".to_string())
        );
        // Namespaced (config_id) form.
        assert_eq!(
            placeholder_to_account("mcp-shield://keychain/a1b2c3d4/postgres/DATABASE_URL"),
            Some("a1b2c3d4:postgres:DATABASE_URL".to_string())
        );
        assert_eq!(
            placeholder_to_account("mcp-shield://keychain/novalue"),
            None
        );
        assert_eq!(placeholder_to_account("mcp-shield://keychain//x/y"), None);
        assert_eq!(placeholder_to_account("plain-value"), None);
    }

    #[test]
    fn file_vault_roundtrip() {
        // Isolated vault + password via env; run serially with other vault users
        // by using a unique home per test run.
        let unique = uuid::Uuid::new_v4().to_string();
        let home = std::env::temp_dir().join(format!("mcp-shield-vault-test-{unique}"));
        std::env::set_var("MCP_SHIELD_HOME", &home);
        std::env::set_var(VAULT_ENV_PASSWORD, "test-password-123");
        {
            let vault = FileVault::open().unwrap();
            vault.set("server:KEY", "top-secret-value").unwrap();
            assert_eq!(vault.get("server:KEY").unwrap(), "top-secret-value");
            vault.delete("server:KEY").unwrap();
            assert!(matches!(vault.get("server:KEY"), Err(StoreError::NotFound)));
        }
        // Wrong password must fail decryption.
        std::env::set_var(VAULT_ENV_PASSWORD, "wrong-password");
        let result = FileVault::open();
        if let Ok(vault) = result {
            assert!(vault.get("server:KEY").is_err());
        }
        std::env::remove_var("MCP_SHIELD_HOME");
        std::env::remove_var(VAULT_ENV_PASSWORD);
        std::fs::remove_dir_all(&home).ok();
    }

    /// Guard the helper types against accidental trait drift.
    #[test]
    fn store_is_object_safe() {
        fn assert_obj(_: &dyn SecretStore) {}
        let _ = assert_obj;
        let mut map: std::collections::BTreeMap<String, Box<dyn SecretStore>> =
            std::collections::BTreeMap::new();
        map.insert("k".to_string(), Box::new(KeychainStore));
        assert_eq!(map["k"].backend_name(), "os-keychain");
    }
}
