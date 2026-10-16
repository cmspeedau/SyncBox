//! Creating and unlocking a vault on disk.
//!
//! This is the one place the crate touches the filesystem. Everything below does
//! the same ceremony in reverse of the other: `create` generates keys, derives a
//! key-encryption key from the password, wraps the keys and their header MAC into
//! `vault.json`; `unlock` reads that header back, re-derives the key-encryption
//! key, checks the MAC, and only then unwraps the master keys.
//!
//! A wrong password is caught by the header MAC before any wrapped key is
//! decrypted, so `unlock` never hands out keys for a vault it could not honestly
//! open.

use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use syncbox_crypto::kdf::{derive_kek, Params, MIN_SALT_LEN};
use syncbox_crypto::keys::MasterKeys;
use syncbox_crypto::wrap::{header_mac, unwrap_master_keys, wrap_master_keys, GCM_NONCE_LEN};
use syncbox_crypto::CryptoError;

use crate::config::{Kdf, VaultConfig, CONFIG_FILE_NAME};
use crate::error::{Result, VaultError};

/// Creates a fresh vault in `root` and returns the master keys it generated.
///
/// `params` are recorded in the header verbatim, so raising the Argon2id cost
/// later never strands an existing vault. The caller keeps the returned keys in
/// memory; they are not written anywhere but wrapped under `password`.
///
/// # Errors
///
/// Returns [`VaultError::NotAVault`] if `root` already holds a `vault.json` (this
/// never overwrites an existing vault), [`VaultError::Crypto`] if derivation or
/// wrapping fails, and [`VaultError::Io`] on any filesystem failure.
pub fn create(root: &Path, password: &str, params: &Params) -> Result<MasterKeys> {
    let config_path = root.join(CONFIG_FILE_NAME);
    if config_path.exists() {
        return Err(VaultError::NotAVault(format!(
            "{} already exists — refusing to overwrite a vault",
            config_path.display()
        )));
    }
    std::fs::create_dir_all(root)?;

    let salt = random_bytes(MIN_SALT_LEN)?;
    let kek = derive_kek(password, &salt, params)?;
    let keys = MasterKeys::generate()?;
    let wrap_nonce = random_bytes(GCM_NONCE_LEN)?;
    let (wrapped_primary, wrapped_hmac) = wrap_master_keys(&kek, &keys, &wrap_nonce)?;

    // Build the header with an empty MAC, compute the MAC over the header's own
    // canonical bytes, then fill it in. The MAC is deliberately not part of the
    // bytes it covers.
    let mut config = VaultConfig::new(
        Kdf::new(params, &salt),
        &wrap_nonce,
        &wrapped_primary,
        &wrapped_hmac,
        &[],
    );
    config.version_mac = BASE64.encode(header_mac(&kek, &canonical_header(&config))?);

    write_config(&config_path, &config)?;
    Ok(keys)
}

/// Opens the vault in `root`, returning its master keys.
///
/// # Errors
///
/// [`VaultError::NotAVault`] if there is no header to read, [`VaultError::NewerVersion`]
/// or [`VaultError::InvalidHeader`] for an unreadable header, and
/// [`VaultError::Crypto`] with [`CryptoError::KeyAuth`] when `password` is wrong or
/// the header was tampered with.
pub fn unlock(root: &Path, password: &str) -> Result<MasterKeys> {
    let config_path = root.join(CONFIG_FILE_NAME);
    if !config_path.is_file() {
        return Err(VaultError::NotAVault(format!(
            "no {} in {}",
            CONFIG_FILE_NAME,
            root.display()
        )));
    }
    let config = read_config(&config_path)?;
    config.check_version()?;

    let params = config.kdf.to_params()?;
    let salt = config.kdf.salt_bytes()?;
    let kek = derive_kek(password, &salt, &params)?;

    let wrap_nonce = config.decode_field(&config.wrap_nonce)?;
    let wrapped_primary = config.decode_field(&config.wrapped_primary)?;
    let wrapped_hmac = config.decode_field(&config.wrapped_hmac)?;
    let stored_mac = config.decode_field(&config.version_mac)?;

    // Reject a wrong password on the MAC alone, before spending a decryption on
    // keys we should not hand back.
    let expected_mac = header_mac(&kek, &canonical_header(&config))?;
    if expected_mac != stored_mac {
        return Err(VaultError::Crypto(CryptoError::KeyAuth));
    }

    Ok(unwrap_master_keys(
        &kek,
        &wrap_nonce,
        &wrapped_primary,
        &wrapped_hmac,
    )?)
}

/// The bytes the header MAC covers: every header field except `version_mac`,
/// rendered so no two different headers share a rendering.
///
/// Strings are length-prefixed and the base64 fields are used exactly as stored,
/// so recomputing over a re-parsed header gives the same bytes it was created
/// over. Fixed-size integers are big-endian; the field order matches the header.
fn canonical_header(config: &VaultConfig) -> Vec<u8> {
    let kdf = &config.kdf;
    let mut out = Vec::new();
    out.extend_from_slice(&config.version.to_be_bytes());
    push_str(&mut out, &kdf.algorithm);
    out.extend_from_slice(&kdf.memory_kib.to_be_bytes());
    out.extend_from_slice(&kdf.iterations.to_be_bytes());
    out.extend_from_slice(&kdf.parallelism.to_be_bytes());
    out.extend_from_slice(&kdf.output_len.to_be_bytes());
    push_str(&mut out, &kdf.salt);
    push_str(&mut out, &config.wrap_nonce);
    push_str(&mut out, &config.wrapped_primary);
    push_str(&mut out, &config.wrapped_hmac);
    out
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| VaultError::Crypto(CryptoError::Backend("operating-system entropy source")))?;
    Ok(bytes)
}

fn write_config(path: &Path, config: &VaultConfig) -> Result<()> {
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;
    std::fs::write(path, json)?;
    Ok(())
}

fn read_config(path: &Path) -> Result<VaultConfig> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| VaultError::InvalidHeader("vault.json is not valid header JSON"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use syncbox_crypto::kdf::Algorithm;

    /// Cheap parameters so the create/unlock tests do not each pay 64 MiB.
    fn test_params() -> Params {
        Params {
            algorithm: Algorithm::Argon2id,
            memory_kib: 4096,
            iterations: 2,
            parallelism: 1,
            output_len: 32,
        }
    }

    #[test]
    fn a_created_vault_unlocks_with_the_same_keys() {
        let dir = tempfile::tempdir().unwrap();
        let keys = create(dir.path(), "correct horse", &test_params()).unwrap();
        let unlocked = unlock(dir.path(), "correct horse").unwrap();
        assert_eq!(unlocked.primary.as_bytes(), keys.primary.as_bytes());
        assert_eq!(unlocked.hmac.as_bytes(), keys.hmac.as_bytes());
    }

    #[test]
    fn the_header_never_contains_a_master_key() {
        let dir = tempfile::tempdir().unwrap();
        let keys = create(dir.path(), "password", &test_params()).unwrap();
        let raw = std::fs::read(dir.path().join(CONFIG_FILE_NAME)).unwrap();
        // The primary key must not appear, in raw or base64 form, anywhere in it.
        assert!(find_subsequence(&raw, keys.primary.as_bytes()).is_none());
        assert!(
            find_subsequence(&raw, BASE64.encode(keys.primary.as_bytes()).as_bytes()).is_none()
        );
    }

    #[test]
    fn a_wrong_password_is_rejected_before_unwrapping() {
        let dir = tempfile::tempdir().unwrap();
        create(dir.path(), "right", &test_params()).unwrap();
        let err = unlock(dir.path(), "wrong").expect_err("must refuse");
        assert!(matches!(err, VaultError::Crypto(CryptoError::KeyAuth)));
    }

    #[test]
    fn a_tampered_header_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        create(dir.path(), "password", &test_params()).unwrap();
        let path = dir.path().join(CONFIG_FILE_NAME);
        let mut config: VaultConfig =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        // Swap the wrapped primary key for another of the same shape; the MAC,
        // which covers that field, no longer matches.
        config.wrapped_primary = BASE64.encode([0u8; 48]);
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();

        let err = unlock(dir.path(), "password").expect_err("must refuse");
        assert!(matches!(err, VaultError::Crypto(CryptoError::KeyAuth)));
    }

    #[test]
    fn a_newer_format_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        create(dir.path(), "password", &test_params()).unwrap();
        let path = dir.path().join(CONFIG_FILE_NAME);
        let mut config: VaultConfig =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        config.version = crate::config::CURRENT_VERSION + 1;
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();

        let err = unlock(dir.path(), "password").expect_err("must refuse");
        assert!(matches!(err, VaultError::NewerVersion(_)));
    }

    #[test]
    fn creating_twice_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        create(dir.path(), "password", &test_params()).unwrap();
        let err = create(dir.path(), "password", &test_params()).expect_err("must refuse");
        assert!(matches!(err, VaultError::NotAVault(_)));
    }

    #[test]
    fn unlocking_a_plain_directory_says_it_is_not_a_vault() {
        let dir = tempfile::tempdir().unwrap();
        let err = unlock(dir.path(), "password").expect_err("nothing to open");
        assert!(matches!(err, VaultError::NotAVault(_)));
    }

    #[test]
    fn the_default_parameters_are_reachable_and_recorded() {
        // A vault made with the shipped defaults records them so it stays openable
        // after the defaults change. (One 64 MiB derivation; the only such test.)
        let dir = tempfile::tempdir().unwrap();
        create(dir.path(), "password", &Params::default()).unwrap();
        let raw = std::fs::read_to_string(dir.path().join(CONFIG_FILE_NAME)).unwrap();
        let config: VaultConfig = serde_json::from_str(&raw).unwrap();
        assert_eq!(config.kdf.to_params().unwrap(), Params::default());
    }

    #[test]
    fn canonical_header_excludes_the_mac_and_is_order_sensitive() {
        let mut config = VaultConfig::new(
            Kdf::new(&test_params(), &[1u8; 16]),
            &[2u8; 12],
            &[3u8; 32],
            &[4u8; 32],
            &[],
        );
        let before = canonical_header(&config);
        // Changing the MAC must not change the covered bytes...
        config.version_mac = BASE64.encode(b"mac");
        assert_eq!(canonical_header(&config), before);
        // ...but changing a covered field must.
        config.wrap_nonce = BASE64.encode([9u8; 12]);
        assert_ne!(canonical_header(&config), before);
    }

    /// Naive byte-subsequence search, enough to prove a key is absent from a
    /// small header file.
    fn find_subsequence(hay: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || needle.len() > hay.len() {
            return None;
        }
        (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
    }
}
