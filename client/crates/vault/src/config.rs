//! The `vault.json` header: how a vault records its parameters and its wrapped
//! master keys.
//!
//! Every field a future version needs to read this vault is in here, including
//! the KDF parameters. Raising the cost of Argon2id later must not be able to
//! strand an existing vault, so the values that were used are written down rather
//! than assumed.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use syncbox_crypto::kdf::{Algorithm, Params};

use crate::error::{Result, VaultError};

/// The header file's name inside a vault directory.
pub const CONFIG_FILE_NAME: &str = "vault.json";

/// The format version this build writes.
pub const CURRENT_VERSION: u32 = 1;

/// Contents of `vault.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    /// Format version this vault was written with.
    pub version: u32,
    /// Parameters needed to derive the key-encryption key.
    pub kdf: Kdf,
    /// Nonce used with the wrap, base64.
    pub wrap_nonce: String,
    /// `primaryMasterKey` wrapped under the key-encryption key, base64.
    pub wrapped_primary: String,
    /// `hmacMasterKey` wrapped under the key-encryption key, base64.
    pub wrapped_hmac: String,
    /// Tag over the header, so a wrong password is noticed before any file is
    /// decrypted against the wrong key, base64.
    pub version_mac: String,
}

impl VaultConfig {
    /// Builds a header for the current format version.
    #[must_use]
    pub fn new(
        kdf: Kdf,
        wrap_nonce: &[u8],
        wrapped_primary: &[u8],
        wrapped_hmac: &[u8],
        version_mac: &[u8],
    ) -> Self {
        Self {
            version: CURRENT_VERSION,
            kdf,
            wrap_nonce: BASE64.encode(wrap_nonce),
            wrapped_primary: BASE64.encode(wrapped_primary),
            wrapped_hmac: BASE64.encode(wrapped_hmac),
            version_mac: BASE64.encode(version_mac),
        }
    }

    /// Refuses vaults written by a newer format.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::NewerVersion`] when `version` is ahead of
    /// [`CURRENT_VERSION`].
    pub fn check_version(&self) -> Result<()> {
        if self.version > CURRENT_VERSION {
            return Err(VaultError::NewerVersion(self.version));
        }
        Ok(())
    }

    /// Decodes a base64 field.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidHeader`] if the field is not valid base64.
    pub fn decode_field(&self, field: &str) -> Result<Vec<u8>> {
        BASE64
            .decode(field)
            .map_err(|_| VaultError::InvalidHeader("field is not valid base64"))
    }
}

/// KDF parameters as stored, mirroring [`Params`] in base64-safe types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kdf {
    /// Algorithm name, currently always `"argon2id"`.
    pub algorithm: String,
    /// Memory cost in kibibytes.
    pub memory_kib: u32,
    /// Passes over the memory block.
    pub iterations: u32,
    /// Lanes the derivation runs in.
    pub parallelism: u32,
    /// Derived key length in bytes.
    pub output_len: u32,
    /// Per-vault random salt, base64.
    pub salt: String,
}

impl Kdf {
    /// Captures `params` and `salt` for storage.
    #[must_use]
    pub fn new(params: &Params, salt: &[u8]) -> Self {
        Self {
            algorithm: params.algorithm.as_str().to_owned(),
            memory_kib: params.memory_kib,
            iterations: params.iterations,
            parallelism: params.parallelism,
            output_len: params.output_len,
            salt: BASE64.encode(salt),
        }
    }

    /// Reads the stored parameters back as crypto types.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Crypto`] with
    /// [`syncbox_crypto::CryptoError::UnsupportedAlgorithm`] for an unknown
    /// algorithm, and [`VaultError::InvalidHeader`] for a bad salt.
    pub fn to_params(&self) -> Result<Params> {
        let salt = self.salt_bytes()?;
        if salt.len() < syncbox_crypto::kdf::MIN_SALT_LEN {
            return Err(VaultError::InvalidHeader("salt is too short"));
        }
        Ok(Params {
            algorithm: Algorithm::parse(&self.algorithm)?,
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
            output_len: self.output_len,
        })
    }

    /// Decodes the stored salt.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::InvalidHeader`] if the salt is not valid base64.
    pub fn salt_bytes(&self) -> Result<Vec<u8>> {
        BASE64
            .decode(&self.salt)
            .map_err(|_| VaultError::InvalidHeader("salt is not valid base64"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VaultConfig {
        VaultConfig::new(
            Kdf::new(&Params::default(), &[9u8; 16]),
            &[1u8; 12],
            &[2u8; 32],
            &[3u8; 32],
            &[4u8; 32],
        )
    }

    #[test]
    fn a_fresh_header_is_at_the_current_version() {
        let config = sample();
        assert_eq!(config.version, CURRENT_VERSION);
        config.check_version().expect("fresh header is readable");
    }

    #[test]
    fn a_newer_vault_is_refused() {
        let mut config = sample();
        config.version = CURRENT_VERSION + 1;
        let err = config.check_version().expect_err("must refuse");
        assert!(matches!(err, VaultError::NewerVersion(v) if v == CURRENT_VERSION + 1));
    }

    #[test]
    fn kdf_parameters_survive_a_round_trip() {
        let params = Params::default();
        let stored = Kdf::new(&params, &[7u8; 16]);
        let loaded = stored.to_params().expect("round trip");
        assert_eq!(loaded, params);
    }

    #[test]
    fn an_unknown_algorithm_is_reported_not_panic() {
        let mut stored = Kdf::new(&Params::default(), &[7u8; 16]);
        stored.algorithm = "scrypt".into();
        let err = stored.to_params().expect_err("must refuse");
        assert!(matches!(
            err,
            VaultError::Crypto(syncbox_crypto::CryptoError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn a_truncated_salt_is_rejected() {
        let mut stored = Kdf::new(&Params::default(), &[7u8; 4]);
        stored.salt = BASE64.encode(b"short");
        let err = stored.to_params().expect_err("must refuse");
        assert!(matches!(err, VaultError::InvalidHeader(_)));
    }

    #[test]
    fn header_fields_decode() {
        let config = sample();
        let nonce = config
            .decode_field(&config.wrap_nonce)
            .expect("valid base64");
        assert_eq!(nonce, vec![1u8; 12]);
        let err = config
            .decode_field("not base64!!")
            .expect_err("invalid base64");
        assert!(matches!(err, VaultError::InvalidHeader(_)));
    }
}
