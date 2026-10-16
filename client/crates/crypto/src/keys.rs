//! The master key hierarchy a vault unlocks to.

use zeroize::ZeroizeOnDrop;

use crate::error::{CryptoError, Result};

/// Length of every master key, in bytes.
pub const MASTER_KEY_LEN: usize = 32;

/// A 256-bit master key. Zeroized when dropped.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; MASTER_KEY_LEN],
}

/// Deliberately does not print the key. A key that shows up in a log line or a
/// test failure is a key that has been exposed.
impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

impl MasterKey {
    /// Takes key material that was unwrapped from `vault.json`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidInput`] unless `bytes` is exactly
    /// [`MASTER_KEY_LEN`] long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let fixed: [u8; MASTER_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidInput("master key is not 32 bytes"))?;
        Ok(Self { bytes: fixed })
    }

    /// Generates a master key from the operating system's CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Backend`] if the OS entropy source is unavailable,
    /// which on the supported platforms means a broken environment rather than
    /// anything the caller can fix.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; MASTER_KEY_LEN];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| CryptoError::Backend("operating-system entropy source"))?;
        Ok(Self { bytes })
    }

    /// The key bytes. Never log them and never store them unwrapped.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.bytes
    }
}

/// Both master keys of a vault, as Cryptomator also keeps.
///
/// Splitting them means a leaked directory-id key does not expose content, and
/// a ciphertext-only oracle cannot confirm a guessed directory id.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MasterKeys {
    /// Encrypts file content and filenames.
    pub primary: MasterKey,
    /// Derives directory ids and chunk ids.
    pub hmac: MasterKey,
}

/// Redacted, like [`MasterKey`]: a pair of master keys that prints is a pair that
/// leaked.
impl std::fmt::Debug for MasterKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKeys(<redacted>)")
    }
}

impl MasterKeys {
    /// Generates both keys from the CSPRNG.
    ///
    /// # Errors
    ///
    /// Propagates [`MasterKey::generate`].
    pub fn generate() -> Result<Self> {
        Ok(Self {
            primary: MasterKey::generate()?,
            hmac: MasterKey::generate()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_must_be_exactly_32_bytes() {
        assert!(MasterKey::from_bytes(&[0; 31]).is_err());
        assert!(MasterKey::from_bytes(&[0; 33]).is_err());
        let key = MasterKey::from_bytes(&[7; 32]).expect("32 bytes is valid");
        assert_eq!(key.as_bytes(), &[7; 32]);
    }

    #[test]
    fn wrong_length_errors_are_explainable() {
        let err = MasterKey::from_bytes(b"short").expect_err("too short");
        assert_eq!(err.to_string(), "invalid input: master key is not 32 bytes");
    }

    #[test]
    fn generated_keys_are_full_length_and_distinct() {
        let a = MasterKey::generate().expect("CSPRNG");
        let b = MasterKey::generate().expect("CSPRNG");
        assert_eq!(a.as_bytes().len(), MASTER_KEY_LEN);
        // Two CSPRNG draws colliding is the failure mode worth a test for; the
        // chance of a false failure here is 1 in 2^256.
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn generated_pair_is_two_independent_keys() {
        let keys = MasterKeys::generate().expect("CSPRNG");
        assert_ne!(keys.primary.as_bytes(), keys.hmac.as_bytes());
    }
}
