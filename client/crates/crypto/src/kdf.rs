//! Turning a user password into a key-encryption key.
//!
//! The password never encrypts anything directly. It derives a
//! [`Kek`], which unwraps the two [`super::MasterKey`]s stored in `vault.json`.
//! Because the parameters are recorded next to the wrapped keys, a vault stays
//! readable after the defaults are raised.

use zeroize::ZeroizeOnDrop;

use crate::error::{CryptoError, Result};

/// Smallest salt the format accepts.
pub const MIN_SALT_LEN: usize = 16;

/// Which key-derivation function produced a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// Argon2id. The only algorithm Syncbox writes.
    Argon2id,
}

impl Algorithm {
    /// Name as it appears in `vault.json`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Argon2id => "argon2id",
        }
    }

    /// Parses the name stored in `vault.json`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::UnsupportedAlgorithm`] for an algorithm this build
    /// does not implement.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "argon2id" => Ok(Self::Argon2id),
            other => Err(CryptoError::UnsupportedAlgorithm(other.to_owned())),
        }
    }
}

/// KDF parameters, recorded in `vault.json` beside the wrapped keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// KDF to run.
    pub algorithm: Algorithm,
    /// Memory cost, in kibibytes.
    pub memory_kib: u32,
    /// Passes over the memory block.
    pub iterations: u32,
    /// Lanes the derivation runs in parallel.
    pub parallelism: u32,
    /// Length of the derived key, in bytes.
    pub output_len: u32,
}

impl Default for Params {
    /// Roughly 64 MiB, three passes, four lanes: uncomfortable for an attacker
    /// with a GPU farm, quick enough to type a password into on a laptop.
    fn default() -> Self {
        Self {
            algorithm: Algorithm::Argon2id,
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 4,
            output_len: 32,
        }
    }
}

/// A key-encryption key derived from a password. Zeroized when dropped.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Kek {
    bytes: Vec<u8>,
}

/// Does not print the key material, so a failing test or a logged error cannot
/// leak a derived key.
impl std::fmt::Debug for Kek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Kek({} bytes)", self.bytes.len())
    }
}

impl Kek {
    /// Wraps key material that was derived elsewhere.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// The derived bytes. Treat them as secret.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Derives the key-encryption key for `password`.
///
/// `salt` must be a fresh random value per vault, at least [`MIN_SALT_LEN`]
/// bytes long.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidInput`] if the salt is too short, and
/// [`CryptoError::Unimplemented`] until M1 supplies the Argon2id backend.
pub fn derive_kek(password: &str, salt: &[u8], params: &Params) -> Result<Kek> {
    let _ = (password, params);
    if salt.len() < MIN_SALT_LEN {
        return Err(CryptoError::InvalidInput("salt shorter than 16 bytes"));
    }
    Err(CryptoError::Unimplemented("Argon2id key derivation"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_recorded_in_the_vault() {
        let params = Params::default();
        assert_eq!(params.algorithm, Algorithm::Argon2id);
        assert_eq!(params.memory_kib, 65536);
        assert_eq!(params.output_len, 32);
    }

    #[test]
    fn algorithm_names_round_trip() {
        assert_eq!(Algorithm::Argon2id.as_str(), "argon2id");
        assert_eq!(Algorithm::parse("argon2id").unwrap(), Algorithm::Argon2id);
        assert!(matches!(
            Algorithm::parse("scrypt"),
            Err(CryptoError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn short_salts_are_rejected_before_any_work() {
        let err = derive_kek("hunter2", b"too-short", &Params::default())
            .expect_err("a short salt must be rejected");
        assert!(matches!(err, CryptoError::InvalidInput(_)));
    }

    #[test]
    fn kek_zeroizes_on_drop() {
        // The derive in `Kek` guarantees this at compile time; this test keeps
        // the type from being quietly changed to something that does not.
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Kek>();
    }
}
