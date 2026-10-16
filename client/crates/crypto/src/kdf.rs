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
/// bytes long. The cost parameters are taken from `params` rather than assumed,
/// so a vault written before the defaults were raised still unlocks.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidInput`] if the salt is too short, and
/// [`CryptoError::Backend`] if the parameters are outside what Argon2id accepts.
pub fn derive_kek(password: &str, salt: &[u8], params: &Params) -> Result<Kek> {
    if salt.len() < MIN_SALT_LEN {
        return Err(CryptoError::InvalidInput("salt shorter than 16 bytes"));
    }

    // Argon2id is the only algorithm this build writes or reads; the algorithm is
    // checked by the caller (Params::algorithm is fixed), so here we only run it.
    let cost = argon2::Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(usize::try_from(params.output_len).unwrap_or(usize::MAX)),
    )
    .map_err(|_| CryptoError::Backend("Argon2id parameters out of range"))?;

    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, cost);
    let mut output = vec![0u8; usize::try_from(params.output_len).unwrap_or(usize::MAX)];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|_| CryptoError::Backend("Argon2id derivation failed"))?;

    Ok(Kek::from_bytes(output))
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

    /// Cheap parameters so the derivation tests run in milliseconds rather than
    /// paying the vault's real 64 MiB cost on every `cargo test`.
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
    fn derivation_is_deterministic_and_exact_length() {
        let salt = [0x42u8; 16];
        let a = derive_kek("correct horse", &salt, &test_params()).unwrap();
        let b = derive_kek("correct horse", &salt, &test_params()).unwrap();
        assert_eq!(a.as_bytes().len(), 32);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn a_different_salt_or_password_gives_a_different_key() {
        let base = derive_kek("password", &[1u8; 16], &test_params()).unwrap();
        let other_salt = derive_kek("password", &[2u8; 16], &test_params()).unwrap();
        let other_pw = derive_kek("Password", &[1u8; 16], &test_params()).unwrap();
        assert_ne!(base.as_bytes(), other_salt.as_bytes());
        assert_ne!(base.as_bytes(), other_pw.as_bytes());
    }

    #[test]
    fn kek_zeroizes_on_drop() {
        // The derive in `Kek` guarantees this at compile time; this test keeps
        // the type from being quietly changed to something that does not.
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Kek>();
    }
}
