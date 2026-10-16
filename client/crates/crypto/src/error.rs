//! Errors from Syncbox cryptographic operations.

use thiserror::Error;

/// Everything that can go wrong in this crate.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The operation is part of the intended API but is not implemented yet.
    /// Every such call names itself, so a half-built vault cannot pretend to
    /// have finished.
    #[error("{0} is not implemented yet")]
    Unimplemented(&'static str),

    /// The wrapped master keys did not authenticate, which means either the
    /// password is wrong or `vault.json` has been tampered with.
    #[error("wrong password or corrupted vault header")]
    KeyAuth,

    /// `vault.json` names a format version this build cannot handle.
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u32),

    /// `vault.json` names a key-derivation algorithm this build cannot run.
    #[error("unsupported key derivation algorithm {0:?}")]
    UnsupportedAlgorithm(String),

    /// Input was too short, too long, or otherwise malformed.
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
}

/// Result alias used across this crate.
pub type Result<T> = std::result::Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_carry_their_reason() {
        assert_eq!(
            CryptoError::Unimplemented("Argon2id key derivation").to_string(),
            "Argon2id key derivation is not implemented yet"
        );
        assert_eq!(
            CryptoError::UnsupportedVersion(2).to_string(),
            "unsupported vault format version 2"
        );
        assert_eq!(
            CryptoError::UnsupportedAlgorithm("scrypt".into()).to_string(),
            "unsupported key derivation algorithm \"scrypt\""
        );
    }
}
