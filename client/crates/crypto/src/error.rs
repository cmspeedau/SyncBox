//! Errors from Syncbox cryptographic operations.

use thiserror::Error;

/// Everything that can go wrong in this crate.
#[derive(Debug, Error)]
pub enum CryptoError {
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

    /// A cryptographic backend refused to run: bad parameters, a derivation
    /// length the primitive does not allow, or the OS entropy source failing.
    /// Distinct from [`CryptoError::KeyAuth`], which means bytes that decrypted
    /// but did not authenticate.
    #[error("cryptographic operation failed: {0}")]
    Backend(&'static str),
}

/// Result alias used across this crate.
pub type Result<T> = std::result::Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_carry_their_reason() {
        assert_eq!(
            CryptoError::UnsupportedVersion(2).to_string(),
            "unsupported vault format version 2"
        );
        assert_eq!(
            CryptoError::UnsupportedAlgorithm("scrypt".into()).to_string(),
            "unsupported key derivation algorithm \"scrypt\""
        );
        assert_eq!(
            CryptoError::KeyAuth.to_string(),
            "wrong password or corrupted vault header"
        );
    }
}
