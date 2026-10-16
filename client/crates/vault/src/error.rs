//! Errors from reading and writing a vault on disk.

use thiserror::Error;

/// Everything that can go wrong in this crate.
#[derive(Debug, Error)]
pub enum VaultError {
    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] syncbox_crypto::CryptoError),

    /// The filesystem refused us.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The directory does not look like a vault.
    #[error("not a Syncbox vault: {0}")]
    NotAVault(String),

    /// `vault.json` is newer than this build understands. Refusing to open is
    /// safer than guessing at a format we have not seen.
    #[error("vault was written by a newer Syncbox (format version {0})")]
    NewerVersion(u32),

    /// `vault.json` was present but unreadable as a header.
    #[error("invalid vault header: {0}")]
    InvalidHeader(&'static str),
}

/// Result alias used across this crate.
pub type Result<T> = std::result::Result<T, VaultError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_newer_vault_explains_itself() {
        let err = VaultError::NewerVersion(2);
        assert_eq!(
            err.to_string(),
            "vault was written by a newer Syncbox (format version 2)"
        );
    }

    #[test]
    fn crypto_errors_pass_through_unchanged() {
        let crypto = syncbox_crypto::CryptoError::KeyAuth;
        let err: VaultError = crypto.into();
        assert_eq!(err.to_string(), "wrong password or corrupted vault header");
    }
}
