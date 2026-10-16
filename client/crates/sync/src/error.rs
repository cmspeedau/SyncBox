//! Errors from the sync engine.

use thiserror::Error;

/// Everything that can go wrong in this crate.
#[derive(Debug, Error)]
pub enum SyncError {
    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] syncbox_crypto::CryptoError),

    /// The filesystem refused us.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Talking to the server failed.
    #[error(transparent)]
    Transport(#[from] syncbox_transport::TransportError),

    /// Decrypted content did not match what the metadata promised.
    #[error("integrity check failed: {0}")]
    Integrity(&'static str),

    /// A chunk was larger than the format allows, which means the splitter and
    /// the format disagree.
    #[error("chunk of {actual} bytes exceeds the {limit} byte limit")]
    ChunkTooLarge {
        /// Size the splitter produced.
        actual: usize,
        /// Size the format allows.
        limit: usize,
    },

    /// The server refused a request and said why.
    #[error("server refused the request: {reason}")]
    Server {
        /// Message from the server.
        reason: String,
    },
}

/// Result alias used across this crate.
pub type Result<T> = std::result::Result<T, SyncError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_oversized_chunk_names_both_numbers() {
        let err = SyncError::ChunkTooLarge {
            actual: 900_000,
            limit: 524_288,
        };
        assert_eq!(
            err.to_string(),
            "chunk of 900000 bytes exceeds the 524288 byte limit"
        );
    }

    #[test]
    fn crypto_errors_pass_through() {
        let err: SyncError = syncbox_crypto::CryptoError::KeyAuth.into();
        assert_eq!(err.to_string(), "wrong password or corrupted vault header");
    }
}
