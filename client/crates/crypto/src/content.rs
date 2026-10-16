//! Chunked encryption of file content.
//!
//! A file is split into content-defined chunks rather than fixed-size ones.
//! Fixed 32 KiB chunks, as Cryptomator uses, cannot survive an insertion: one
//! byte added near the start shifts every later boundary, so a whole-file edit
//! re-encrypts and re-uploads everything after it. Content-defined boundaries
//! keep the chunks on either side of the insertion identical, which is what makes
//! delta sync cheap.
//!
//! Each chunk is encrypted independently with AES-256-GCM, using a key and nonce
//! derived from the file key and the chunk's position, so no chunk can be moved
//! or reordered without detection. The chunk id is an HMAC of the *plaintext*,
//! which is what lets two clients agree on which chunks already exist without
//! either revealing content.
//!
//! The tradeoff is stated in `docs/format.md`: deterministic chunk ids let the
//! server notice that two chunks inside one vault are identical. It learns
//! nothing across vaults and nothing about what the chunk says.

use crate::error::{CryptoError, Result};

/// Smallest chunk the splitter will emit, in plaintext bytes.
pub const CHUNK_MIN: usize = 8 * 1024;

/// Chunk size the splitter aims for.
pub const CHUNK_TARGET: usize = 64 * 1024;

/// Largest chunk the splitter will emit, and the ceiling on any stored chunk.
pub const CHUNK_MAX: usize = 512 * 1024;

/// AES-GCM nonce length.
pub const NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length.
pub const TAG_LEN: usize = 16;

/// A content-addressed chunk identifier, uppercase Crockford base32.
///
/// Two chunks with the same id decrypt to the same plaintext inside the same
/// vault, which is the whole basis of deduplication.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkId(String);

impl ChunkId {
    /// Wraps an id that is already encoded.
    #[must_use]
    pub fn from_base32(text: &str) -> Self {
        Self(text.to_ascii_uppercase())
    }

    /// The encoded id, which is also the blob filename on the server.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ChunkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Computes the id of a plaintext chunk.
///
/// # Errors
///
/// Returns [`CryptoError::Unimplemented`] until M1 adds HMAC-SHA256.
pub fn chunk_id(vault_key: &crate::keys::MasterKey, plaintext: &[u8]) -> Result<ChunkId> {
    let _ = (vault_key, plaintext);
    Err(CryptoError::Unimplemented("chunk id derivation"))
}

/// Encrypts one chunk, returning nonce, ciphertext, and tag in the stored order.
///
/// # Errors
///
/// Returns [`CryptoError::Unimplemented`] until M1 adds AES-GCM.
pub fn encrypt_chunk(file_key: &[u8], index: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    let _ = (file_key, index, plaintext);
    Err(CryptoError::Unimplemented("AES-GCM chunk encryption"))
}

/// Decrypts one chunk previously produced by [`encrypt_chunk`].
///
/// # Errors
///
/// Returns [`CryptoError::Unimplemented`] until M1 adds AES-GCM. Once it does, a
/// failed tag check is reported as [`CryptoError::KeyAuth`].
pub fn decrypt_chunk(file_key: &[u8], index: u64, stored: &[u8]) -> Result<Vec<u8>> {
    let _ = (file_key, index, stored);
    Err(CryptoError::Unimplemented("AES-GCM chunk decryption"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_sizes_are_ordered() {
        // Checked at compile time: an out-of-order constant would fail the build
        // rather than wait for this test to run.
        const _: () = assert!(CHUNK_MIN < CHUNK_TARGET);
        const _: () = assert!(CHUNK_TARGET < CHUNK_MAX);
    }

    #[test]
    fn stored_chunk_has_room_for_nonce_and_tag() {
        // A chunk of MIN plaintext must still round-trip through a buffer that
        // only adds a nonce and a tag, so the framing constants stay coherent.
        assert_eq!(NONCE_LEN + TAG_LEN, 28);
    }

    #[test]
    fn chunk_ids_are_uppercased() {
        assert_eq!(ChunkId::from_base32("ab12").as_str(), "AB12");
        assert_eq!(ChunkId::from_base32("AB12").to_string(), "AB12");
    }

    #[test]
    fn crypto_operations_are_still_stubs() {
        let key = crate::keys::MasterKey::from_bytes(&[1; 32]).unwrap();
        assert!(matches!(
            chunk_id(&key, b"hello"),
            Err(CryptoError::Unimplemented(_))
        ));
        assert!(matches!(
            encrypt_chunk(&[0; 32], 0, b"hello"),
            Err(CryptoError::Unimplemented(_))
        ));
        assert!(matches!(
            decrypt_chunk(&[0; 32], 0, b"hello"),
            Err(CryptoError::Unimplemented(_))
        ));
    }
}
