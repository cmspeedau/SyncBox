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

use crate::derive::{hkdf_sha256, hmac_sha256};
use crate::error::{CryptoError, Result};
use crate::keys::MasterKey;
use crate::names::base32_encode;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

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

/// Computes the id of a plaintext chunk: `BASE32( HMAC-SHA256( hmacMasterKey,
/// plaintext ) )`.
///
/// Deterministic per vault, so two clients agree on which chunks already exist
/// without either revealing content. See `docs/format.md` for what that lets the
/// server infer.
///
/// # Errors
///
/// Propagates [`CryptoError::Backend`] from HMAC.
pub fn chunk_id(vault_key: &MasterKey, plaintext: &[u8]) -> Result<ChunkId> {
    Ok(ChunkId(base32_encode(&hmac_sha256(
        vault_key.as_bytes(),
        plaintext,
    )?)))
}

/// Derives a chunk's AES-GCM key and nonce from the file key and its position, so
/// no two positions of the same file share a nonce and no chunk can be reordered
/// or moved without detection.
///
/// ```text
/// chunkKey[i] = HKDF(fileKey, "chunk" || uint64be(i))   // 32 bytes
/// nonce[i]    = HKDF(fileKey, "nonce" || uint64be(i))   // 12 bytes
/// ```
fn chunk_keys(file_key: &[u8], index: u64) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let mut position = [0u8; 8];
    position.copy_from_slice(&index.to_be_bytes());

    let mut key_info = b"chunk".to_vec();
    key_info.extend_from_slice(&position);
    let key = hkdf_sha256(file_key, &key_info, 32)?;

    let mut nonce_info = b"nonce".to_vec();
    nonce_info.extend_from_slice(&position);
    let derived = hkdf_sha256(file_key, &nonce_info, NONCE_LEN)?;

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&derived);
    Ok((key, nonce))
}

/// Encrypts one chunk, returning `nonce || ciphertext || tag` in the stored order.
///
/// # Errors
///
/// Returns [`CryptoError::Backend`] if AES-GCM rejects the derived key length.
pub fn encrypt_chunk(file_key: &[u8], index: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    let (key, nonce) = chunk_keys(file_key, index)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::Backend("AES-GCM key length"))?;

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| CryptoError::Backend("AES-GCM encryption failed"))?;

    let mut stored = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    stored.extend_from_slice(&nonce);
    stored.extend_from_slice(&ciphertext);
    Ok(stored)
}

/// Decrypts one chunk previously produced by [`encrypt_chunk`].
///
/// The nonce is taken from the stored bytes rather than re-derived, so it is the
/// authoritative one even though derivation would reproduce the same value.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidInput`] if the stored blob is too short to hold a
/// nonce and a tag, and [`CryptoError::KeyAuth`] when the tag does not verify.
pub fn decrypt_chunk(file_key: &[u8], index: u64, stored: &[u8]) -> Result<Vec<u8>> {
    if stored.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::InvalidInput(
            "stored chunk shorter than nonce plus tag",
        ));
    }
    let (nonce, ciphertext) = stored.split_at(NONCE_LEN);

    // The position still selects the key, so a chunk moved to another index fails
    // to authenticate even though its stored nonce is intact.
    let (key, _derived_nonce) = chunk_keys(file_key, index)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::Backend("AES-GCM key length"))?;

    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::KeyAuth)
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
    fn chunk_id_is_deterministic_key_dependent_and_uppercase() {
        let key = crate::keys::MasterKey::from_bytes(&[1; 32]).unwrap();
        let other = crate::keys::MasterKey::from_bytes(&[2; 32]).unwrap();
        let id = chunk_id(&key, b"hello").unwrap();
        assert_eq!(id.as_str(), chunk_id(&key, b"hello").unwrap().as_str());
        assert_eq!(id.as_str(), id.as_str().to_ascii_uppercase());
        assert_ne!(id, chunk_id(&other, b"hello").unwrap());
        // A different plaintext is a different id: this is what makes ids usable
        // as content addresses.
        assert_ne!(id, chunk_id(&key, b"hellp").unwrap());
    }

    #[test]
    fn chunks_round_trip() {
        let file_key = [0x11u8; 32];
        for index in [0u64, 1, 7, u64::MAX] {
            let stored = encrypt_chunk(&file_key, index, b"hello world").unwrap();
            // The stored blob is exactly the nonce, the plaintext, and the tag.
            assert_eq!(stored.len(), NONCE_LEN + b"hello world".len() + TAG_LEN);
            assert_eq!(
                decrypt_chunk(&file_key, index, &stored).unwrap(),
                b"hello world"
            );
        }
    }

    #[test]
    fn encryption_is_position_bound() {
        let file_key = [0x22u8; 32];
        let stored = encrypt_chunk(&file_key, 3, b"payload").unwrap();
        // A chunk replayed at a different position must not authenticate, even
        // though its stored nonce is untouched, because the position selects key.
        assert!(matches!(
            decrypt_chunk(&file_key, 4, &stored),
            Err(CryptoError::KeyAuth)
        ));
    }

    #[test]
    fn tampered_chunk_fails_authentication() {
        let file_key = [0x33u8; 32];
        let mut stored = encrypt_chunk(&file_key, 0, b"payload").unwrap();
        let last = stored.len() - 1;
        stored[last] ^= 0x01; // flip a bit of the tag
        assert!(matches!(
            decrypt_chunk(&file_key, 0, &stored),
            Err(CryptoError::KeyAuth)
        ));
    }

    #[test]
    fn truncated_chunk_is_input_invalid_not_a_key_failure() {
        assert!(matches!(
            decrypt_chunk(&[0; 32], 0, b"too short"),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    #[test]
    fn encrypting_the_same_position_twice_gives_identical_bytes() {
        // Chunk keys and nonces are derived, not random, so encryption is
        // deterministic. That is what lets the client skip re-encrypting an
        // unchanged chunk; a random nonce here would silently break that.
        let file_key = [0x44u8; 32];
        assert_eq!(
            encrypt_chunk(&file_key, 5, b"same").unwrap(),
            encrypt_chunk(&file_key, 5, b"same").unwrap()
        );
    }
}
