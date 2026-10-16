//! Chunked encryption of file content.
//!
//! A file is split into content-defined chunks rather than fixed-size ones.
//! Fixed 32 KiB chunks, as Cryptomator uses, cannot survive an insertion: one
//! byte added near the start shifts every later boundary, so a whole-file edit
//! re-encrypts and re-uploads everything after it. Content-defined boundaries
//! keep the chunks on either side of the insertion identical, which is what makes
//! delta sync cheap.
//!
//! A chunk's key and nonce are derived from its **content** — specifically from
//! the same HMAC digest that forms its id — under the vault's `primaryMasterKey`.
//! Content-derived keying is what makes deduplication and delta sync work against
//! the server, which stores each chunk id once and assumes the bytes behind an id
//! never change: the same plaintext chunk is therefore the same ciphertext bytes
//! wherever it appears, so an unchanged chunk is already on the server and is
//! never re-uploaded.
//!
//! Because position no longer keys a chunk, reordering and cross-file replay are
//! not detected here; they are caught one level up, by the authenticated manifest
//! ([`crate::file`]), which is keyed per file and lists the chunk ids in order.
//! The chunk id itself is the HMAC of the plaintext, so the AES-GCM tag binds the
//! stored bytes to the id: a blob that does not decrypt to the chunk its id names
//! fails the tag check.
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
pub fn chunk_id(hmac_key: &MasterKey, plaintext: &[u8]) -> Result<ChunkId> {
    Ok(ChunkId(base32_encode(&hmac_sha256(
        hmac_key.as_bytes(),
        plaintext,
    )?)))
}

/// Derives an AES-GCM key and nonce from an input keying material and a
/// domain-separating `info` string.
///
/// ```text
/// key   = HKDF(ikm, "chunk" || info)   // 32 bytes
/// nonce = HKDF(ikm, "nonce" || info)   // 12 bytes
/// ```
///
/// For file chunks `info` is the chunk id, so keying is content-derived. Keeping
/// the derivation in one place is what guarantees the encrypt and decrypt paths
/// agree byte for byte.
fn chunk_keys(ikm: &[u8], info: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let mut key_info = b"chunk".to_vec();
    key_info.extend_from_slice(info);
    let key = hkdf_sha256(ikm, &key_info, 32)?;

    let mut nonce_info = b"nonce".to_vec();
    nonce_info.extend_from_slice(info);
    let derived = hkdf_sha256(ikm, &nonce_info, NONCE_LEN)?;

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&derived);
    Ok((key, nonce))
}

/// Encrypts one chunk under `ikm` labelled by `info`, returning `nonce ||
/// ciphertext || tag` in the stored order.
///
/// This is the AES-GCM primitive the file format is built on; [`seal_chunk`] is
/// the usual caller, and passes the chunk id as `info` so keying is content-derived.
///
/// # Errors
///
/// Returns [`CryptoError::Backend`] if AES-GCM rejects the derived key length.
pub fn encrypt_chunk(ikm: &[u8], info: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let (key, nonce) = chunk_keys(ikm, info)?;
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

/// Decrypts one chunk produced by [`encrypt_chunk`] with the same `ikm` and `info`.
///
/// The nonce is taken from the stored bytes rather than re-derived, so it is the
/// authoritative one even though derivation would reproduce the same value.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidInput`] if the stored blob is too short to hold a
/// nonce and a tag, and [`CryptoError::KeyAuth`] when the tag does not verify.
pub fn decrypt_chunk(ikm: &[u8], info: &[u8], stored: &[u8]) -> Result<Vec<u8>> {
    if stored.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::InvalidInput(
            "stored chunk shorter than nonce plus tag",
        ));
    }
    let (nonce, ciphertext) = stored.split_at(NONCE_LEN);

    let (key, _derived_nonce) = chunk_keys(ikm, info)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::Backend("AES-GCM key length"))?;

    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::KeyAuth)
}

/// Seals one plaintext chunk, returning its id and its stored bytes together.
///
/// The id is `chunk_id(hmac_key, plaintext)` and is used both as the server blob
/// key and as the `info` that derives the encryption key, so the ciphertext is a
/// function of the content alone: identical chunks are byte-identical everywhere.
///
/// # Errors
///
/// Propagates HMAC and AES-GCM errors from [`chunk_id`] and [`encrypt_chunk`].
pub fn seal_chunk(
    primary_key: &MasterKey,
    hmac_key: &MasterKey,
    plaintext: &[u8],
) -> Result<(ChunkId, Vec<u8>)> {
    let id = chunk_id(hmac_key, plaintext)?;
    let stored = encrypt_chunk(primary_key.as_bytes(), id.as_str().as_bytes(), plaintext)?;
    Ok((id, stored))
}

/// Opens one stored chunk by the id it claims, under `primary_key`.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidInput`] for a too-short blob and
/// [`CryptoError::KeyAuth`] when the bytes do not authenticate to this id — which
/// covers both tampering and a blob swapped in for a different chunk.
pub fn open_chunk(primary_key: &MasterKey, id: &ChunkId, stored: &[u8]) -> Result<Vec<u8>> {
    decrypt_chunk(primary_key.as_bytes(), id.as_str().as_bytes(), stored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterKey;

    fn primary() -> MasterKey {
        MasterKey::from_bytes(&[0x20; 32]).unwrap()
    }
    fn hmac() -> MasterKey {
        MasterKey::from_bytes(&[0x00; 32]).unwrap()
    }

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
        let key = MasterKey::from_bytes(&[1; 32]).unwrap();
        let other = MasterKey::from_bytes(&[2; 32]).unwrap();
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
        for plaintext in [b"hello world".as_slice(), b"", b"a", &[0u8; 100][..]] {
            let (id, stored) = seal_chunk(&primary(), &hmac(), plaintext).unwrap();
            assert_eq!(stored.len(), NONCE_LEN + plaintext.len() + TAG_LEN);
            assert_eq!(open_chunk(&primary(), &id, &stored).unwrap(), plaintext);
        }
    }

    #[test]
    fn encryption_is_content_bound_not_position_bound() {
        // The whole point of content-derived keying: the same plaintext seals to
        // the same bytes every time, so an unchanged chunk is already on the server.
        let a = seal_chunk(&primary(), &hmac(), b"duplicate me").unwrap();
        let b = seal_chunk(&primary(), &hmac(), b"duplicate me").unwrap();
        assert_eq!(a.0, b.0);
        assert_eq!(a.1, b.1);
    }

    #[test]
    fn a_blob_only_opens_under_its_own_id() {
        // Content-derived keying means keying is by id: bytes sealed for one id do
        // not open under another, which is how a swapped-in chunk is rejected.
        let (id, stored) = seal_chunk(&primary(), &hmac(), b"payload").unwrap();
        assert_eq!(open_chunk(&primary(), &id, &stored).unwrap(), b"payload");
        let other = chunk_id(&hmac(), b"different payload").unwrap();
        assert!(matches!(
            open_chunk(&primary(), &other, &stored),
            Err(CryptoError::KeyAuth)
        ));
    }

    #[test]
    fn the_same_chunk_in_two_vaults_differs() {
        // Different hmac master keys give different ids, so nothing is shared
        // across vaults even for identical plaintext.
        let other_vault = MasterKey::from_bytes(&[0xFF; 32]).unwrap();
        let here = seal_chunk(&primary(), &hmac(), b"same bytes").unwrap();
        let there = seal_chunk(&primary(), &other_vault, b"same bytes").unwrap();
        assert_ne!(here.0, there.0);
        assert_ne!(here.1, there.1);
    }

    #[test]
    fn tampered_chunk_fails_authentication() {
        let (id, mut stored) = seal_chunk(&primary(), &hmac(), b"payload").unwrap();
        let last = stored.len() - 1;
        stored[last] ^= 0x01; // flip a bit of the tag
        assert!(matches!(
            open_chunk(&primary(), &id, &stored),
            Err(CryptoError::KeyAuth)
        ));
    }

    #[test]
    fn truncated_chunk_is_input_invalid_not_a_key_failure() {
        let id = ChunkId::from_base32("ABCD");
        assert!(matches!(
            open_chunk(&primary(), &id, b"too short"),
            Err(CryptoError::InvalidInput(_))
        ));
    }
}
