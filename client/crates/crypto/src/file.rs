//! The per-file manifest: what a Syncbox file stores besides its chunks.
//!
//! A file's content is a list of content-addressed chunks, but the chunks alone do
//! not say which chunks belong to *this* file or in what order — the manifest does.
//! It records the chunk ids in order, each chunk's stored length, and the plaintext
//! size, and it is encrypted and authenticated under a per-file key, so the server
//! sees only an opaque blob and cannot reorder, truncate, or splice chunks without
//! the tag failing. This is where reordering and replay protection live now that
//! chunk keying is content-derived ([`crate::content`]).
//!
//! The per-file key is derived, not stored: `fileKey = HKDF(primaryMasterKey,
//! "file" || dirId || cipherName)`. Everything it depends on is available to a
//! client that has unlocked the vault and holds the file's revision (`dirId` and
//! the encrypted name are on the revision), so a manifest can always be decrypted
//! without keeping a key anywhere. Because a rename changes the encrypted name, it
//! changes the key, which is consistent with the whole-tree rule that a rename
//! re-keys a file.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::content::{ChunkId, NONCE_LEN, TAG_LEN};
use crate::derive::hkdf_sha256;
use crate::error::{CryptoError, Result};
use crate::keys::MasterKey;
use crate::names::DirId;

/// The key length a file manifest is encrypted under.
const FILE_KEY_LEN: usize = 32;

/// One chunk as recorded in a manifest: its id and how many stored bytes it occupies
/// (`nonce || ciphertext || tag`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkEntry {
    /// The content-addressed chunk id.
    pub id: ChunkId,
    /// Stored length in bytes, so a reader knows the chunk's extent without the
    /// server telling it anything.
    pub stored_len: u32,
}

/// A decoded file manifest: the ordered chunks and the plaintext size they spell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// Total plaintext bytes, so a zero-length and an empty-list file are
    /// distinguishable and a reader can size its output buffer.
    pub plaintext_size: u64,
    /// Chunk ids in file order.
    pub chunks: Vec<ChunkEntry>,
}

impl Manifest {
    /// An empty file's manifest: no chunks, zero bytes.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            plaintext_size: 0,
            chunks: Vec::new(),
        }
    }
}

/// The on-disk / on-wire shape of a manifest. Kept separate from [`Manifest`] so the
/// encrypted payload has an explicit version and base32-string ids.
#[derive(Serialize, Deserialize)]
struct ManifestPayload {
    /// Manifest format version.
    v: u8,
    size: u64,
    chunks: Vec<ChunkRecord>,
}

#[derive(Serialize, Deserialize)]
struct ChunkRecord {
    id: String,
    len: u32,
}

/// Derives a file's key from the primary master key and the file's identity within
/// the tree: `HKDF(primaryMasterKey, "file" || dirId || "\n" || cipherName)`.
///
/// `cipher_name` is the encrypted name without the `.c9r` suffix. Both `dirId` and
/// `cipherName` are Crockford base32 (never containing a newline), so the separator
/// is unambiguous.
///
/// # Errors
///
/// Propagates [`CryptoError::Backend`] from HKDF.
pub fn file_key(primary_key: &MasterKey, dir: &DirId, cipher_name: &str) -> Result<Vec<u8>> {
    let mut info = b"file".to_vec();
    info.extend_from_slice(dir.as_str().as_bytes());
    info.push(b'\n');
    info.extend_from_slice(cipher_name.as_bytes());
    hkdf_sha256(primary_key.as_bytes(), &info, FILE_KEY_LEN)
}

/// Encrypts a manifest under the file's key, returning `nonce || ciphertext || tag`.
///
/// The nonce is derived from the file key and the manifest bytes, so an unchanged
/// file re-encodes to identical bytes while any edit changes the nonce — reusing a
/// nonce across two different manifests never happens.
///
/// # Errors
///
/// Returns [`CryptoError::Backend`] if AES-GCM refuses to run or the manifest cannot
/// be serialised.
pub fn encode_manifest(
    primary_key: &MasterKey,
    dir: &DirId,
    cipher_name: &str,
    manifest: &Manifest,
) -> Result<Vec<u8>> {
    let key = file_key(primary_key, dir, cipher_name)?;

    let payload = ManifestPayload {
        v: 1,
        size: manifest.plaintext_size,
        chunks: manifest
            .chunks
            .iter()
            .map(|c| ChunkRecord {
                id: c.id.as_str().to_owned(),
                len: c.stored_len,
            })
            .collect(),
    };
    let plaintext =
        serde_json::to_vec(&payload).map_err(|_| CryptoError::Backend("manifest serialise"))?;

    // Content-derived nonce: distinct manifests under the same file key (an edit)
    // get distinct nonces, so the file key is safe to reuse across revisions.
    let mut hasher = Sha256::new();
    hasher.update(&plaintext);
    let mut nonce_info = b"manifest".to_vec();
    nonce_info.extend_from_slice(&hasher.finalize());
    let derived = hkdf_sha256(&key, &nonce_info, NONCE_LEN)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&derived);

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::Backend("manifest key length"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), &plaintext[..])
        .map_err(|_| CryptoError::Backend("manifest encryption failed"))?;

    let mut stored = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    stored.extend_from_slice(&nonce);
    stored.extend_from_slice(&ciphertext);
    Ok(stored)
}

/// Decrypts and authenticates a manifest produced by [`encode_manifest`].
///
/// # Errors
///
/// Returns [`CryptoError::InvalidInput`] if the blob is too short or does not
/// deserialise, and [`CryptoError::KeyAuth`] when the tag does not verify — the
/// wrong file identity, a tampered blob, or a manifest spliced from another file.
pub fn decode_manifest(
    primary_key: &MasterKey,
    dir: &DirId,
    cipher_name: &str,
    stored: &[u8],
) -> Result<Manifest> {
    if stored.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::InvalidInput(
            "manifest shorter than nonce plus tag",
        ));
    }
    let key = file_key(primary_key, dir, cipher_name)?;
    let (nonce, ciphertext) = stored.split_at(NONCE_LEN);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::Backend("manifest key length"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::KeyAuth)?;

    let payload: ManifestPayload = serde_json::from_slice(&plaintext)
        .map_err(|_| CryptoError::InvalidInput("manifest json"))?;
    if payload.v != 1 {
        return Err(CryptoError::InvalidInput("unsupported manifest version"));
    }
    Ok(Manifest {
        plaintext_size: payload.size,
        chunks: payload
            .chunks
            .into_iter()
            .map(|c| ChunkEntry {
                id: ChunkId::from_base32(&c.id),
                stored_len: c.len,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterKey;

    fn primary() -> MasterKey {
        MasterKey::from_bytes(&[0x20; 32]).unwrap()
    }

    fn sample_manifest() -> Manifest {
        Manifest {
            plaintext_size: 1_000_000,
            chunks: vec![
                ChunkEntry {
                    id: ChunkId::from_base32("AAAAAAA"),
                    stored_len: 524_316,
                },
                ChunkEntry {
                    id: ChunkId::from_base32("BBBBBBB"),
                    stored_len: 1_048_604,
                },
            ],
        }
    }

    #[test]
    fn file_key_is_deterministic_and_path_dependent() {
        let dir = DirId::from_base32("ABCDEFGH");
        let a = file_key(&primary(), &dir, "NAME").unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(a, file_key(&primary(), &dir, "NAME").unwrap());
        // A rename (different cipher name) or a move (different dir) re-keys the file.
        assert_ne!(a, file_key(&primary(), &dir, "OTHER").unwrap());
        assert_ne!(
            a,
            file_key(&primary(), &DirId::from_base32("ZZZZZZZZ"), "NAME").unwrap()
        );
    }

    #[test]
    fn manifest_round_trips() {
        let dir = DirId::from_base32("ABCDEFGH");
        for manifest in [Manifest::empty(), sample_manifest()] {
            let blob = encode_manifest(&primary(), &dir, "NAME", &manifest).unwrap();
            let back = decode_manifest(&primary(), &dir, "NAME", &blob).unwrap();
            assert_eq!(back, manifest);
        }
    }

    #[test]
    fn manifest_only_decodes_under_its_own_file_key() {
        let dir = DirId::from_base32("ABCDEFGH");
        let blob = encode_manifest(&primary(), &dir, "NAME", &sample_manifest()).unwrap();
        // Same content, different location: the file key differs, so the tag fails.
        assert!(matches!(
            decode_manifest(&primary(), &dir, "RENAMED", &blob),
            Err(CryptoError::KeyAuth)
        ));
    }

    #[test]
    fn tampered_manifest_fails_authentication() {
        let dir = DirId::from_base32("ABCDEFGH");
        let mut blob = encode_manifest(&primary(), &dir, "NAME", &sample_manifest()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(
            decode_manifest(&primary(), &dir, "NAME", &blob),
            Err(CryptoError::KeyAuth)
        ));
    }

    #[test]
    fn editing_the_manifest_changes_the_nonce_not_reusing_it() {
        let dir = DirId::from_base32("ABCDEFGH");
        let before = encode_manifest(&primary(), &dir, "NAME", &sample_manifest()).unwrap();
        let mut edited = sample_manifest();
        edited.plaintext_size += 1;
        let after = encode_manifest(&primary(), &dir, "NAME", &edited).unwrap();
        // Different content under the same file key must not share a nonce: the
        // first NONCE_LEN bytes differ.
        assert_ne!(&before[..NONCE_LEN], &after[..NONCE_LEN]);
    }

    #[test]
    fn encoding_is_deterministic_for_unchanged_content() {
        let dir = DirId::from_base32("ABCDEFGH");
        assert_eq!(
            encode_manifest(&primary(), &dir, "NAME", &sample_manifest()).unwrap(),
            encode_manifest(&primary(), &dir, "NAME", &sample_manifest()).unwrap()
        );
    }
}
