//! The cleartext codec: a sync space's naming, chunking and manifest.
//!
//! A vault's codec lives in [`crate::vault`] and seals everything under keys.
//! A sync space is the other half of M11: ordinary files the server is allowed
//! to read, indexed and served. The protocol is unchanged — `dir_id` and
//! `cipher_name` are still opaque text the server only compares for equality,
//! and a manifest is still a blob — but the client fills them in the clear:
//!
//! * a directory id is its relative path, base32-encoded so it survives the
//!   wire's uppercase canonical form and decodes back exactly (a leading NUL,
//!   which no path can contain, keeps the root non-empty and the mapping
//!   unambiguous);
//! * a file's `cipher_name` is its plaintext name, one path component;
//! * a chunk id is `BASE32(SHA-256(chunk))`, so identical bytes deduplicate
//!   exactly as they do in a vault, and the stored bytes are the plaintext;
//! * a manifest is a small versioned binary record rather than an
//!   authenticated envelope, and a reader verifies each chunk's id against the
//!   bytes it fetched.

use sha2::{Digest, Sha256};
use syncbox_crypto::content::ChunkId;
use syncbox_crypto::names::{base32_decode, base32_encode, DirId};
use syncbox_crypto::{ChunkEntry, Manifest};

use crate::error::{Result, SyncError};

/// Manifest format tag. A sync-space manifest is readable on purpose; the tag
/// is what tells a reader it is the cleartext shape and not a vault blob.
const MAGIC: &[u8; 8] = b"SBXSYNC1";

/// The directory id of `rel_dir` (`""` for the root): its path, base32-encoded.
#[must_use]
pub(crate) fn dir_id(rel_dir: &str) -> DirId {
    let mut bytes = Vec::with_capacity(rel_dir.len() + 1);
    // No filesystem path may contain NUL, so a leading one cannot collide with
    // a real directory and keeps the root's encoding non-empty.
    bytes.push(0);
    bytes.extend_from_slice(rel_dir.as_bytes());
    DirId::from_base32(&base32_encode(&bytes))
}

/// The relative path a directory id encodes, or `None` if it is not one this
/// codec could have written.
#[must_use]
pub(crate) fn rel_dir(dir_id: &DirId) -> Option<String> {
    let bytes = base32_decode(dir_id.as_str()).ok()?;
    let (first, rest) = bytes.split_first()?;
    if *first != 0 {
        return None;
    }
    let rel = String::from_utf8(rest.to_vec()).ok()?;
    safe_rel_dir(&rel).then_some(rel)
}

/// Whether `rel` is a relative directory path this codec will place a file
/// under: `/`-separated, no empty or parent components, no NUL or backslash.
///
/// The vault gets this property from authenticated names; a sync space has no
/// tag to verify, so it refuses anything a hostile or broken server could use
/// to escape the folder instead.
#[must_use]
pub(crate) fn safe_rel_dir(rel: &str) -> bool {
    rel.is_empty()
        || rel.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && !segment.contains('\\')
                && !segment.contains('\0')
        })
}

/// Whether `name` is one plaintext file name a sync space may write.
#[must_use]
pub(crate) fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

/// The content address of one plaintext chunk: `BASE32(SHA-256(bytes))`.
#[must_use]
pub(crate) fn chunk_id(data: &[u8]) -> ChunkId {
    ChunkId::from_base32(&base32_encode(&Sha256::digest(data)))
}

/// Encodes a cleartext manifest:
/// `MAGIC || size:u64 || count:u32 || (stored_len:u32 || id_len:u16 || id)*`.
///
/// # Errors
///
/// Returns [`SyncError::Integrity`] if the chunk count or one id cannot be
/// represented, which no splitter output can produce.
pub(crate) fn encode_manifest(manifest: &Manifest) -> Result<Vec<u8>> {
    let count = u32::try_from(manifest.chunks.len())
        .map_err(|_| SyncError::Integrity("too many chunks for a sync manifest"))?;
    let mut out = Vec::with_capacity(20 + manifest.chunks.len() * 58);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&manifest.plaintext_size.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    for entry in &manifest.chunks {
        let id = entry.id.as_str();
        let id_len = u16::try_from(id.len())
            .map_err(|_| SyncError::Integrity("chunk id too long for a sync manifest"))?;
        out.extend_from_slice(&entry.stored_len.to_le_bytes());
        out.extend_from_slice(&id_len.to_le_bytes());
        out.extend_from_slice(id.as_bytes());
    }
    Ok(out)
}

/// Decodes a manifest written by [`encode_manifest`], rejecting a truncated,
/// overlong or trailing-garbage record rather than trusting its count.
///
/// # Errors
///
/// Returns [`SyncError::Integrity`] when the bytes are not a well-formed
/// sync-space manifest or an id is not valid UTF-8.
pub(crate) fn decode_manifest(bytes: &[u8]) -> Result<Manifest> {
    if bytes.len() < 20 || &bytes[..8] != MAGIC {
        return Err(SyncError::Integrity(
            "manifest is not a sync-space manifest",
        ));
    }
    let size = u64::from_le_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| SyncError::Integrity("manifest size is truncated"))?,
    );
    let count = u32::from_le_bytes(
        bytes[16..20]
            .try_into()
            .map_err(|_| SyncError::Integrity("manifest count is truncated"))?,
    );
    // A hostile count must not allocate before the bytes have vouched for it.
    let mut rest = &bytes[20..];
    let mut chunks = Vec::with_capacity(usize::try_from(count).unwrap_or(0).min(1024));
    for _ in 0..count {
        if rest.len() < 6 {
            return Err(SyncError::Integrity("manifest chunk is truncated"));
        }
        let stored_len = u32::from_le_bytes(
            rest[..4]
                .try_into()
                .map_err(|_| SyncError::Integrity("chunk length is truncated"))?,
        );
        let id_len =
            usize::from(u16::from_le_bytes(rest[4..6].try_into().map_err(|_| {
                SyncError::Integrity("chunk id length is truncated")
            })?));
        rest = &rest[6..];
        if rest.len() < id_len || id_len == 0 {
            return Err(SyncError::Integrity("manifest chunk id is truncated"));
        }
        let id = std::str::from_utf8(&rest[..id_len])
            .map_err(|_| SyncError::Integrity("manifest chunk id is not text"))?;
        chunks.push(ChunkEntry {
            id: ChunkId::from_base32(id),
            stored_len,
        });
        rest = &rest[id_len..];
    }
    if !rest.is_empty() {
        return Err(SyncError::Integrity(
            "manifest has trailing bytes after its chunks",
        ));
    }
    Ok(Manifest {
        plaintext_size: size,
        chunks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_round_trips_through_its_id() {
        for rel in ["", "docs", "docs/2026", "a b/c-d", "Ünïcode"] {
            let id = dir_id(rel);
            assert!(!id.as_str().is_empty(), "an id is never empty");
            assert_eq!(rel_dir(&id).as_deref(), Some(rel), "{rel} round-trips");
        }
        // The root is a fixed, non-empty id that no real path produces.
        assert_eq!(dir_id(""), dir_id(""));
        assert_ne!(dir_id(""), dir_id("docs"));
    }

    #[test]
    fn a_directory_id_that_is_not_ours_is_refused() {
        // A vault directory id (an HMAC) does not start with the NUL tag.
        let foreign = DirId::from_base32(&base32_encode(&[7u8; 32]));
        assert_eq!(rel_dir(&foreign), None);
        // Nor does path traversal survive.
        assert!(!safe_rel_dir("../etc"));
        assert!(!safe_rel_dir("a//b"));
        assert!(!safe_rel_dir("a/./b"));
        assert!(!safe_rel_dir("a\\b"));
        assert!(safe_rel_dir(""));
        assert!(safe_rel_dir("a/b"));
    }

    #[test]
    fn a_plaintext_name_must_be_one_component() {
        assert!(safe_name("notes.txt"));
        assert!(!safe_name(""));
        assert!(!safe_name("."));
        assert!(!safe_name(".."));
        assert!(!safe_name("../escape"));
        assert!(!safe_name("a/b"));
        assert!(!safe_name("a\\b"));
        assert!(!safe_name("nul\0"));
    }

    #[test]
    fn a_manifest_round_trips() {
        let manifest = Manifest {
            plaintext_size: 1234,
            chunks: vec![
                ChunkEntry {
                    id: chunk_id(b"first"),
                    stored_len: 5,
                },
                ChunkEntry {
                    id: chunk_id(b"second"),
                    stored_len: 6,
                },
            ],
        };
        let bytes = encode_manifest(&manifest).expect("encode");
        assert_eq!(decode_manifest(&bytes).expect("decode"), manifest);
    }

    #[test]
    fn a_malformed_manifest_is_refused() {
        assert!(decode_manifest(b"not a manifest").is_err());
        let bytes = encode_manifest(&Manifest {
            plaintext_size: 1,
            chunks: vec![ChunkEntry {
                id: chunk_id(b"x"),
                stored_len: 1,
            }],
        })
        .expect("encode");
        assert!(
            decode_manifest(&bytes[..bytes.len() - 1]).is_err(),
            "truncated"
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_manifest(&trailing).is_err(), "trailing byte");
    }

    #[test]
    fn a_chunk_id_is_the_plain_hash_of_its_bytes() {
        assert_eq!(chunk_id(b"same"), chunk_id(b"same"));
        assert_ne!(chunk_id(b"same"), chunk_id(b"other"));
        // 32 bytes of SHA-256 in Crockford base32 is 52 symbols.
        assert_eq!(chunk_id(b"").as_str().len(), 52);
    }
}
