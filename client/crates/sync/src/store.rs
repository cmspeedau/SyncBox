//! Where the ciphertext a pull fetched goes, so a local store can serve it later.
//!
//! The [`crate::Engine`] pulls a file by downloading its manifest and chunks and
//! decrypting them into the plaintext folder. That leaves the ciphertext in hand for
//! only an instant. A [`PullStore`] catches it, so a read-only mount (the
//! `syncbox-mount` crate) can serve a file that came down from the server without
//! fetching it again — the same blobs, under the same opaque names, that a local write
//! would have left.
//!
//! This trait is owned by `sync`, not by `mount`, because the engine writes into it but
//! must not depend on the mount crate: the dependency runs the other way
//! (`mount` → `sync`). A store in `mount` implements this by handing the bytes to its
//! own write side.

use syncbox_crypto::{names::DirId, ChunkId};

/// Receives a pulled file's encrypted manifest and the stored chunk bytes fetched for
/// it, so they can be kept locally and served without another round to the server.
pub trait PullStore {
    /// Stores `manifest` (the encoded manifest bytes) and the distinct `chunks` that
    /// make up the file now at `dir_id` / `cipher_name`.
    ///
    /// # Errors
    ///
    /// A store-specific I/O failure (an in-memory store never fails).
    fn put_pulled(
        &mut self,
        dir_id: &DirId,
        cipher_name: &str,
        manifest: &[u8],
        chunks: &[(ChunkId, Vec<u8>)],
    ) -> std::io::Result<()>;
}

/// A [`PullStore`] that keeps nothing — the default for callers that only mirror a
/// plaintext folder and never mount the vault, so a plain `sync` stores no extra copy.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullStore;

impl PullStore for NullStore {
    fn put_pulled(
        &mut self,
        _dir_id: &DirId,
        _cipher_name: &str,
        _manifest: &[u8],
        _chunks: &[(ChunkId, Vec<u8>)],
    ) -> std::io::Result<()> {
        Ok(())
    }
}
