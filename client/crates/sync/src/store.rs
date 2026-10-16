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

/// Receives a pulled file's encrypted manifest and chunks — chunk by chunk, as they
/// arrive — so they can be kept locally and served without another round to the
/// server. The manifest is cached *last*: its presence is the mark that the whole
/// file made it, while cached chunks alone are a download half-done, worth resuming
/// from rather than starting over.
pub trait PullStore {
    /// Keeps one downloaded chunk's stored bytes, keyed by content id, so a
    /// later fetch (this file's, or any file sharing the chunk) skips the server.
    ///
    /// # Errors
    ///
    /// A store-specific I/O failure (an in-memory store never fails).
    fn cache_chunk(&mut self, id: &ChunkId, bytes: &[u8]) -> std::io::Result<()>;

    /// Keeps `manifest`, the encoded manifest bytes of the file now at `dir_id` /
    /// `cipher_name`. Call after [`PullStore::cache_chunk`] for every chunk.
    ///
    /// # Errors
    ///
    /// A store-specific I/O failure.
    fn cache_manifest(
        &mut self,
        dir_id: &DirId,
        cipher_name: &str,
        manifest: &[u8],
    ) -> std::io::Result<()>;

    /// Stores a whole pulled file in one call: every chunk, then the manifest.
    fn put_pulled(
        &mut self,
        dir_id: &DirId,
        cipher_name: &str,
        manifest: &[u8],
        chunks: &[(ChunkId, Vec<u8>)],
    ) -> std::io::Result<()> {
        for (id, bytes) in chunks {
            self.cache_chunk(id, bytes)?;
        }
        self.cache_manifest(dir_id, cipher_name, manifest)
    }
}

/// Where a file's manifest and chunks are kept (the read side).
///
/// One contract, two users: the mount asks it to serve the tree, and a folderless
/// engine asks it to turn a dirty index record back into plaintext. The same opaque
/// keys [`PullStore`] writes by — the two traits together make a store a full local
/// cache of the vault's ciphertext.
pub trait ContentStore {
    /// The stored (encrypted) manifest bytes for a file, by its directory id and
    /// encrypted name.
    fn manifest(&self, dir_id: &DirId, cipher_name: &str) -> Option<Vec<u8>>;

    /// The stored bytes of one chunk, by content id.
    fn chunk(&self, id: &ChunkId) -> Option<Vec<u8>>;
}

/// What an [`crate::Engine`] content store must be: a sink for pulls and a source for
/// pushes. Blanket-implemented — any type with both halves is one, so implementors
/// name neither this trait nor the direction they serve.
pub trait SyncStore: PullStore + ContentStore {}

impl<T: PullStore + ContentStore + ?Sized> SyncStore for T {}

/// A [`PullStore`] that keeps nothing — the default for callers that only mirror a
/// plaintext folder and never mount the vault, so a plain `sync` stores no extra copy.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullStore;

impl PullStore for NullStore {
    fn cache_chunk(&mut self, _id: &ChunkId, _bytes: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    fn cache_manifest(
        &mut self,
        _dir_id: &DirId,
        _cipher_name: &str,
        _manifest: &[u8],
    ) -> std::io::Result<()> {
        Ok(())
    }
}

impl ContentStore for NullStore {
    fn manifest(&self, _dir_id: &DirId, _cipher_name: &str) -> Option<Vec<u8>> {
        None
    }

    fn chunk(&self, _id: &ChunkId) -> Option<Vec<u8>> {
        None
    }
}
