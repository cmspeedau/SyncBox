//! Where a file's encrypted material comes from: the [`ContentStore`] seam and its
//! in-memory and on-disk implementations.
//!
//! The filesystem asks a store for a file's manifest and chunks; the store decides
//! where they live. [`MemoryStore`] answers from RAM (tests, and the shape a
//! write-through cache takes). [`DiskStore`] keeps them in a folder of ciphertext
//! under opaque names — the same "on disk it is a folder of opaque blobs" property
//! the vault has everywhere else: a chunk is stored under its content id, a manifest
//! under its directory id and encrypted name, so nothing on disk is a plaintext hint.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use syncbox_crypto::{names::DirId, ChunkId};
use syncbox_sync::Sealed;

/// Where a file's manifest and chunks are kept.
///
/// The filesystem asks; the store answers. This indirection is what lets the read
/// path be tested against an in-memory store and run against a local ciphertext
/// folder (or, later, the server) without the tree logic knowing the difference.
pub trait ContentStore {
    /// The stored (encrypted) manifest bytes for a file, by its directory id and
    /// encrypted name.
    fn manifest(&self, dir_id: &DirId, cipher_name: &str) -> Option<Vec<u8>>;

    /// The stored bytes of one chunk, by content id.
    fn chunk(&self, id: &ChunkId) -> Option<Vec<u8>>;
}

/// An in-memory [`ContentStore`]: the read backend for tests, and the shape a
/// write-through cache will take.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    manifests: HashMap<(String, String), Vec<u8>>,
    chunks: HashMap<ChunkId, Vec<u8>>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores a file's manifest bytes.
    pub fn put_manifest(&mut self, dir_id: &DirId, cipher_name: &str, bytes: Vec<u8>) {
        self.manifests
            .insert((dir_id.as_str().to_owned(), cipher_name.to_owned()), bytes);
    }

    /// Stores one chunk's bytes.
    pub fn put_chunk(&mut self, id: &ChunkId, bytes: Vec<u8>) {
        self.chunks.insert(id.clone(), bytes);
    }

    /// Stores everything a [`Sealed`] file produced — manifest and its distinct
    /// chunks — so the store can serve a later read.
    pub fn put_sealed(&mut self, dir_id: &DirId, cipher_name: &str, sealed: &Sealed) {
        self.put_manifest(dir_id, cipher_name, sealed.manifest.clone());
        for (id, bytes) in &sealed.chunks {
            self.put_chunk(id, bytes.clone());
        }
    }
}

impl ContentStore for MemoryStore {
    fn manifest(&self, dir_id: &DirId, cipher_name: &str) -> Option<Vec<u8>> {
        self.manifests
            .get(&(dir_id.as_str().to_owned(), cipher_name.to_owned()))
            .cloned()
    }

    fn chunk(&self, id: &ChunkId) -> Option<Vec<u8>> {
        self.chunks.get(id).cloned()
    }
}

/// A [`ContentStore`] that keeps blobs on disk under opaque, sharded names:
///
/// ```text
/// <root>/chunks/<id[0..2]>/<id[2..4]>/<id>                 chunk bytes
/// <root>/manifests/<dirid[0..2]>/<dirid[2..4]>/<dirid>/<cipherName>   manifest bytes
/// ```
///
/// Both file names are content-addressed or already ciphertext (a base32 chunk id, a
/// base32 directory id, an encrypted name), so the folder leaks nothing about
/// plaintext. Writes go through a temp file and a rename so a reader never sees a
/// half-written blob.
#[derive(Clone, Debug)]
pub struct DiskStore {
    root: PathBuf,
}

impl DiskStore {
    /// A store rooted at `root` (created on first write).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory the root lives in, for tests and callers.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Stores one chunk's bytes, creating its shard directories.
    pub fn put_chunk(&mut self, id: &ChunkId, bytes: &[u8]) -> io::Result<()> {
        write_blob(&self.chunk_path(id.as_str()), bytes)
    }

    /// Stores a file's manifest bytes.
    pub fn put_manifest(
        &mut self,
        dir_id: &DirId,
        cipher_name: &str,
        bytes: &[u8],
    ) -> io::Result<()> {
        write_blob(&self.manifest_path(dir_id.as_str(), cipher_name), bytes)
    }

    /// Stores a whole sealed file (manifest + its distinct chunks).
    pub fn put_sealed(
        &mut self,
        dir_id: &DirId,
        cipher_name: &str,
        sealed: &Sealed,
    ) -> io::Result<()> {
        self.put_manifest(dir_id, cipher_name, &sealed.manifest)?;
        for (id, bytes) in &sealed.chunks {
            self.put_chunk(id, bytes)?;
        }
        Ok(())
    }

    /// Seals `plaintext` with `vault` and stores the result, returning the sealed
    /// file so the caller can record it in the index. This is the store's write
    /// primitive — the same shape a mount write and a sync download both use.
    pub fn capture(
        &mut self,
        vault: &syncbox_sync::Vault,
        dir_id: &DirId,
        cipher_name: &str,
        plaintext: &[u8],
    ) -> io::Result<Sealed> {
        let sealed = vault
            .seal(dir_id, cipher_name, plaintext)
            .map_err(io::Error::other)?;
        self.put_sealed(dir_id, cipher_name, &sealed)?;
        Ok(sealed)
    }

    fn chunk_path(&self, id: &str) -> PathBuf {
        shard_path(&self.root.join("chunks"), id)
    }

    fn manifest_path(&self, dir_id: &str, cipher_name: &str) -> PathBuf {
        // Shard by the directory id, then a file named by the (encrypted) name.
        let sharded = shard_path(&self.root.join("manifests"), dir_id);
        // shard_path returns <base>/<a>/<b>/<id>; make <id> a directory and the
        // encrypted name its file, so all entries of one directory sit together.
        sharded.join(cipher_name)
    }
}

impl ContentStore for DiskStore {
    fn manifest(&self, dir_id: &DirId, cipher_name: &str) -> Option<Vec<u8>> {
        read_blob(&self.manifest_path(dir_id.as_str(), cipher_name))
    }

    fn chunk(&self, id: &ChunkId) -> Option<Vec<u8>> {
        read_blob(&self.chunk_path(id.as_str()))
    }
}

/// `<base>/<s[0..2]>/<s[2..4]>/<s>` — shard by the first two and next two characters
/// so no directory grows unbounded, and keep the full id as the leaf name.
fn shard_path(base: &Path, s: &str) -> PathBuf {
    let a: String = s.chars().take(2).collect();
    let b: String = s.chars().skip(2).take(2).collect();
    let mut path = base.to_path_buf();
    if !a.is_empty() {
        path.push(&a);
    }
    if !b.is_empty() {
        path.push(&b);
    }
    path.push(s);
    path
}

/// Writes `bytes` to `path` atomically (temp file + rename), creating parents.
fn write_blob(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Reads a blob, treating any read failure (missing, permissions) as a cache miss.
fn read_blob(path: &Path) -> Option<Vec<u8>> {
    fs::read(path).ok()
}

#[cfg(test)]
mod tests {
    use syncbox_crypto::{MasterKey, MasterKeys};
    use syncbox_sync::Vault;

    use super::*;

    fn keys() -> MasterKeys {
        MasterKeys {
            primary: MasterKey::from_bytes(&[0x20; 32]).unwrap(),
            hmac: MasterKey::from_bytes(&[0x00; 32]).unwrap(),
        }
    }

    fn vault(dir: &Path) -> Vault {
        Vault::new(keys(), "vault", dir).expect("vault")
    }

    #[test]
    fn memory_store_round_trips_manifest_and_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let dir_id = v.root().clone();
        let mut store = MemoryStore::new();
        store.put_manifest(&dir_id, "NAME", b"manifest".to_vec());
        let id = ChunkId::from_base32("ABCD");
        store.put_chunk(&id, b"chunk".to_vec());
        assert_eq!(
            store.manifest(&dir_id, "NAME").as_deref(),
            Some(&b"manifest"[..])
        );
        assert_eq!(store.chunk(&id).as_deref(), Some(&b"chunk"[..]));
        assert!(store.chunk(&ChunkId::from_base32("EEEE")).is_none());
    }

    #[test]
    fn disk_store_round_trips_through_disk() {
        let root = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let v = vault(files.path());
        let dir_id = v.root().clone();
        let content = b"a file that must survive a trip to disk and back".to_vec();
        let sealed = v.seal(&dir_id, "CIPHER1", &content).expect("seal");

        let mut store = DiskStore::new(root.path());
        store.put_sealed(&dir_id, "CIPHER1", &sealed).expect("put");

        // A brand-new handle over the same root (nothing cached) reads it back.
        let reopened = DiskStore::new(root.path());
        assert_eq!(
            reopened.manifest(&dir_id, "CIPHER1").as_deref(),
            Some(sealed.manifest.as_slice())
        );
        for (id, bytes) in &sealed.chunks {
            assert_eq!(reopened.chunk(id).as_deref(), Some(bytes.as_slice()));
        }
    }

    #[test]
    fn disk_store_capture_then_read_manifest_and_chunks() {
        let root = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let v = vault(files.path());
        let dir_id = v.root().clone();
        let mut store = DiskStore::new(root.path());
        let sealed = store
            .capture(&v, &dir_id, "CAP", b"written through capture")
            .expect("capture");
        assert_eq!(
            store.manifest(&dir_id, "CAP").as_deref(),
            Some(sealed.manifest.as_slice())
        );
        assert!(!sealed.chunks.is_empty());
    }

    #[test]
    fn disk_store_names_are_opaque_ids() {
        let root = tempfile::tempdir().unwrap();
        let mut store = DiskStore::new(root.path().join("vault"));
        let id = ChunkId::from_base32("ABCDEFGHIJKLMNOP");
        store.put_chunk(&id, b"x").expect("put");

        // The blob sits under a path made only of base32 id shards + the id.
        let on_disk = root.path().join("vault").join("chunks");
        let collected = walk(&on_disk);
        assert!(
            collected.iter().any(|p| p.ends_with(id.as_str())),
            "blob named by its id"
        );
        // Nothing on the path is a plaintext word.
        for p in &collected {
            let s = p.to_string_lossy();
            assert!(
                !s.contains("secret") && !s.contains("plaintext"),
                "leaked name: {s}"
            );
        }
    }

    #[test]
    fn disk_store_reports_missing_as_none() {
        let root = tempfile::tempdir().unwrap();
        let v = vault(root.path());
        let store = DiskStore::new(root.path().join("vault"));
        assert!(store.chunk(&ChunkId::from_base32("ZZZZ")).is_none());
        assert!(store.manifest(v.root(), "NOPE").is_none());
    }

    #[test]
    fn chunks_are_stored_once_across_a_shared_file() {
        let root = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let v = vault(files.path());
        let dir_id = v.root().clone();
        let mut store = DiskStore::new(root.path());
        // Same content twice: seal produces one distinct chunk, stored once.
        let a = v.seal(&dir_id, "AAA", b"dup dup dup").expect("seal");
        let b = v.seal(&dir_id, "BBB", b"dup dup dup").expect("seal");
        store.put_sealed(&dir_id, "AAA", &a).expect("a");
        store.put_sealed(&dir_id, "BBB", &b).expect("b");
        // The two files' distinct-chunk lists overlap fully.
        let a_ids: Vec<_> = a.chunks.iter().map(|(id, _)| id.clone()).collect();
        assert!(
            b.chunks.iter().all(|(id, _)| a_ids.contains(id)),
            "same content dedups"
        );
    }

    /// Collects every file path under `dir` (best effort).
    fn walk(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    out.extend(walk(&path));
                } else {
                    out.push(path);
                }
            }
        }
        out
    }
}
