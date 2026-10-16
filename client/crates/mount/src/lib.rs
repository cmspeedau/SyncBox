//! A vault seen as a filesystem, with no kernel in the hot path.
//!
//! The FUSE mount is really two things. The hard, interesting thing — deciding what
//! the tree *is*, and turning a path back into plaintext — lives here; the [`fuser`]
//! adapter that hands those answers to the kernel is a thin mapping kept in a
//! separate crate so this one needs no libfuse.
//!
//! The namespace is the local [`Index`], not the ciphertext. Directory names cannot
//! be recovered from the server's opaque ids alone (a subdirectory's encrypted name is
//! never stored under its parent), so the client's own index — which records
//! [`FileEntry`] plaintext paths — is the only place the tree's shape is knowable. A
//! path is a file when the index has an entry for it, and a directory when it is the
//! parent prefix of some entry.
//!
//! Content is read through a [`ContentStore`]: the per-file manifest and the chunk
//! blobs a file is made of. [`Fs::read_all`] fetches those and decrypts via
//! [`Vault::open`]. Where the store gets its bytes — an in-memory [`MemoryStore`] in
//! tests, a [`DiskStore`] folder of ciphertext on disk, the server on demand — is the
//! store's business, not the filesystem's.
//!
//! [`fuser`]: https://docs.rs/fuser

use std::collections::{BTreeMap, BTreeSet};

use syncbox_index::{FileEntry, Index};
use syncbox_sync::{SyncError, Vault};

mod store;

pub use store::{ContentStore, DiskStore, MemoryStore};

/// Whether a path names a directory or a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    /// A directory (including the root).
    Directory,
    /// A regular file.
    File,
}

/// A node in the vault tree: enough to answer `getattr`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// Normalised path, `""` for the root.
    pub path: String,
    /// Directory or file.
    pub kind: NodeKind,
    /// Byte size (0 for a directory).
    pub size: u64,
    /// The revision a file corresponds to (0 for a directory or an unsynced file).
    pub revision: u64,
}

impl Node {
    /// The root directory.
    #[must_use]
    pub fn root() -> Self {
        Self {
            path: String::new(),
            kind: NodeKind::Directory,
            size: 0,
            revision: 0,
        }
    }

    /// True for a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.kind == NodeKind::Directory
    }
}

/// One child of a directory, as `readdir` reports it. The `.` and `..` entries are
/// left to the caller (FUSE synthesises them), so the list holds only real children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// The child's basename.
    pub name: String,
    /// Directory or file.
    pub kind: NodeKind,
    /// Byte size (0 for a directory).
    pub size: u64,
}

/// Anything that can go wrong reading through the filesystem.
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    /// Nothing is at that path.
    #[error("no such file or directory: {0}")]
    NoSuchFile(String),
    /// A read was asked for a path that is a directory, not a file.
    #[error("not a file: {0}")]
    NotAFile(String),
    /// The index knows the file but the store has no manifest for it yet.
    #[error("no stored manifest for this file")]
    MissingManifest,
    /// Decryption or chunk fetch failed.
    #[error(transparent)]
    Sync(#[from] SyncError),
}

/// Result alias used across this crate.
pub type Result<T> = std::result::Result<T, MountError>;

/// A read-only snapshot of the vault tree built from an [`Index`].
///
/// It is a value, not a live handle: the mount takes a snapshot per operation (or
/// after each sync) so the filesystem it presents is stable while a directory read is
/// in flight. Rebuilding it from the index is cheap.
#[derive(Debug, Default, Clone)]
pub struct Fs {
    files: BTreeMap<String, FileEntry>,
    /// Every directory path; the root `""` is always present.
    dirs: BTreeSet<String>,
}

impl Fs {
    /// An empty tree: just the root directory.
    #[must_use]
    pub fn empty() -> Self {
        let mut dirs = BTreeSet::new();
        dirs.insert(String::new());
        Self {
            files: BTreeMap::new(),
            dirs,
        }
    }

    /// Builds the tree from everything the index knows.
    #[must_use]
    pub fn from_index(index: &dyn Index) -> Self {
        Self::from_entries(index.files().iter())
    }

    /// Builds the tree from a set of file records (the index's, or a test's).
    #[must_use]
    pub fn from_entries<'a>(entries: impl Iterator<Item = &'a FileEntry>) -> Self {
        let mut fs = Self::empty();
        for entry in entries {
            fs.add_file(entry);
        }
        fs
    }

    /// Records a file and turns every ancestor prefix into a directory.
    fn add_file(&mut self, entry: &FileEntry) {
        let path = normalize(&entry.path);
        if path.is_empty() {
            return;
        }
        let components: Vec<&str> = path.split('/').collect();
        // Every component except the last names a directory that must exist.
        let mut acc = String::new();
        for component in &components[..components.len() - 1] {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(component);
            // A prefix that is itself a recorded file is a corrupt index; skip it
            // rather than list the same path twice.
            if !self.files.contains_key(&acc) {
                self.dirs.insert(acc.clone());
            }
        }
        self.dirs.remove(&path);
        self.files.insert(path, entry.clone());
    }

    /// The node at `path`, or `None` if nothing is there. `""` and `"/"` are the root.
    #[must_use]
    pub fn lookup(&self, path: &str) -> Option<Node> {
        let path = normalize(path);
        if path.is_empty() {
            return Some(Node::root());
        }
        if let Some(entry) = self.files.get(&path) {
            return Some(Node {
                path,
                kind: NodeKind::File,
                size: entry.size,
                revision: entry.revision,
            });
        }
        if self.dirs.contains(&path) {
            return Some(Node {
                path,
                kind: NodeKind::Directory,
                size: 0,
                revision: 0,
            });
        }
        None
    }

    /// The real children of the directory `path`, sorted by name. `None` if `path` is
    /// not a directory.
    #[must_use]
    pub fn readdir(&self, path: &str) -> Option<Vec<DirEntry>> {
        let dir = normalize(path);
        if !(dir.is_empty() || self.dirs.contains(&dir)) {
            return None;
        }
        let mut children = Vec::new();
        for (child_path, entry) in &self.files {
            if parent_of(child_path) == dir {
                children.push(DirEntry {
                    name: basename(child_path).to_owned(),
                    kind: NodeKind::File,
                    size: entry.size,
                });
            }
        }
        for child_dir in &self.dirs {
            if !child_dir.is_empty() && parent_of(child_dir) == dir {
                children.push(DirEntry {
                    name: basename(child_dir).to_owned(),
                    kind: NodeKind::Directory,
                    size: 0,
                });
            }
        }
        children.sort_by(|a, b| a.name.cmp(&b.name));
        Some(children)
    }

    /// The index record for a file path, if one exists.
    #[must_use]
    pub fn file(&self, path: &str) -> Option<&FileEntry> {
        self.files.get(&normalize(path))
    }

    /// True when `path` names a directory (the root included).
    #[must_use]
    pub fn is_dir(&self, path: &str) -> bool {
        let path = normalize(path);
        path.is_empty() || self.dirs.contains(&path)
    }

    /// True when the tree holds nothing but the root.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.dirs.len() == 1
    }

    /// Every file path, sorted. Handy for tests and for a `find`-style view.
    #[must_use]
    pub fn file_paths(&self) -> Vec<String> {
        self.files.keys().cloned().collect()
    }

    /// Decrypts the whole file at `path` using the vault's keys and the store's
    /// manifest and chunks.
    ///
    /// # Errors
    ///
    /// [`MountError::NoSuchFile`] / [`MountError::NotAFile`] if the path is not a
    /// known file; [`MountError::MissingManifest`] if the store has no manifest;
    /// otherwise the decrypt/`fetch` failure via [`MountError::Sync`].
    pub fn read_all(&self, vault: &Vault, store: &dyn ContentStore, path: &str) -> Result<Vec<u8>> {
        let entry = self.lookup_file(path)?;
        let manifest = store
            .manifest(&entry.dir_id, &entry.cipher_name)
            .ok_or(MountError::MissingManifest)?;
        let (bytes, _ids) =
            vault.open(&entry.dir_id, &entry.cipher_name, &manifest, &mut |id| {
                store.chunk(id).ok_or(SyncError::Integrity(
                    "mount: chunk absent from content store",
                ))
            })?;
        Ok(bytes)
    }

    /// Reads up to `len` bytes from `offset`. Reconstructs the file then slices;
    /// chunk-range reads are a later optimisation, not a correctness concern.
    ///
    /// # Errors
    ///
    /// As [`Fs::read_all`]. Reads past the end yield an empty buffer, like POSIX.
    pub fn read_range(
        &self,
        vault: &Vault,
        store: &dyn ContentStore,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>> {
        let bytes = self.read_all(vault, store, path)?;
        let start = (offset as usize).min(bytes.len());
        let end = start.saturating_add(len).min(bytes.len());
        Ok(bytes[start..end].to_vec())
    }

    /// The file record for `path`, or a distinguishing error if it is absent or a
    /// directory.
    fn lookup_file(&self, path: &str) -> Result<&FileEntry> {
        let normalized = normalize(path);
        match self.files.get(&normalized) {
            Some(entry) => Ok(entry),
            None if self.dirs.contains(&normalized) => Err(MountError::NotAFile(path.to_owned())),
            None => Err(MountError::NoSuchFile(path.to_owned())),
        }
    }
}

/// Collapses a path to its canonical form: `/`-joined, no leading/trailing or
/// repeated slashes, no `.` segments. Returns `""` for the root.
fn normalize(path: &str) -> String {
    path.split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// The directory that holds `path`, or `""` for a top-level entry.
fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(index) => &path[..index],
        None => "",
    }
}

/// The final path component.
fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(index) => &path[index + 1..],
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use syncbox_crypto::names::DirId;
    use syncbox_crypto::{MasterKey, MasterKeys};
    use syncbox_index::MemoryIndex;

    use super::*;

    fn entry(path: &str, size: u64, revision: u64) -> FileEntry {
        FileEntry {
            revision,
            size,
            ..FileEntry::fresh(path, DirId::from_base32("AA"), "CIPHER")
        }
    }

    fn sample() -> Fs {
        let files = [
            entry("a.txt", 10, 3),
            entry("docs/readme.md", 200, 5),
            entry("docs/sub/deep.bin", 1_024, 7),
        ];
        Fs::from_entries(files.iter())
    }

    #[test]
    fn empty_tree_is_just_the_root() {
        let fs = Fs::empty();
        assert!(fs.is_empty());
        assert_eq!(fs.lookup("").map(|n| n.kind), Some(NodeKind::Directory));
        assert_eq!(fs.lookup("/").map(|n| n.kind), Some(NodeKind::Directory));
        assert_eq!(fs.readdir("").unwrap(), vec![]);
        assert_eq!(fs.lookup("anything"), None);
    }

    #[test]
    fn a_file_node_carries_its_size_and_revision() {
        let fs = sample();
        let node = fs.lookup("a.txt").expect("file");
        assert_eq!(node.kind, NodeKind::File);
        assert_eq!(node.size, 10);
        assert_eq!(node.revision, 3);
    }

    #[test]
    fn directories_come_from_path_prefixes_not_entries() {
        let fs = sample();
        assert_eq!(fs.lookup("docs").map(|n| n.kind), Some(NodeKind::Directory));
        assert_eq!(
            fs.lookup("docs/sub").map(|n| n.kind),
            Some(NodeKind::Directory)
        );
        assert!(fs.is_dir("docs"));
        assert!(!fs.is_dir("a.txt"));
    }

    #[test]
    fn root_listing_sorts_files_and_dirs_by_name() {
        let fs = sample();
        let entries = fs.readdir("").unwrap();
        assert_eq!(names(&entries), vec!["a.txt", "docs"]);
        assert_eq!(entries[0].kind, NodeKind::File);
        assert_eq!(entries[1].kind, NodeKind::Directory);
    }

    #[test]
    fn nested_readdir_sees_only_direct_children() {
        let fs = sample();
        assert_eq!(
            names(&fs.readdir("docs").unwrap()),
            vec!["readme.md", "sub"]
        );
        assert_eq!(names(&fs.readdir("docs/sub").unwrap()), vec!["deep.bin"]);
        assert!(
            fs.readdir("docs/sub/deep.bin").is_none(),
            "a file is not a directory"
        );
    }

    #[test]
    fn looking_up_beyond_the_tree_is_none() {
        let fs = sample();
        assert_eq!(fs.lookup("nope"), None);
        assert_eq!(fs.lookup("docs/nope/x"), None);
        assert!(
            fs.readdir("nope").is_none(),
            "listing a non-directory fails"
        );
    }

    #[test]
    fn paths_are_normalized_for_slashes_and_dots() {
        let fs = sample();
        assert_eq!(
            fs.lookup("/docs//sub/").map(|n| n.path),
            Some("docs/sub".into())
        );
        assert_eq!(fs.lookup("./a.txt").map(|n| n.size), Some(10));
    }

    #[test]
    fn file_paths_are_sorted() {
        let fs = sample();
        assert_eq!(
            fs.file_paths(),
            vec!["a.txt", "docs/readme.md", "docs/sub/deep.bin"]
        );
    }

    #[test]
    fn it_builds_from_a_real_index() {
        let mut index = MemoryIndex::default();
        index.put_file(entry("notes.txt", 7, 1));
        index.put_file(entry("img/logo.png", 42, 2));
        let fs = Fs::from_index(&index);
        assert_eq!(names(&fs.readdir("").unwrap()), vec!["img", "notes.txt"]);
        assert_eq!(fs.lookup("img/logo.png").map(|n| n.size), Some(42));
    }

    // --- content reads -------------------------------------------------------

    fn keys() -> MasterKeys {
        MasterKeys {
            primary: MasterKey::from_bytes(&[0x20; 32]).unwrap(),
            hmac: MasterKey::from_bytes(&[0x00; 32]).unwrap(),
        }
    }

    /// Seals `content` into the store and returns an index entry naming it `path`,
    /// so an `Fs` built from that entry can be read back through `vault`.
    fn stage(vault: &Vault, store: &mut MemoryStore, path: &str, content: &[u8]) -> FileEntry {
        let dir_id = vault.root().clone();
        let cipher = "FILE1CIPHER";
        let sealed = vault.seal(&dir_id, cipher, content).expect("seal");
        store.put_sealed(&dir_id, cipher, &sealed);
        FileEntry {
            size: content.len() as u64,
            revision: 1,
            chunk_ids: sealed.chunk_ids.clone(),
            local_dirty: false,
            ..FileEntry::fresh(path, dir_id, cipher)
        }
    }

    #[test]
    fn read_reconstructs_a_sealed_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let mut store = MemoryStore::new();
        let content = b"the quick brown fox jumps over the lazy dog".to_vec();
        let e = stage(&vault, &mut store, "hello.txt", &content);
        let fs = Fs::from_entries([e].iter());

        let got = fs.read_all(&vault, &store, "hello.txt").expect("read");
        assert_eq!(got, content);
    }

    #[test]
    fn ranged_read_slices_and_past_the_end_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let mut store = MemoryStore::new();
        let content = b"hello syncbox world".to_vec();
        let e = stage(&vault, &mut store, "greet.txt", &content);
        let fs = Fs::from_entries([e].iter());

        assert_eq!(
            fs.read_range(&vault, &store, "greet.txt", 6, 7)
                .expect("slice"),
            b"syncbox"
        );
        assert!(fs
            .read_range(&vault, &store, "greet.txt", content.len() as u64, 10)
            .expect("past end")
            .is_empty());
    }

    #[test]
    fn read_works_over_the_disk_store() {
        let files = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", files.path()).expect("vault");
        let dir_id = vault.root().clone();
        let content = b"reading a file served from the on-disk ciphertext store".to_vec();
        let mut store = DiskStore::new(files.path().join("blobs"));
        let sealed = store
            .capture(&vault, &dir_id, "DISK", &content)
            .expect("capture");
        let e = FileEntry {
            size: sealed.plaintext_size,
            revision: 1,
            chunk_ids: sealed.chunk_ids.clone(),
            local_dirty: false,
            ..FileEntry::fresh("on-disk.txt", dir_id, "DISK")
        };
        let fs = Fs::from_entries([e].iter());
        let got = fs.read_all(&vault, &store, "on-disk.txt").expect("read");
        assert_eq!(got, content);
    }

    #[test]
    fn read_without_a_stored_manifest_errors() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let store = MemoryStore::new(); // nothing staged
        let fs = Fs::from_entries([entry("ghost.txt", 5, 1)].iter());
        let err = fs
            .read_all(&vault, &store, "ghost.txt")
            .expect_err("no manifest");
        assert!(matches!(err, MountError::MissingManifest));
    }

    #[test]
    fn read_with_a_manifest_but_missing_chunks_errors() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let mut store = MemoryStore::new();
        // Store the manifest but none of the chunks it points at, so decrypting the
        // manifest succeeds and reconstructing the content cannot.
        let dir_id = vault.root().clone();
        let sealed = vault
            .seal(&dir_id, "CIPHER", b"chunks not stored")
            .expect("seal");
        store.put_manifest(&dir_id, "CIPHER", sealed.manifest.clone());
        let e = FileEntry {
            size: sealed.plaintext_size,
            revision: 1,
            chunk_ids: sealed.chunk_ids.clone(),
            local_dirty: false,
            ..FileEntry::fresh("f.txt", dir_id, "CIPHER")
        };
        let fs = Fs::from_entries([e].iter());
        assert!(fs.read_all(&vault, &store, "f.txt").is_err());
    }

    #[test]
    fn reading_a_directory_is_not_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let store = MemoryStore::new();
        let fs = sample();
        let err = fs.read_all(&vault, &store, "docs").expect_err("a dir");
        assert!(matches!(err, MountError::NotAFile(_)));
    }

    fn names(entries: &[DirEntry]) -> Vec<String> {
        entries.iter().map(|e| e.name.clone()).collect()
    }
}
