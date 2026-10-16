//! Writing through the filesystem: seal, store, and index a change — no kernel and
//! no server in the loop.
//!
//! A write turns plaintext into vault content the same way the sync engine's push
//! does — [`Vault::locate`] picks the directory id and encrypted name for the path,
//! [`Vault::seal`] chunks and encrypts it, the [`WriteStore`] keeps the manifest and
//! chunks, and a dirty [`FileEntry`] is written to the [`Index`]. Marking the entry
//! `local_dirty` is what makes it *sync-able*: the later push loop reads dirty entries
//! from the index, uploads the chunks the server lacks, and clears the flag. That
//! wiring to the running [`syncbox_agent::Agent`] is the CLI/mount step; here the
//! focus is the model, tested against an in-memory index and store with no FUSE.
//!
//! Directories are not stored records — they are the path prefixes of files in this
//! index-derived namespace — so [`FsMut::mkdir`] does not persist an empty directory
//! (it appears once a file lands under it), and [`FsMut::rename`] handles files, not
//! directory subtrees.

use syncbox_crypto::ChunkId;
use syncbox_index::{FileEntry, Index};
use syncbox_sync::Vault;

use crate::store::WriteStore;
use crate::{normalize, Fs, MountError, Result};

/// What a write changed, returned for the caller that will push it.
#[derive(Debug)]
pub struct Written {
    /// The normalised path written.
    pub path: String,
    /// Plaintext size now.
    pub size: u64,
    /// Chunk ids in file order.
    pub chunk_ids: Vec<ChunkId>,
    /// How many distinct chunk blobs the store was handed this call.
    pub stored_chunks: usize,
}

/// A writable view over a mutable [`Index`], a [`Vault`], and a [`WriteStore`].
///
/// It borrows all three so the caller keeps ownership (and can inspect the index or
/// store after each operation); the expensive material never leaves their hands.
pub struct FsMut<'a, I: Index, W: WriteStore> {
    index: &'a mut I,
    vault: &'a Vault,
    store: &'a mut W,
}

impl<'a, I: Index, W: WriteStore> FsMut<'a, I, W> {
    /// Borrows the pieces a write needs.
    pub fn new(index: &'a mut I, vault: &'a Vault, store: &'a mut W) -> Self {
        Self {
            index,
            vault,
            store,
        }
    }

    /// A read-only snapshot of the tree as it now stands, for `readdir`/`lookup`.
    #[must_use]
    pub fn fs(&self) -> Fs {
        Fs::from_index(&*self.index)
    }

    /// Creates an empty file at `path`.
    ///
    /// # Errors
    ///
    /// [`MountError::EmptyPath`] for the root; sealing/store failures otherwise.
    pub fn create(&mut self, path: &str) -> Result<Written> {
        self.write(path, &[])
    }

    /// Creates or replaces `path` with `bytes`.
    ///
    /// # Errors
    ///
    /// [`MountError::EmptyPath`] for the root; a crypto or store error otherwise.
    pub fn write(&mut self, path: &str, bytes: &[u8]) -> Result<Written> {
        self.seal_and_index(path, bytes)
    }

    /// Sets `path` to exactly `len` bytes, zero-filling on grow and keeping the head
    /// on shrink. Creates the file if it does not exist.
    ///
    /// # Errors
    ///
    /// As [`FsMut::write`], plus a decrypt failure reading the file it is resizing.
    pub fn truncate(&mut self, path: &str, len: u64) -> Result<Written> {
        let mut data = if self.index.file(&normalize(path)).is_some() {
            self.plaintext_at(path)?
        } else {
            Vec::new()
        };
        let want = usize::try_from(len).unwrap_or(usize::MAX);
        if want < data.len() {
            data.truncate(want);
        } else {
            data.resize(want, 0);
        }
        self.seal_and_index(path, &data)
    }

    /// Removes `path`, reporting whether a file was there. Chunk references drop with
    /// it; the blobs become collectable but are left in place (blob GC is M7).
    pub fn unlink(&mut self, path: &str) -> bool {
        self.index.remove_file(&normalize(path))
    }

    /// Accepts a directory creation. Because directories are the prefixes of file
    /// paths (not stored records), nothing is persisted for an empty directory: it
    /// appears in [`FsMut::fs`] once a file is written beneath it. A real mount may
    /// hold empty directories in memory until then.
    ///
    /// # Errors
    ///
    /// [`MountError::EmptyPath`] if `path` is the root (which always exists).
    pub fn mkdir(&mut self, path: &str) -> Result<()> {
        if normalize(path).is_empty() {
            return Err(MountError::EmptyPath);
        }
        Ok(())
    }

    /// Moves a file's content from `from` to `to`, giving it a new directory id and
    /// encrypted name and removing the old record. Renaming a directory (a subtree) is
    /// out of scope for this model.
    ///
    /// # Errors
    ///
    /// [`MountError::NoSuchFile`] if `from` is absent; a write error on the new path.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<Written> {
        let data = self.plaintext_at(from)?;
        let written = self.seal_and_index(to, &data)?;
        self.index.remove_file(&normalize(from));
        Ok(written)
    }

    /// The current plaintext at `path`, or a decrypt/`NoSuchFile` error if it is not
    /// a readable file.
    fn plaintext_at(&self, path: &str) -> Result<Vec<u8>> {
        Fs::from_index(&*self.index).read_all(self.vault, &*self.store, path)
    }

    /// Seals `bytes` under the vault name for `path`, hands the result to the store,
    /// and writes a dirty index record for it.
    fn seal_and_index(&mut self, path: &str, bytes: &[u8]) -> Result<Written> {
        let path = normalize(path);
        if path.is_empty() {
            return Err(MountError::EmptyPath);
        }
        let (dir_id, cipher_name, _name) = self.vault.locate(&path)?;
        let sealed = self.vault.seal(&dir_id, &cipher_name, bytes)?;
        self.store.put_sealed(&dir_id, &cipher_name, &sealed)?;

        let mut entry = FileEntry::fresh(&path, dir_id, &cipher_name);
        entry.size = sealed.plaintext_size;
        entry.chunk_ids = sealed.chunk_ids.clone();
        self.index.put_file(entry);

        Ok(Written {
            path,
            size: sealed.plaintext_size,
            chunk_ids: sealed.chunk_ids,
            stored_chunks: sealed.chunks.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use syncbox_crypto::{MasterKey, MasterKeys};
    use syncbox_index::{FileEntry, MemoryIndex};

    use crate::store::{ContentStore, DiskStore, MemoryStore};

    use super::*;

    fn keys() -> MasterKeys {
        MasterKeys {
            primary: MasterKey::from_bytes(&[0x20; 32]).unwrap(),
            hmac: MasterKey::from_bytes(&[0x00; 32]).unwrap(),
        }
    }

    fn vault(dir: &std::path::Path) -> Vault {
        Vault::new(keys(), "vault", dir).expect("vault")
    }

    #[test]
    fn a_write_lands_a_dirty_record_and_reappears_through_read() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let mut index = MemoryIndex::default();
        let mut store = MemoryStore::new();
        let content = b"the bytes a mount write pushes through the vault".to_vec();

        let written = FsMut::new(&mut index, &vault, &mut store)
            .write("hello.txt", &content)
            .expect("write");
        assert_eq!(written.size, content.len() as u64);

        // The index has a dirty record for it, and it is a file in the tree.
        let entry = index.file("hello.txt").expect("recorded");
        assert!(entry.local_dirty, "the write is sync-able");
        assert_eq!(entry.size, content.len() as u64);
        assert!(!entry.chunk_ids.is_empty());

        // Read it back through the filesystem: decrypted to the same bytes.
        let fs = Fs::from_index(&index);
        let got = fs.read_all(&vault, &store, "hello.txt").expect("read");
        assert_eq!(got, content);
    }

    #[test]
    fn rewriting_drops_the_old_chunks_from_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let mut index = MemoryIndex::default();
        let mut store = MemoryStore::new();

        {
            let mut fs = FsMut::new(&mut index, &vault, &mut store);
            fs.write("file.txt", b"first version of the content")
                .unwrap();
        }
        let before: Vec<_> = index.file("file.txt").unwrap().chunk_ids;

        {
            let mut fs = FsMut::new(&mut index, &vault, &mut store);
            fs.write("file.txt", b"an entirely different second version")
                .unwrap();
        }
        let after: Vec<_> = index.file("file.txt").unwrap().chunk_ids;
        assert_ne!(before, after, "the content changed");
        assert_eq!(index.files().len(), 1, "still one file");
    }

    #[test]
    fn create_is_an_empty_readable_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let mut index = MemoryIndex::default();
        let mut store = MemoryStore::new();

        FsMut::new(&mut index, &vault, &mut store)
            .create("empty.txt")
            .expect("create");
        let fs = Fs::from_index(&index);
        assert_eq!(fs.lookup("empty.txt").map(|n| n.size), Some(0));
        assert!(fs.read_all(&vault, &store, "empty.txt").unwrap().is_empty());
    }

    #[test]
    fn truncate_shrinks_and_grows() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let mut index = MemoryIndex::default();
        let mut store = MemoryStore::new();
        let content = b"0123456789".to_vec();

        FsMut::new(&mut index, &vault, &mut store)
            .write("num.txt", &content)
            .unwrap();

        // Shrink to 4 bytes.
        FsMut::new(&mut index, &vault, &mut store)
            .truncate("num.txt", 4)
            .unwrap();
        let fs = Fs::from_index(&index);
        assert_eq!(fs.read_all(&vault, &store, "num.txt").unwrap(), b"0123");

        // Grow to 6 with zeros.
        FsMut::new(&mut index, &vault, &mut store)
            .truncate("num.txt", 6)
            .unwrap();
        assert_eq!(
            fs.read_all(&vault, &store, "num.txt").unwrap(),
            b"0123\0\0".to_vec()
        );
    }

    #[test]
    fn unlink_removes_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let mut index = MemoryIndex::default();
        let mut store = MemoryStore::new();
        FsMut::new(&mut index, &vault, &mut store)
            .write("gone.txt", b"bye")
            .unwrap();

        let existed = FsMut::new(&mut index, &vault, &mut store).unlink("gone.txt");
        assert!(existed);
        assert!(index.file("gone.txt").is_none());
        assert!(Fs::from_index(&index).lookup("gone.txt").is_none());
        // Unlinking a missing file reports nothing removed.
        assert!(!FsMut::new(&mut index, &vault, &mut store).unlink("gone.txt"));
    }

    #[test]
    fn rename_moves_content_to_a_new_name() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let mut index = MemoryIndex::default();
        let mut store = MemoryStore::new();
        let content = b"content that changes homes".to_vec();
        FsMut::new(&mut index, &vault, &mut store)
            .write("docs/old.txt", &content)
            .unwrap();

        FsMut::new(&mut index, &vault, &mut store)
            .rename("docs/old.txt", "docs/new.txt")
            .expect("rename");

        let fs = Fs::from_index(&index);
        assert!(fs.lookup("docs/old.txt").is_none(), "old name gone");
        assert_eq!(
            fs.read_all(&vault, &store, "docs/new.txt").unwrap(),
            content,
            "content survived the move"
        );
    }

    #[test]
    fn rename_of_a_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let mut index = MemoryIndex::default();
        let mut store = MemoryStore::new();
        let err = FsMut::new(&mut index, &vault, &mut store)
            .rename("nope.txt", "else.txt")
            .expect_err("absent");
        assert!(matches!(err, MountError::NoSuchFile(_)));
    }

    #[test]
    fn a_written_file_in_a_new_directory_shows_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let mut index = MemoryIndex::default();
        let mut store = MemoryStore::new();

        // mkdir alone persists nothing (dirs are file prefixes in this namespace).
        FsMut::new(&mut index, &vault, &mut store)
            .mkdir("photos")
            .expect("mkdir");
        assert!(
            Fs::from_index(&index).lookup("photos").is_none(),
            "no phantom dir"
        );

        // Writing under it makes the directory appear.
        FsMut::new(&mut index, &vault, &mut store)
            .write("photos/cat.png", b"meow")
            .unwrap();
        let fs = Fs::from_index(&index);
        assert!(fs.is_dir("photos"));
        assert_eq!(fs.lookup("photos/cat.png").map(|n| n.size), Some(4));
    }

    #[test]
    fn writes_run_against_the_disk_store_too() {
        let root = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let vault = vault(files.path());
        let mut index = MemoryIndex::default();
        let mut store = DiskStore::new(root.path());
        let content = b"written through the model straight to disk".to_vec();

        FsMut::new(&mut index, &vault, &mut store)
            .write("deep/nested/file.txt", &content)
            .expect("write");

        // Read back through a fresh handle: the model wrote real blobs + manifest.
        let reopened = DiskStore::new(root.path());
        let entry: FileEntry = index.file("deep/nested/file.txt").unwrap();
        let manifest = reopened
            .manifest(&entry.dir_id, &entry.cipher_name)
            .expect("manifest");
        let (bytes, _ids) = vault
            .open(&entry.dir_id, &entry.cipher_name, &manifest, &mut |id| {
                reopened
                    .chunk(id)
                    .ok_or(syncbox_sync::SyncError::Integrity("missing chunk"))
            })
            .expect("open");
        assert_eq!(bytes, content);
    }

    #[test]
    fn the_root_path_is_not_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let mut index = MemoryIndex::default();
        let mut store = MemoryStore::new();
        let mut fs = FsMut::new(&mut index, &vault, &mut store);
        assert!(matches!(fs.write("", b"x"), Err(MountError::EmptyPath)));
    }
}
