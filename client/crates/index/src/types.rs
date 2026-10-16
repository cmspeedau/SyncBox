//! The records the index stores.

use syncbox_crypto::{names::DirId, ChunkId};

/// One file the client knows about, keyed by its plaintext path relative to the
/// vault root.
///
/// The path is plaintext because it only ever exists on the client; what leaves
/// the machine is `dir_id` plus `cipher_name`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    /// Plaintext path, `/`-separated, relative to the vault root.
    pub path: String,
    /// Directory id this file's name is encrypted under.
    pub dir_id: DirId,
    /// Encrypted file name, without the `.c9r` suffix.
    pub cipher_name: String,
    /// Plaintext size in bytes.
    pub size: u64,
    /// Last modification time, seconds since the Unix epoch.
    pub modified_unix: i64,
    /// Server-side revision this copy corresponds to, `0` if never synced.
    pub revision: u64,
    /// Chunk ids in file order.
    pub chunk_ids: Vec<ChunkId>,
    /// The local copy is ahead of `revision`.
    pub local_dirty: bool,
    /// The server has a revision newer than `revision`.
    pub remote_dirty: bool,
}

impl FileEntry {
    /// A record for a file that has never been synced.
    #[must_use]
    pub fn fresh(path: &str, dir_id: DirId, cipher_name: &str) -> Self {
        Self {
            path: path.to_owned(),
            dir_id,
            cipher_name: cipher_name.to_owned(),
            size: 0,
            modified_unix: 0,
            revision: 0,
            chunk_ids: Vec::new(),
            local_dirty: true,
            remote_dirty: false,
        }
    }

    /// True when the local copy and the server agree.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.local_dirty && !self.remote_dirty
    }
}

/// Something a local delete left behind that sync still owes the server.
///
/// A deletion cannot be replayed from the file records once the record is gone, so
/// the index keeps one of these per deleted file until its tombstone is committed:
/// a crash between "unlinked" and "tombstoned" must not silently un-delete the file
/// on the peers. The key is `(dir_id, cipher_name)` — the server's file key — because
/// the tombstone commit names files that way, and a bare path no longer resolves
/// once the record is gone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletedFile {
    /// The path the file had, kept for display and logging only.
    pub path: String,
    /// The vault directory holding the file.
    pub dir_id: DirId,
    /// The encrypted file name inside that directory.
    pub cipher_name: String,
    /// The last known modification time, echoed in the tombstone commit.
    pub modified_unix: i64,
}

impl DeletedFile {
    /// The queue entry for a file record about to be removed.
    #[must_use]
    pub fn from_entry(entry: &FileEntry) -> Self {
        Self {
            path: entry.path.clone(),
            dir_id: entry.dir_id.clone(),
            cipher_name: entry.cipher_name.clone(),
            modified_unix: entry.modified_unix,
        }
    }

    /// The server-side key of the file, which is what a tombstone addresses.
    #[must_use]
    pub fn key(&self) -> (DirId, String) {
        (self.dir_id.clone(), self.cipher_name.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_file_starts_dirty_and_unsynced() {
        let entry = FileEntry::fresh("notes.txt", DirId::from_base32("AA"), "ABCDEFGH");
        assert_eq!(entry.revision, 0);
        assert!(entry.local_dirty);
        assert!(!entry.is_clean());
    }

    #[test]
    fn either_side_being_dirty_makes_the_file_dirty() {
        let mut entry = FileEntry::fresh("a.txt", DirId::from_base32("AA"), "AB");
        entry.local_dirty = false;
        assert!(entry.is_clean());
        entry.remote_dirty = true;
        assert!(!entry.is_clean());
    }
}
