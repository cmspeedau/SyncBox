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

/// Something the sync engine still owes the server, or the server owes us.
///
/// The queue exists so an interrupted run resumes: after a crash the engine reads
/// this list instead of rescanning the vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingOp {
    /// A local file has chunks the server does not have.
    Upload {
        /// Plaintext path of the file.
        path: String,
    },
    /// The server has a revision the local copy does not.
    Download {
        /// Plaintext path of the file.
        path: String,
    },
    /// A deletion that has not been committed yet.
    Delete {
        /// Plaintext path of the file.
        path: String,
    },
    /// A rename, which is a new name plus a delete so a peer can follow it.
    Rename {
        /// Old plaintext path.
        from: String,
        /// New plaintext path.
        to: String,
    },
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
