//! The client's local index: what it knows about each file, which chunks a file
//! is made of, and which chunks nobody needs any more.
//!
//! The index is what makes sync cheap. Without it, every run would have to
//! re-read and re-chunk the whole vault to discover what changed, and it would
//! have no way to tell a chunk that is merely new from one that is safe to
//! delete from the local cache.
//!
//! [`Index`] is the contract the sync engine codes against. [`MemoryIndex`]
//! satisfies it in RAM and drives the tests; the durable SQLite implementation
//! arrives with M3 behind the same methods.

pub mod memory;
pub mod sqlite;
pub mod types;

pub use memory::MemoryIndex;
pub use sqlite::SqliteIndex;
pub use types::{FileEntry, PendingOp};

use syncbox_crypto::ChunkId;

/// Durable bookkeeping of files and chunk references.
///
/// Implementations are expected to keep chunk reference counts consistent with
/// the file records: a chunk is deletable exactly when no file lists it.
pub trait Index {
    /// Looks up one file by its plaintext path, relative to the vault root.
    fn file(&self, path: &str) -> Option<FileEntry>;

    /// Every known file, ordered by path.
    fn files(&self) -> Vec<FileEntry>;

    /// Inserts or replaces a file record, moving chunk references along with it.
    fn put_file(&mut self, entry: FileEntry);

    /// Drops a file record and its chunk references, reporting whether it existed.
    fn remove_file(&mut self, path: &str) -> bool;

    /// Records one more reference to a chunk of `size` bytes.
    fn retain_chunk(&mut self, id: &ChunkId, size: u64);

    /// Drops one reference to a chunk.
    fn release_chunk(&mut self, id: &ChunkId);

    /// How many times a chunk is currently referenced.
    fn chunk_refs(&self, id: &ChunkId) -> u32;

    /// Chunks that no file references, ready to leave the local cache.
    fn unreferenced_chunks(&self) -> Vec<ChunkId>;

    /// Bytes still referenced by at least one file.
    fn referenced_bytes(&self) -> u64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use syncbox_crypto::names::DirId;

    pub(crate) fn chunk(tag: u8) -> ChunkId {
        ChunkId::from_base32(&syncbox_crypto::names::base32_encode(&[tag]))
    }

    fn entry(path: &str, chunks: &[u8]) -> FileEntry {
        FileEntry {
            path: path.to_owned(),
            dir_id: DirId::from_base32("AA"),
            cipher_name: format!("{path}.c9r"),
            size: chunks.len() as u64 * 1024,
            modified_unix: 1_700_000_000,
            revision: 1,
            chunk_ids: chunks.iter().map(|t| chunk(*t)).collect(),
            local_dirty: false,
            remote_dirty: false,
        }
    }

    fn id_of(index: &dyn Index, path: &str) -> Vec<ChunkId> {
        index
            .file(path)
            .unwrap_or_else(|| panic!("{path} missing"))
            .chunk_ids
    }

    #[test]
    fn rewriting_a_file_drops_only_the_chunks_it_stopped_using() {
        let mut index = MemoryIndex::default();
        let kept = chunk(2);
        let dropped = chunk(1);
        let added = chunk(3);

        index.put_file(entry("notes.txt", &[1, 2]));
        index.put_file(entry("notes.txt", &[2, 3]));

        assert!(
            index.unreferenced_chunks().contains(&dropped),
            "the chunk the rewrite abandoned is collectable"
        );
        assert!(!index.unreferenced_chunks().contains(&kept));
        assert!(!index.unreferenced_chunks().contains(&added));
        assert_eq!(id_of(&index, "notes.txt").len(), 2);
    }

    #[test]
    fn a_chunk_shared_by_two_files_survives_one_being_deleted() {
        let shared = chunk(9);
        let mut index = MemoryIndex::default();
        index.put_file(FileEntry {
            chunk_ids: vec![shared.clone()],
            ..entry("a.txt", &[])
        });
        index.put_file(FileEntry {
            chunk_ids: vec![shared.clone()],
            ..entry("b.txt", &[])
        });

        assert!(index.remove_file("a.txt"));
        assert!(
            !index.unreferenced_chunks().contains(&shared),
            "still referenced by b.txt"
        );

        assert!(index.remove_file("b.txt"));
        assert!(index.unreferenced_chunks().contains(&shared));
    }

    #[test]
    fn removing_an_unknown_file_reports_nothing_removed() {
        let mut index = MemoryIndex::default();
        assert!(!index.remove_file("ghost.txt"));
    }

    #[test]
    fn the_trait_is_usable_as_a_trait_object() {
        // The sync engine holds a boxed index, so this has to keep compiling.
        let index: Box<dyn Index> = Box::new(MemoryIndex::default());
        assert!(index.files().is_empty());
    }
}
