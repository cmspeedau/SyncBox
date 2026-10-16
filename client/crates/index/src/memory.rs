//! An in-RAM [`Index`], used by the tests and by anything that wants to run a
//! sync without a durable database.

use std::collections::{BTreeMap, HashMap};

use syncbox_crypto::ChunkId;

use crate::types::FileEntry;
use crate::Index;

/// A chunk's size and how many files currently point at it.
#[derive(Clone, Copy, Debug)]
struct ChunkRecord {
    size: u64,
    refs: u32,
}

/// The [`Index`] trait, backed by maps.
#[derive(Clone, Debug, Default)]
pub struct MemoryIndex {
    files: BTreeMap<String, FileEntry>,
    chunks: HashMap<ChunkId, ChunkRecord>,
}

impl MemoryIndex {
    /// An empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many times a chunk is referenced.
    #[must_use]
    pub fn chunk_refs(&self, id: &ChunkId) -> u32 {
        self.chunks.get(id).map_or(0, |record| record.refs)
    }

    fn retain(&mut self, id: &ChunkId, size: u64) {
        let record = self
            .chunks
            .entry(id.clone())
            .or_insert(ChunkRecord { size, refs: 0 });
        if record.size == 0 {
            record.size = size;
        }
        record.refs += 1;
    }

    fn release(&mut self, id: &ChunkId) {
        if let Some(record) = self.chunks.get_mut(id) {
            record.refs = record.refs.saturating_sub(1);
        }
    }
}

impl Index for MemoryIndex {
    fn file(&self, path: &str) -> Option<FileEntry> {
        self.files.get(path).cloned()
    }

    fn files(&self) -> Vec<FileEntry> {
        self.files.values().cloned().collect()
    }

    fn put_file(&mut self, entry: FileEntry) {
        // Releasing first means a rewrite that keeps some chunks leaves those
        // references at the right count instead of drifting upward. The stale ids
        // are taken out of the map first so no borrow of `self` is held while the
        // counts are edited.
        let stale = self.files.get(&entry.path).map(|old| old.chunk_ids.clone());
        if let Some(stale) = stale {
            for id in &stale {
                self.release(id);
            }
        }
        for id in &entry.chunk_ids {
            self.retain(id, 0);
        }
        self.files.insert(entry.path.clone(), entry);
    }

    fn remove_file(&mut self, path: &str) -> bool {
        let Some(entry) = self.files.remove(path) else {
            return false;
        };
        for id in &entry.chunk_ids {
            self.release(id);
        }
        true
    }

    fn retain_chunk(&mut self, id: &ChunkId, size: u64) {
        self.retain(id, size);
    }

    fn release_chunk(&mut self, id: &ChunkId) {
        self.release(id);
    }

    fn unreferenced_chunks(&self) -> Vec<ChunkId> {
        let mut dead: Vec<ChunkId> = self
            .chunks
            .iter()
            .filter(|(_, record)| record.refs == 0)
            .map(|(id, _)| id.clone())
            .collect();
        dead.sort();
        dead
    }

    fn referenced_bytes(&self) -> u64 {
        self.chunks
            .values()
            .filter(|record| record.refs > 0)
            .map(|record| record.size)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::chunk as shared_chunk;
    use syncbox_crypto::names::DirId;

    fn entry(path: &str, chunks: &[u8]) -> FileEntry {
        FileEntry {
            path: path.to_owned(),
            dir_id: DirId::from_base32("AA"),
            cipher_name: "AB".into(),
            size: 0,
            modified_unix: 0,
            revision: 0,
            chunk_ids: chunks.iter().map(|t| shared_chunk(*t)).collect(),
            local_dirty: false,
            remote_dirty: false,
        }
    }

    #[test]
    fn files_come_back_sorted_by_path() {
        let mut index = MemoryIndex::new();
        index.put_file(entry("z.txt", &[]));
        index.put_file(entry("a.txt", &[]));
        index.put_file(entry("m.txt", &[]));
        let paths: Vec<String> = index.files().into_iter().map(|e| e.path).collect();
        assert_eq!(paths, vec!["a.txt", "m.txt", "z.txt"]);
    }

    #[test]
    fn reference_counts_track_rewrites() {
        let kept = shared_chunk(1);
        let dropped = shared_chunk(2);
        let added = shared_chunk(3);

        let mut index = MemoryIndex::new();
        index.put_file(entry("a.txt", &[1, 2]));
        assert_eq!(index.chunk_refs(&kept), 1);
        assert_eq!(index.chunk_refs(&dropped), 1);

        index.put_file(entry("a.txt", &[1, 3]));
        assert_eq!(index.chunk_refs(&kept), 1, "kept chunk keeps one reference");
        assert_eq!(index.chunk_refs(&dropped), 0, "dropped chunk dies");
        assert_eq!(index.chunk_refs(&added), 1, "new chunk lives");
    }

    #[test]
    fn sizes_are_recorded_for_referenced_chunks() {
        let mut index = MemoryIndex::new();
        let id = shared_chunk(5);
        index.retain_chunk(&id, 4096);
        index.retain_chunk(&id, 4096);
        assert_eq!(index.referenced_bytes(), 4096, "counted once, not twice");
        index.release_chunk(&id);
        assert_eq!(index.referenced_bytes(), 4096);
        index.release_chunk(&id);
        assert_eq!(index.referenced_bytes(), 0);
    }

    #[test]
    fn releasing_more_than_retaining_does_not_panic() {
        // An interrupted run can leave the queue ahead of the tables. The count
        // must bottom out rather than wrap.
        let mut index = MemoryIndex::new();
        let id = shared_chunk(7);
        index.release_chunk(&id);
        assert_eq!(index.chunk_refs(&id), 0);
    }
}
