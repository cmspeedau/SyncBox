//! The sync loop.
//!
//! One pass is: ask the index what is dirty, chunk it, ask the server which of
//! those chunks it already has, send only the rest, then commit a revision. The
//! planning half lives here and is real; the transfer half waits on M3.

use syncbox_index::Index;

use crate::error::{Result, SyncError};

/// What one sync pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Files whose new content we sent.
    pub uploaded: usize,
    /// Files we brought down from the server.
    pub downloaded: usize,
    /// Files written as conflicted copies.
    pub conflicts: usize,
    /// Chunks the server had to store for us.
    pub chunks_uploaded: usize,
    /// Plaintext bytes those chunks covered.
    pub bytes_uploaded: u64,
}

impl SyncReport {
    /// True when the pass found nothing to do, which is the normal state of a
    /// settled vault and what the tray icon shows.
    #[must_use]
    pub fn is_quiet(&self) -> bool {
        *self == Self::default()
    }
}

/// Coordinates the index, the vault, and the server.
///
/// The index is generic so the engine can be driven against [`MemoryIndex`] in
/// tests and against the durable database in the real client, with no branching.
#[derive(Debug)]
pub struct Engine<I: Index> {
    /// Local state the engine reads and updates.
    pub index: I,
}

impl<I: Index> Engine<I> {
    /// Wraps an index.
    #[must_use]
    pub fn new(index: I) -> Self {
        Self { index }
    }

    /// Paths with local content the server does not have yet, in index order.
    ///
    /// This is the whole reason a settled vault syncs instantly: the answer comes
    /// from the index, not from reading files.
    #[must_use]
    pub fn pending_uploads(&self) -> Vec<String> {
        self.index
            .files()
            .into_iter()
            .filter(|entry| entry.local_dirty)
            .map(|entry| entry.path)
            .collect()
    }

    /// Paths where the server is ahead of us, in index order.
    #[must_use]
    pub fn pending_downloads(&self) -> Vec<String> {
        self.index
            .files()
            .into_iter()
            .filter(|entry| entry.remote_dirty)
            .map(|entry| entry.path)
            .collect()
    }

    /// Files dirty on both sides, which is what a conflict looks like before it
    /// is resolved.
    #[must_use]
    pub fn conflicted(&self) -> Vec<String> {
        self.index
            .files()
            .into_iter()
            .filter(|entry| entry.local_dirty && entry.remote_dirty)
            .map(|entry| entry.path)
            .collect()
    }

    /// Runs one pass against the server.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Unimplemented`] until M3 wires up the transport, and
    /// thereafter any transport, crypto, or filesystem error encountered.
    pub fn sync_once(&mut self) -> Result<SyncReport> {
        Err(SyncError::Unimplemented("sync against the server"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syncbox_crypto::names::DirId;
    use syncbox_index::{FileEntry, MemoryIndex};

    fn entry(path: &str, local: bool, remote: bool) -> FileEntry {
        FileEntry {
            path: path.to_owned(),
            dir_id: DirId::from_base32("AA"),
            cipher_name: "AB".into(),
            size: 1,
            modified_unix: 0,
            revision: 1,
            chunk_ids: Vec::new(),
            local_dirty: local,
            remote_dirty: remote,
        }
    }

    fn engine_with(entries: &[(&str, bool, bool)]) -> Engine<MemoryIndex> {
        let mut index = MemoryIndex::new();
        for (path, local, remote) in entries {
            index.put_file(entry(path, *local, *remote));
        }
        Engine::new(index)
    }

    #[test]
    fn planning_only_asks_the_index() {
        let engine = engine_with(&[
            ("clean.txt", false, false),
            ("local.txt", true, false),
            ("remote.txt", false, true),
            ("both.txt", true, true),
        ]);

        // A file dirty on both sides is owed in both directions.
        assert_eq!(engine.pending_uploads(), vec!["both.txt", "local.txt"]);
        assert_eq!(engine.pending_downloads(), vec!["both.txt", "remote.txt"]);
        assert_eq!(engine.conflicted(), vec!["both.txt"]);
    }

    #[test]
    fn a_settled_vault_has_nothing_to_do() {
        let engine = engine_with(&[("a.txt", false, false), ("b.txt", false, false)]);
        assert!(engine.pending_uploads().is_empty());
        assert!(engine.pending_downloads().is_empty());
        assert!(engine.conflicted().is_empty());
    }

    #[test]
    fn an_empty_report_is_quiet() {
        assert!(SyncReport::default().is_quiet());
        let report = SyncReport {
            uploaded: 1,
            ..SyncReport::default()
        };
        assert!(!report.is_quiet());
    }

    #[test]
    fn the_transfer_pass_is_still_a_stub() {
        let mut engine = engine_with(&[("local.txt", true, false)]);
        let err = engine.sync_once().expect_err("M3 implements the transfer");
        assert!(matches!(err, SyncError::Unimplemented(_)));
    }
}
