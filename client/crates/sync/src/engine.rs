//! The sync loop.
//!
//! One pass is: read the server's whole revision log for the vault and apply what
//! is newer than what the index already reflects, then push every local file that
//! has changed since its index record, committing each against the vault's current
//! head. The two halves look like the same walk from opposite ends, and the reason
//! they can share it is the server's model of a revision:
//!
//! * Revisions in a vault form one **global, ordered log**. A commit is accepted
//!   only if its `parent` is the vault's current head, and it is assigned
//!   `head + 1`. So a client never commits "against a file's old version" — it
//!   commits against the head it last saw, and any other client's commit in the
//!   meantime is a `409`, not a silent clobber.
//! * The log carries tombstones too: a `deleted` revision is how a deletion
//!   propagates. The newest revision for a file key — by revision number, since
//!   the log is ordered — is that file's current state.
//!
//! That means the index needs only one number per file (`FileEntry::revision`, the
//! log position the file's local copy matches) to know whether it is ahead, behind,
//! or settled, and the engine reads the log from position 0 each pass, so it never
//! has to persist a sync cursor of its own.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use syncbox_crypto::content::{NONCE_LEN, TAG_LEN};
use syncbox_crypto::names::DirId;
use syncbox_crypto::ChunkId;
use syncbox_index::{FileEntry, Index};
use syncbox_transport::dto::{CommitRequest, Revision};
use syncbox_transport::{Client, Http, TransportError};

use crate::conflict::conflicted_copy_name;
use crate::error::{Result, SyncError};
use crate::store::PullStore;
use crate::vault::Vault;

/// The optional local store a pull tees the ciphertext it downloads into, so a
/// read-only mount can later serve a server-sourced file without fetching it again.
/// `None` for a plain plaintext-folder sync, which keeps no ciphertext copy. A newtype
/// so the derived [`Debug`] on [`Engine`] does not have to print a `dyn` trait object.
/// `Send + Sync` because the [`syncbox_agent`](https://docs.rs/syncbox-agent) worker
/// drives an engine from a background thread.
struct Store(Option<Box<dyn PullStore + Send + Sync>>);

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            Some(_) => "Store(installed)",
            None => "Store(none)",
        })
    }
}

/// What one sync pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Files whose new content we sent.
    pub uploaded: usize,
    /// Files we brought down from the server.
    pub downloaded: usize,
    /// Files written as conflicted copies.
    pub conflicts: usize,
    /// Files deleted (locally mirrored from a remote tombstone, or a local delete
    /// we committed).
    pub deleted: usize,
    /// Remote files we could not place because their directory is unknown here.
    pub skipped: usize,
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
/// The index is generic so the engine can be driven against [`syncbox_index::MemoryIndex`]
/// in tests and against the durable database in the real client, with no branching.
/// The server is supplied per [`Engine::sync_once`] call, so the same engine can be
/// pointed at any transport.
#[derive(Debug)]
pub struct Engine<I: Index> {
    /// Local state the engine reads and updates.
    pub index: I,
    /// The unlocked vault whose keys and plaintext tree this engine syncs.
    pub vault: Vault,
    /// Where a pull deposits downloaded ciphertext, if a local store is configured.
    store: Store,
}

impl<I: Index> Engine<I> {
    /// Wraps an index and a vault, with no local content store (a plain folder sync).
    #[must_use]
    pub fn new(index: I, vault: Vault) -> Self {
        Self {
            index,
            vault,
            store: Store(None),
        }
    }

    /// Adds a local content store: on a pull, each file's manifest and downloaded
    /// chunks are teed into it, so a read-only mount backed by the same store can serve
    /// server-sourced files without re-fetching them. Chaining constructor.
    #[must_use]
    pub fn with_store(mut self, store: impl PullStore + Send + Sync + 'static) -> Self {
        self.set_store(store);
        self
    }

    /// Installs (or replaces) the local content store a pull writes into.
    pub fn set_store(&mut self, store: impl PullStore + Send + Sync + 'static) {
        self.store = Store(Some(Box::new(store)));
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

    /// Runs one full sync pass: pull what the server has that we lack, then push
    /// what we have that the server lacks, resolving a both-sides edit into a
    /// conflicted copy.
    ///
    /// `now` is a `YYYY-MM-DD` label for any conflicted copy this pass produces;
    /// the caller owns the clock so the naming stays deterministic in tests.
    ///
    /// # Errors
    ///
    /// Propagates transport, crypto, and filesystem errors. A `409` on a commit is
    /// not fatal: it means another client won the head, and the lost file is kept
    /// as a conflicted copy for a later pass to reconcile.
    pub fn sync_once<H: Http>(&mut self, client: &mut Client<H>, now: &str) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        let vault_id = self.vault.vault_id().to_owned();

        let head = self.pull(client, &vault_id, now, &mut report)?;
        self.push(client, &vault_id, head, now, &mut report)?;
        Ok(report)
    }

    /// Applies the server's log to the local tree and returns the head it reached,
    /// which is the parent every push this pass must chain from.
    fn pull<H: Http>(
        &mut self,
        client: &mut Client<H>,
        vault_id: &str,
        now: &str,
        report: &mut SyncReport,
    ) -> Result<u64> {
        let page = client.revisions(vault_id, 0)?;
        let head = page.upto;

        // The log is oldest-first, so overwriting by file key leaves the newest
        // revision for each file — which, if it is a tombstone, is the file's
        // current "deleted" state.
        let mut latest: HashMap<(String, String), Revision> = HashMap::new();
        for revision in page.revisions {
            latest.insert(
                (revision.dir_id.clone(), revision.cipher_name.clone()),
                revision,
            );
        }
        // Iterate newest-first-by-revision so writes happen in a stable order.
        let mut revisions: Vec<Revision> = latest.into_values().collect();
        revisions.sort_by_key(|r| r.revision);

        let dir_map = self.vault.dir_map()?;
        let index_by_key: HashMap<(String, String), FileEntry> = self
            .index
            .files()
            .into_iter()
            .map(|e| ((e.dir_id.as_str().to_owned(), e.cipher_name.clone()), e))
            .collect();

        for revision in revisions {
            let dir_id = DirId::from_base32(&revision.dir_id);
            let Some(path) =
                self.resolve_path(&dir_map, &index_by_key, &dir_id, &revision.cipher_name)?
            else {
                report.skipped += 1;
                continue;
            };

            let known = self.index.file(&path);
            let known_revision = known.as_ref().map_or(0, |entry| entry.revision);

            if revision.deleted {
                if known.is_some() {
                    delete_local(self.vault.plaintext_root(), &path)?;
                    self.index.remove_file(&path);
                    report.deleted += 1;
                }
                continue;
            }

            // A local copy already at or past this revision is settled (or ahead,
            // in which case push will carry it up).
            if revision.revision <= known_revision {
                continue;
            }

            // The server is ahead. If our on-disk copy also differs from what the
            // index says we synced, both sides edited: keep ours as a conflicted
            // copy before the server's version takes the canonical name.
            if let (Some(entry), Some((size, mtime))) = (
                known.as_ref(),
                stat_local(self.vault.plaintext_root(), &path),
            ) {
                if entry.size != size || entry.modified_unix != mtime {
                    let ours = read_local(self.vault.plaintext_root(), &path)?;
                    let copy = conflict_path(&path, now);
                    write_local(self.vault.plaintext_root(), &copy, &ours)?;
                    report.conflicts += 1;
                }
            }

            let manifest = BASE64
                .decode(&revision.manifest)
                .map_err(|_| SyncError::Integrity("manifest is not valid base64"))?;
            // When a local store is configured, record each downloaded chunk as it
            // arrives, then store the manifest too, so a read-only mount backed by the
            // same store can serve this file later without fetching it again. With no
            // store the download path is byte-identical to a plain folder sync.
            let tee = self.store.0.is_some();
            let mut downloaded: Vec<(ChunkId, Vec<u8>)> = Vec::new();
            let (plaintext, chunk_ids) =
                self.vault
                    .open(&dir_id, &revision.cipher_name, &manifest, &mut |id| {
                        let stored = client
                            .download_chunk(vault_id, id)
                            .map_err(SyncError::from)?;
                        if tee {
                            downloaded.push((id.clone(), stored.clone()));
                        }
                        Ok(stored)
                    })?;
            if let Some(store) = self.store.0.as_mut() {
                store.put_pulled(&dir_id, &revision.cipher_name, &manifest, &downloaded)?;
            }
            write_local(self.vault.plaintext_root(), &path, &plaintext)?;
            // Record the mtime the filesystem actually landed, so the next scan
            // sees this file as unchanged rather than freshly touched.
            let (size, mtime) = stat_local(self.vault.plaintext_root(), &path)
                .unwrap_or((plaintext.len() as u64, 0));
            self.index.put_file(FileEntry {
                path,
                dir_id,
                cipher_name: revision.cipher_name,
                size,
                modified_unix: mtime,
                revision: revision.revision,
                chunk_ids,
                local_dirty: false,
                remote_dirty: false,
            });
            report.downloaded += 1;
        }

        Ok(head)
    }

    /// Sends every changed local file, committing each against the running head,
    /// and mirrors deletions as tombstones.
    fn push<H: Http>(
        &mut self,
        client: &mut Client<H>,
        vault_id: &str,
        mut head: u64,
        now: &str,
        report: &mut SyncReport,
    ) -> Result<()> {
        // Scan after the pull so anything we just downloaded is seen as settled and
        // any conflicted copy the pull wrote is queued to upload as a new file.
        let mut local: BTreeMap<String, (u64, i64)> = BTreeMap::new();
        for (path, size, mtime) in list_tree(self.vault.plaintext_root())? {
            local.insert(path, (size, mtime));
        }

        // Deletions first: an index record with no file behind it is gone locally.
        for entry in self.index.files() {
            if local.contains_key(&entry.path) {
                continue;
            }
            let response = client.commit(
                vault_id,
                &CommitRequest {
                    parent: head,
                    revision: Revision {
                        revision: 0,
                        parent: head,
                        dir_id: entry.dir_id.as_str().to_owned(),
                        cipher_name: entry.cipher_name.clone(),
                        manifest: String::new(),
                        size: 0,
                        modified_unix: entry.modified_unix,
                        deleted: true,
                    },
                },
            )?;
            head = response.revision;
            self.index.remove_file(&entry.path);
            report.deleted += 1;
        }

        for (path, (size, mtime)) in local {
            let known = self.index.file(&path);
            let changed = match &known {
                Some(entry) => {
                    entry.local_dirty || entry.size != size || entry.modified_unix != mtime
                }
                None => true,
            };
            if !changed {
                continue;
            }

            let plaintext = read_local(self.vault.plaintext_root(), &path)?;
            let (dir_id, cipher_name, _name) = self.vault.locate(&path)?;
            let sealed = self.vault.seal(&dir_id, &cipher_name, &plaintext)?;

            let offered: Vec<ChunkId> = sealed.chunks.iter().map(|(id, _)| id.clone()).collect();
            let missing = client.missing_chunks(vault_id, &offered)?;
            for (id, stored) in sealed.chunks.iter().filter(|(id, _)| missing.contains(id)) {
                client.upload_chunk(vault_id, id, stored)?;
                report.chunks_uploaded += 1;
                report.bytes_uploaded +=
                    (stored.len() as u64).saturating_sub((NONCE_LEN + TAG_LEN) as u64);
            }

            let request = CommitRequest {
                parent: head,
                revision: Revision {
                    revision: 0,
                    parent: head,
                    dir_id: dir_id.as_str().to_owned(),
                    cipher_name: cipher_name.clone(),
                    manifest: BASE64.encode(&sealed.manifest),
                    size,
                    modified_unix: mtime,
                    deleted: false,
                },
            };
            match client.commit(vault_id, &request) {
                Ok(response) => {
                    head = response.revision;
                    self.index.put_file(FileEntry {
                        path,
                        dir_id,
                        cipher_name,
                        size,
                        modified_unix: mtime,
                        revision: response.revision,
                        chunk_ids: sealed.chunk_ids,
                        local_dirty: false,
                        remote_dirty: false,
                    });
                    report.uploaded += 1;
                }
                Err(TransportError::Refused { ref code, .. }) if code == "conflict" => {
                    // Another client advanced the head first. Keep our bytes under a
                    // conflicted name rather than lose them; leave the index record
                    // untouched so a later pass reconciles the canonical copy.
                    let copy = conflict_path(&path, now);
                    write_local(self.vault.plaintext_root(), &copy, &plaintext)?;
                    report.conflicts += 1;
                }
                Err(other) => return Err(SyncError::from(other)),
            }
        }

        Ok(())
    }

    /// Maps a revision's `(dir_id, cipher_name)` to a local relative path.
    ///
    /// A file is placeable if its directory exists locally (so we can decrypt its
    /// name into that directory), or if we already track a file under that exact
    /// key and can reuse its path. Otherwise the directory is one a peer created
    /// that we cannot name from an opaque id, and the file is skipped.
    fn resolve_path(
        &self,
        dir_map: &HashMap<DirId, String>,
        index_by_key: &HashMap<(String, String), FileEntry>,
        dir_id: &DirId,
        cipher_name: &str,
    ) -> Result<Option<String>> {
        if let Some(rel_dir) = dir_map.get(dir_id) {
            let name = self.vault.plaintext_name(dir_id, cipher_name)?;
            return Ok(Some(join_rel(rel_dir, &name)));
        }
        if let Some(entry) = index_by_key.get(&(dir_id.as_str().to_owned(), cipher_name.to_owned()))
        {
            return Ok(Some(entry.path.clone()));
        }
        Ok(None)
    }
}

/// Joins a directory-relative path and a name with `/`, the index's separator.
fn join_rel(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

/// Turns `a/b.txt` into `a/b (conflicted copy 2026-10-16).txt`, keeping the file in
/// its directory and labelling only the file name.
fn conflict_path(path: &str, now: &str) -> String {
    match path.rsplit_once('/') {
        Some((dir, name)) => join_rel(dir, &conflicted_copy_name(name, now)),
        None => conflicted_copy_name(path, now),
    }
}

/// The absolute path of a vault-relative file.
fn full_path(root: &Path, rel: &str) -> PathBuf {
    root.join(rel)
}

/// Size and modification time of a local file, or `None` if it is not there.
fn stat_local(root: &Path, rel: &str) -> Option<(u64, i64)> {
    let meta = std::fs::metadata(full_path(root, rel)).ok()?;
    if !meta.is_file() {
        return None;
    }
    let mtime = meta.modified().map_or(0, epoch_secs);
    Some((meta.len(), mtime))
}

/// Seconds since the Unix epoch, allowing pre-1970 as a negative value.
fn epoch_secs(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

/// Reads a vault-relative file.
fn read_local(root: &Path, rel: &str) -> Result<Vec<u8>> {
    Ok(std::fs::read(full_path(root, rel))?)
}

/// Writes a vault-relative file, creating its parent directories.
fn write_local(root: &Path, rel: &str, bytes: &[u8]) -> Result<()> {
    let path = full_path(root, rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

/// Removes a vault-relative file, tolerating it already being gone.
fn delete_local(root: &Path, rel: &str) -> Result<()> {
    match std::fs::remove_file(full_path(root, rel)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Lists every regular file under `root` as `(relative path, size, mtime)`.
///
/// Relative paths use `/` regardless of host separator, matching the index.
fn list_tree(root: &Path) -> Result<Vec<(String, u64, i64)>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let path = entry.path();
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let rel = relative(root, &path)?;
            let meta = entry.metadata()?;
            let mtime = meta.modified().map_or(0, epoch_secs);
            out.push((rel, meta.len(), mtime));
        }
    }
    Ok(out)
}

/// The `/`-separated path of `path` under `root`.
fn relative(root: &Path, path: &Path) -> Result<String> {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let joined = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use syncbox_crypto::{MasterKey, MasterKeys};
    use syncbox_index::MemoryIndex;

    fn keys() -> MasterKeys {
        MasterKeys {
            primary: MasterKey::from_bytes(&[0x20; 32]).unwrap(),
            hmac: MasterKey::from_bytes(&[0x00; 32]).unwrap(),
        }
    }

    fn vault(dir: &Path) -> Vault {
        Vault::new(keys(), "vault", dir).expect("vault")
    }

    fn index_with(entries: &[(&str, bool, bool)]) -> MemoryIndex {
        let mut index = MemoryIndex::new();
        for (path, local, remote) in entries {
            index.put_file(FileEntry {
                path: (*path).to_owned(),
                dir_id: DirId::from_base32("AA"),
                cipher_name: "AB".into(),
                size: 1,
                modified_unix: 0,
                revision: 1,
                chunk_ids: Vec::new(),
                local_dirty: *local,
                remote_dirty: *remote,
            });
        }
        index
    }

    #[test]
    fn planning_only_asks_the_index() {
        let dir = std::env::temp_dir();
        let engine = Engine::new(
            index_with(&[
                ("clean.txt", false, false),
                ("local.txt", true, false),
                ("remote.txt", false, true),
                ("both.txt", true, true),
            ]),
            vault(&dir),
        );

        assert_eq!(engine.pending_uploads(), vec!["both.txt", "local.txt"]);
        assert_eq!(engine.pending_downloads(), vec!["both.txt", "remote.txt"]);
        assert_eq!(engine.conflicted(), vec!["both.txt"]);
    }

    #[test]
    fn conflict_path_labels_only_the_file_name() {
        assert_eq!(
            conflict_path("docs/report.md", "2026-10-16"),
            "docs/report (conflicted copy 2026-10-16).md"
        );
        assert_eq!(
            conflict_path("LICENSE", "2026-10-16"),
            "LICENSE (conflicted copy 2026-10-16)"
        );
    }

    #[test]
    fn join_rel_omits_an_empty_directory() {
        assert_eq!(join_rel("", "a.txt"), "a.txt");
        assert_eq!(join_rel("a/b", "c.txt"), "a/b/c.txt");
    }

    #[test]
    fn relative_paths_use_forward_slashes() {
        let joined = relative(Path::new("/root/vault"), Path::new("/root/vault/a/b.txt")).unwrap();
        assert_eq!(joined, "a/b.txt");
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
    fn a_tree_scan_sorts_by_path_and_stats_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("b.txt"), b"hello").unwrap();
        std::fs::write(dir.path().join("sub/a.txt"), b"xyz").unwrap();

        let mut listed = list_tree(dir.path()).unwrap();
        listed.sort();
        let paths: Vec<&str> = listed.iter().map(|(p, _, _)| p.as_str()).collect();
        assert_eq!(paths, vec!["b.txt", "sub/a.txt"]);
        let sizes: Vec<u64> = listed.iter().map(|(_, s, _)| *s).collect();
        assert_eq!(sizes, vec![5, 3]);
    }

    #[test]
    fn writing_a_file_creates_its_directories() {
        let dir = tempfile::tempdir().unwrap();
        write_local(dir.path(), "deep/inner/file.txt", b"data").unwrap();
        assert_eq!(
            read_local(dir.path(), "deep/inner/file.txt").unwrap(),
            b"data"
        );
        assert_eq!(stat_local(dir.path(), "deep/inner/file.txt").unwrap().0, 4);
    }

    #[test]
    fn deleting_a_missing_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        delete_local(dir.path(), "nope.txt").expect("tolerated");
    }
}
