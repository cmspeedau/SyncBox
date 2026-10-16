//! Reclaiming ciphertext that no live file needs any more.
//!
//! The store only ever grows on its own: every overwrite leaves the previous
//! generation's unique chunks behind, and an unlink or rename leaves its
//! manifest (and any chunks nothing else shares) as an orphan. [`collect`] is
//! the one place that deletes: it asks the [`Index`] what is live, inventories
//! the [`GcStore`], and removes everything in between.
//!
//! Liveness is decided by the index's file records alone. The index is the one
//! place that knows every live file — *including dirty ones*: a file edited
//! through the mount but not yet pushed is exactly as live as a synced one, so
//! a folderless vault never GCs ahead of its own push. The chunk reference
//! counts the index also keeps are deliberately not trusted here: a refcount
//! bug could make GC delete live bytes, whereas recomputing from the file
//! records degrades to keeping too much, never too little.

use std::collections::HashSet;
use std::io;

use syncbox_crypto::ChunkId;
use syncbox_index::Index;

use crate::lock::StoreLock;

/// A store that can be inventoried and pruned — everything [`collect`] needs.
///
/// The memory and disk stores implement this next to their layout code, but it
/// is kept apart from [`crate::ContentStore`] / [`crate::WriteStore`]: ordinary
/// file operations never enumerate or delete blobs, only a collect pass does.
pub trait GcStore {
    /// Every chunk id currently stored.
    fn all_chunk_ids(&self) -> Vec<ChunkId>;

    /// Every `(dir id, cipher name)` manifest key currently stored.
    fn all_manifest_keys(&self) -> Vec<(String, String)>;

    /// Removes a chunk, reporting the bytes freed (`0` if it was already gone).
    ///
    /// # Errors
    ///
    /// A store-specific I/O failure other than absence.
    fn delete_chunk(&mut self, id: &ChunkId) -> io::Result<u64>;

    /// Removes a manifest; absence is success.
    ///
    /// # Errors
    ///
    /// A store-specific I/O failure other than absence.
    fn delete_manifest(&mut self, dir_id: &str, cipher_name: &str) -> io::Result<()>;
}

/// What one [`collect`] pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Chunks the index references (and therefore kept).
    pub live_chunks: usize,
    /// Chunks deleted.
    pub removed_chunks: usize,
    /// Manifests deleted — ciphertext for files the index no longer names.
    pub removed_manifests: usize,
    /// Bytes freed by chunk removals.
    pub freed_bytes: u64,
}

/// Deletes everything `store` holds that no record in `index` references.
///
/// Manifests go first, chunks second: a pass interrupted in the middle then
/// leaves at worst extra orphan chunks for the next pass to take — never a
/// manifest whose chunks are gone.
///
/// # Errors
///
/// The store's first I/O failure.
///
/// # Concurrency
///
/// Run it while nothing else holds the pair — a live mount or a sync pass
/// writes index and store between these two enumerations, and content they add
/// after the liveness sets were built would look like an orphan. [`maybe_collect`]
/// is the policy-checked, lock-holding wrapper that enforces this.
pub fn collect(index: &dyn Index, store: &mut dyn GcStore) -> io::Result<GcReport> {
    let mut live_chunks: HashSet<ChunkId> = HashSet::new();
    let mut live_keys: HashSet<(String, String)> = HashSet::new();
    for entry in index.files() {
        live_chunks.extend(entry.chunk_ids);
        live_keys.insert((entry.dir_id.as_str().to_owned(), entry.cipher_name));
    }

    let mut report = GcReport {
        live_chunks: live_chunks.len(),
        ..GcReport::default()
    };

    for key in store.all_manifest_keys() {
        if !live_keys.contains(&key) {
            store.delete_manifest(&key.0, &key.1)?;
            report.removed_manifests += 1;
        }
    }

    for id in store.all_chunk_ids() {
        if !live_chunks.contains(&id) {
            report.freed_bytes += store.delete_chunk(&id)?;
            report.removed_chunks += 1;
        }
    }

    Ok(report)
}

/// When a sync pass should run [`collect`] without a human asking.
///
/// GC needs no password and no server: liveness is index-derived, so running
/// it early can only keep too much, never delete too little. What is left to
/// decide is only *how often* — each pass costs a store walk, so the policy
/// is a floor on the interval, not a safety mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GcPolicy {
    /// Only collect when a human runs `syncbox gc`.
    Off,
    /// Let [`maybe_collect`] run at most once per `seconds` — the default for
    /// a configured store.
    Interval {
        /// Minimum seconds between collects, persisted in the index.
        seconds: u64,
    },
}

impl GcPolicy {
    /// The shipped default: collect at most once a day.
    pub const DAILY: GcPolicy = GcPolicy::Interval {
        seconds: 24 * 60 * 60,
    };
}

/// The index meta key holding the unix time of the last collect attempt.
pub const LAST_GC_KEY: &str = "last_gc_unix";

/// What a [`maybe_collect`] call decided and did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MaybeGc {
    /// Policy is off, or the interval has not passed.
    NotDue,
    /// Due, but the store is held shared elsewhere — a live mount — so this
    /// round was skipped rather than queued.
    Busy,
    /// Collected. A zero-report means the store was already tight.
    Collected(GcReport),
}

/// The policy-checked, lock-holding face of [`collect`], for the end of a
/// sync pass.
///
/// `lock` is the caller's own *shared* store hold, taken at pass start; a due
/// pass upgrades it in place — atomic, so no second process's GC can slip in
/// mid-upgrade — and gives it back after. A garbage or missing stamp counts as
/// due (self-healing), and the stamp is written *before* collecting so a
/// collect that fails still backs off for one interval instead of retrying on
/// every pass.
///
/// # Errors
///
/// Lock or store I/O failure. (Stamping itself cannot fail: the index aborts
/// the process on a broken database, like every other index write.)
///
/// # Panics
///
/// Panics if the shared hold cannot be downgraded after collecting, which
/// leaves the lock exclusive for the guard's remaining lifetime — a bug, not
/// a condition.
pub fn maybe_collect(
    index: &mut dyn Index,
    store: &mut dyn GcStore,
    lock: &StoreLock,
    policy: GcPolicy,
    now_unix: i64,
) -> io::Result<MaybeGc> {
    let seconds = match policy {
        GcPolicy::Off => return Ok(MaybeGc::NotDue),
        GcPolicy::Interval { seconds } => seconds as i64,
    };
    let due = match index
        .meta_value(LAST_GC_KEY)
        .and_then(|stamp| stamp.parse::<i64>().ok())
    {
        Some(last) => now_unix.saturating_sub(last) >= seconds,
        None => true,
    };
    if !due {
        return Ok(MaybeGc::NotDue);
    }
    if !lock.try_upgrade()? {
        return Ok(MaybeGc::Busy);
    }
    index.set_meta_value(LAST_GC_KEY, &now_unix.to_string());
    let report = collect(index, store);
    // The collect took or failed — either way the visit is over; hand the
    // shared hold back before bubbling the result.
    lock.downgrade()
        .expect("downgrade of an exclusive store lock we own");
    Ok(MaybeGc::Collected(report?))
}

#[cfg(test)]
mod tests {
    use syncbox_crypto::names::DirId;
    use syncbox_crypto::{MasterKey, MasterKeys};
    use syncbox_index::{FileEntry, MemoryIndex};
    use syncbox_sync::Vault;

    use super::*;
    use crate::store::{DiskStore, MemoryStore, WriteStore};
    use crate::ContentStore;

    fn keys() -> MasterKeys {
        MasterKeys {
            primary: MasterKey::from_bytes(&[0x20; 32]).unwrap(),
            hmac: MasterKey::from_bytes(&[0x00; 32]).unwrap(),
        }
    }

    /// Seals `content` under `cipher_name` in `dir_id` into `store` and returns
    /// the index record that references it.
    fn stage(
        vault: &Vault,
        store: &mut dyn WriteStore,
        dir_id: &DirId,
        cipher_name: &str,
        content: &[u8],
    ) -> FileEntry {
        let sealed = vault.seal(dir_id, cipher_name, content).expect("seal");
        store
            .put_sealed(dir_id, cipher_name, &sealed)
            .expect("stage sealed");
        FileEntry {
            size: content.len() as u64,
            revision: 1,
            chunk_ids: sealed.chunk_ids.clone(),
            local_dirty: false,
            ..FileEntry::fresh(&format!("{cipher_name}.bin"), dir_id.clone(), cipher_name)
        }
    }

    fn root(vault: &Vault) -> DirId {
        vault.root().clone()
    }

    #[test]
    fn a_store_holding_exactly_the_live_file_is_left_whole() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let mut store = MemoryStore::new();
        let mut index = MemoryIndex::default();

        let e = stage(
            &vault,
            &mut store,
            &root(&vault),
            "LIVE",
            b"nothing here is collectable",
        );
        index.put_file(e.clone());

        let report = collect(&index, &mut store).expect("collect");
        assert_eq!(report.removed_chunks, 0);
        assert_eq!(report.removed_manifests, 0);
        assert_eq!(report.live_chunks, e.chunk_ids.len());
        assert!(store.manifest(&e.dir_id, "LIVE").is_some());
        for id in &e.chunk_ids {
            assert!(store.chunk(id).is_some(), "live chunk {id} vanished");
        }
    }

    #[test]
    fn an_unlinked_files_manifest_and_chunks_are_reclaimed() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let mut store = MemoryStore::new();
        let mut index = MemoryIndex::default();

        let e = stage(
            &vault,
            &mut store,
            &root(&vault),
            "GONE",
            b"this file will be unlinked",
        );
        index.put_file(e.clone());
        assert_eq!(collect(&index, &mut store).expect("gc").removed_chunks, 0);

        index.remove_file(&e.path);
        let report = collect(&index, &mut store).expect("collect");
        assert_eq!(report.removed_manifests, 1);
        assert_eq!(report.removed_chunks, e.chunk_ids.len());
        assert!(report.freed_bytes > 0);
        assert!(store.manifest(&e.dir_id, "GONE").is_none());
        assert!(store.all_chunk_ids().is_empty());

        // A second pass has nothing left to do.
        assert_eq!(
            collect(&index, &mut store).expect("idempotent"),
            GcReport::default()
        );
    }

    #[test]
    fn an_overwrite_lets_the_previous_generation_go() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let mut store = MemoryStore::new();
        let mut index = MemoryIndex::default();

        let r = root(&vault);
        let v1 = stage(
            &vault,
            &mut store,
            &r,
            "VER",
            b"the first version of the file",
        );
        index.put_file(v1);
        let v2 = stage(
            &vault,
            &mut store,
            &r,
            "VER",
            b"the second version, different bytes!",
        );
        index.put_file(v2.clone()); // replaces the record, same manifest key

        let report = collect(&index, &mut store).expect("collect");
        assert_eq!(
            report.removed_manifests, 0,
            "the live key was never orphaned"
        );
        assert!(
            report.removed_chunks > 0,
            "v1's now-unreferenced chunks must go"
        );
        assert_eq!(store.all_chunk_ids().len(), v2.chunk_ids.len());
        for id in &v2.chunk_ids {
            assert!(store.chunk(id).is_some(), "v2 chunk {id} vanished");
        }

        let fs = crate::Fs::from_entries([v2].iter());
        let got = fs
            .read_all(&vault, &store, "VER.bin")
            .expect("read v2 after gc");
        assert_eq!(got, b"the second version, different bytes!");
    }

    #[test]
    fn chunks_shared_with_a_live_file_survive() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let mut store = MemoryStore::new();
        let mut index = MemoryIndex::default();

        // Same content sealed under two names: the chunk is stored once, the
        // manifests differ.
        let shared = b"identical content dedupes to one chunk".to_vec();
        let r = root(&vault);
        let a = stage(&vault, &mut store, &r, "AAA", &shared);
        let b = stage(&vault, &mut store, &r, "BBB", &shared);
        index.put_file(a.clone());
        index.put_file(b.clone());

        index.remove_file(&a.path);
        let report = collect(&index, &mut store).expect("collect");
        assert_eq!(report.removed_manifests, 1, "only AAA's manifest goes");
        assert_eq!(report.removed_chunks, 0, "BBB still references the chunk");
        assert!(store.manifest(&b.dir_id, "BBB").is_some());
        for id in &b.chunk_ids {
            assert!(store.chunk(id).is_some());
        }
    }

    #[test]
    fn a_record_naming_a_missing_chunk_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let mut store = MemoryStore::new();
        let mut index = MemoryIndex::default();

        // A pull-style half state: the manifest is stored, its chunks are not.
        // The record is live, so the manifest stays and no chunk deletion is
        // even attempted — GC must not treat "index wants it, store lacks it"
        // as an error.
        let r = root(&vault);
        let sealed = vault.seal(&r, "PART", b"manifest only").expect("seal");
        store
            .put_manifest(&r, "PART", &sealed.manifest)
            .expect("put manifest");
        index.put_file(FileEntry {
            size: sealed.plaintext_size,
            revision: 1,
            chunk_ids: sealed.chunk_ids.clone(),
            local_dirty: false,
            ..FileEntry::fresh("PART.bin", r, "PART")
        });

        let report = collect(&index, &mut store).expect("collect");
        assert_eq!(report.removed_chunks, 0);
        assert_eq!(report.removed_manifests, 0);
        assert_eq!(report.live_chunks, sealed.chunk_ids.len());
    }

    #[test]
    fn the_refcounts_and_the_recomputed_live_set_agree_after_a_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let mut store = MemoryStore::new();
        let mut index = MemoryIndex::default();

        let r = root(&vault);
        let a = stage(&vault, &mut store, &r, "AAA", b"content A");
        let b = stage(&vault, &mut store, &r, "BBB", b"content B");
        index.put_file(a);
        index.put_file(b.clone());
        index.remove_file(&b.path);
        let report = collect(&index, &mut store).expect("collect");

        // The index's own reference counts say exactly what GC decided: B's
        // chunks are the unreferenced ones, and GC removed precisely them.
        let mut refcounted = index.unreferenced_chunks();
        let mut removed = b.chunk_ids.clone();
        refcounted.sort();
        removed.sort();
        assert_eq!(refcounted, removed);
        assert_eq!(report.removed_chunks, b.chunk_ids.len());
    }

    #[test]
    fn the_disk_store_is_pruned_and_its_shard_dirs_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let root_blobs = dir.path().join("blobs");
        let mut store = DiskStore::new(root_blobs.clone());
        let mut index = MemoryIndex::default();

        let keep = stage(
            &vault,
            &mut store,
            &root(&vault),
            "KEEP",
            b"a file that stays live",
        );
        // GONE lives under a different directory id, so its manifest shard
        // chain can empty out completely while KEEP's stays put.
        let other = DirId::from_base32("BBBBBBBBBB");
        let gone = stage(
            &vault,
            &mut store,
            &other,
            "GONE",
            b"a file that is about to go away",
        );
        index.put_file(keep.clone());
        index.put_file(gone.clone());
        assert_eq!(collect(&index, &mut store).expect("gc").removed_chunks, 0);

        index.remove_file(&gone.path);
        let report = collect(&index, &mut store).expect("collect");
        assert_eq!(report.removed_manifests, 1);
        assert!(report.removed_chunks >= 1);

        assert!(store.manifest(&gone.dir_id, "GONE").is_none());
        assert!(store.manifest(&keep.dir_id, "KEEP").is_some());
        for id in &keep.chunk_ids {
            assert!(store.chunk(id).is_some(), "live disk chunk {id} vanished");
        }

        // GONE's leaf files are really off disk, and their now-empty shard
        // directories were pruned away.
        let chars: Vec<char> = gone.dir_id.as_str().chars().collect();
        let manifest_chain: std::path::PathBuf = [
            "manifests",
            &chars[..2].iter().collect::<String>(),
            &chars[2..4].iter().collect::<String>(),
            gone.dir_id.as_str(),
        ]
        .into_iter()
        .collect();
        assert!(
            !root_blobs.join(&manifest_chain).exists(),
            "an emptied manifest shard chain is pruned"
        );
        assert!(
            root_blobs.join("manifests").exists(),
            "pruning never eats the store's own layout root"
        );
        for id in &gone.chunk_ids {
            let c: Vec<char> = id.as_str().chars().collect();
            let leaf: std::path::PathBuf = [
                "chunks",
                &c[..2].iter().collect::<String>(),
                &c[2..4].iter().collect::<String>(),
                id.as_str(),
            ]
            .into_iter()
            .collect();
            assert!(
                !root_blobs.join(leaf).exists(),
                "chunk blob {id} still on disk"
            );
        }
    }

    #[test]
    fn in_flight_temp_files_are_invisible_to_gc() {
        let dir = tempfile::tempdir().unwrap();
        let root_blobs = dir.path().join("blobs");
        let mut store = DiskStore::new(root_blobs.clone());
        let index = MemoryIndex::default();

        // A half-written chunk as write_blob leaves it mid-write: a .tmp file.
        let tmp = root_blobs
            .join("chunks")
            .join("ZZ")
            .join("ZY")
            .join("ABC.tmp");
        std::fs::create_dir_all(tmp.parent().unwrap()).unwrap();
        std::fs::write(&tmp, b"half a blob").unwrap();

        let report = collect(&index, &mut store).expect("collect");
        assert_eq!(report.removed_chunks, 0, "a .tmp leaf is not a chunk id");
        assert!(tmp.exists(), "and it is left alone for its writer");
    }

    /// An orphan waiting to be collected, plus the index that no longer names it.
    fn orphans(
        vault: &Vault,
        store: &mut MemoryStore,
        index: &mut MemoryIndex,
        name: &str,
    ) -> FileEntry {
        let e = stage(
            vault,
            store,
            &root(vault),
            name,
            b"bytes nobody will name again",
        );
        index.put_file(e.clone());
        index.remove_file(&e.path);
        e
    }

    #[test]
    fn the_first_due_pass_collects_and_stamps() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let mut store = MemoryStore::new();
        let mut index = MemoryIndex::default();
        let gone = orphans(&vault, &mut store, &mut index, "FIRST");
        let lock = StoreLock::shared(dir.path()).expect("shared lock");

        let out = maybe_collect(&mut index, &mut store, &lock, GcPolicy::DAILY, 1_000_000)
            .expect("due collect");
        match out {
            MaybeGc::Collected(report) => {
                assert_eq!(report.removed_chunks, gone.chunk_ids.len());
                assert_eq!(report.removed_manifests, 1);
            }
            other => panic!("expected a collection, got {other:?}"),
        }
        assert_eq!(
            index.meta_value(LAST_GC_KEY).as_deref(),
            Some("1000000"),
            "the stamp records the visit"
        );

        // The same pass asking again is simply not due.
        let out = maybe_collect(&mut index, &mut store, &lock, GcPolicy::DAILY, 1_000_001)
            .expect("not due");
        assert_eq!(out, MaybeGc::NotDue);
    }

    #[test]
    fn the_stamp_gates_the_next_day_and_moves_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let mut store = MemoryStore::new();
        let mut index = MemoryIndex::default();
        let lock = StoreLock::shared(dir.path()).expect("shared lock");

        index.set_meta_value(LAST_GC_KEY, "1000000");
        // One hour later: still inside a day's interval, store untouched.
        orphans(&vault, &mut store, &mut index, "WAIT");
        assert_eq!(
            maybe_collect(&mut index, &mut store, &lock, GcPolicy::DAILY, 1_003_600)
                .expect("interval holds"),
            MaybeGc::NotDue
        );
        assert!(store.manifest(&root(&vault), "WAIT").is_some());

        // Twenty-five hours on: due again, collects, and the stamp moves.
        let out = maybe_collect(&mut index, &mut store, &lock, GcPolicy::DAILY, 1_090_000)
            .expect("due again");
        assert!(matches!(out, MaybeGc::Collected(_)));
        assert_eq!(
            index.meta_value(LAST_GC_KEY).as_deref(),
            Some("1090000"),
            "the stamp rides with the pass that ran"
        );
    }

    #[test]
    fn off_never_collects_and_garbage_heals() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let mut store = MemoryStore::new();
        let mut index = MemoryIndex::default();
        orphans(&vault, &mut store, &mut index, "OFF");
        let lock = StoreLock::shared(dir.path()).expect("shared lock");

        assert_eq!(
            maybe_collect(&mut index, &mut store, &lock, GcPolicy::Off, 9_999_999)
                .expect("off is quiet"),
            MaybeGc::NotDue
        );
        assert_eq!(index.meta_value(LAST_GC_KEY), None, "off stamps nothing");

        // A stamp that is not a number must mean "due", not "never again".
        index.set_meta_value(LAST_GC_KEY, "not a timestamp");
        let out = maybe_collect(&mut index, &mut store, &lock, GcPolicy::DAILY, 2_000)
            .expect("garbage heals");
        assert!(matches!(out, MaybeGc::Collected(_)));
    }

    #[test]
    fn a_live_shared_holder_makes_the_round_busy_not_queued() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let mut store = MemoryStore::new();
        let mut index = MemoryIndex::default();
        let gone = orphans(&vault, &mut store, &mut index, "MOUNTED");
        // The sync pass's own hold, plus a mount's — the situation in the field.
        let ours = StoreLock::shared(dir.path()).expect("shared lock");
        let mount = StoreLock::shared(dir.path()).expect("mount hold");

        assert_eq!(
            maybe_collect(&mut index, &mut store, &ours, GcPolicy::DAILY, 1_000_000)
                .expect("busy is not an error"),
            MaybeGc::Busy,
            "GC skips a live mount rather than pruning in front of it"
        );
        assert_eq!(index.meta_value(LAST_GC_KEY), None, "a skip does not stamp");
        assert!(
            store.chunk(&gone.chunk_ids[0]).is_some(),
            "and nothing was collected"
        );

        drop(mount);
        assert!(matches!(
            maybe_collect(&mut index, &mut store, &ours, GcPolicy::DAILY, 1_000_000)
                .expect("mount gone"),
            MaybeGc::Collected(_)
        ));
    }

    #[test]
    fn a_failed_collect_still_stamps_so_retries_back_off() {
        struct Broken(MemoryStore);
        impl ContentStore for Broken {
            fn manifest(&self, d: &DirId, n: &str) -> Option<Vec<u8>> {
                self.0.manifest(d, n)
            }
            fn chunk(&self, id: &ChunkId) -> Option<Vec<u8>> {
                self.0.chunk(id)
            }
        }
        impl GcStore for Broken {
            fn all_chunk_ids(&self) -> Vec<ChunkId> {
                self.0.all_chunk_ids()
            }
            fn all_manifest_keys(&self) -> Vec<(String, String)> {
                self.0.all_manifest_keys()
            }
            fn delete_chunk(&mut self, _id: &ChunkId) -> io::Result<u64> {
                Err(io::Error::other("the disk said no"))
            }
            fn delete_manifest(&mut self, _d: &str, _n: &str) -> io::Result<()> {
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", dir.path()).expect("vault");
        let mut inner = MemoryStore::new();
        let mut index = MemoryIndex::default();
        orphans(&vault, &mut inner, &mut index, "BROKE");
        let mut store = Broken(inner);
        let lock = StoreLock::shared(dir.path()).expect("shared lock");

        let error = maybe_collect(&mut index, &mut store, &lock, GcPolicy::DAILY, 500)
            .expect_err("the store's no bubbles up");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            index.meta_value(LAST_GC_KEY).as_deref(),
            Some("500"),
            "the failed round still stamps: back off a day, not hammer every pass"
        );

        // And the shared hold came back: a mount may still join.
        assert!(StoreLock::shared(dir.path()).is_ok());
        drop(lock);
        assert!(
            StoreLock::try_exclusive(dir.path())
                .expect("free")
                .is_some(),
            "the failure left no lock stuck exclusive"
        );
    }
}
