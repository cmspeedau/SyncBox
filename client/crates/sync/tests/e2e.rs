//! End-to-end sync against an in-process fake server.
//!
//! This is the harness the milestone is judged on: a real `Engine` moving a real
//! plaintext folder, over the real `transport::Client`, against a server that
//! behaves like `server/internal/store` (content-addressed chunks stored once; a
//! global, ordered revision log where a commit needs the current head; tombstones
//! for deletes). Everything is hermetic — temp directories and this fake — so it
//! runs in `cargo test` with no daemon. The Go server's own tests cover its side of
//! the same contract.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::json;
use syncbox_crypto::names::DirId;
use syncbox_crypto::{ChunkId, MasterKey, MasterKeys};
use syncbox_index::{FileEntry, Index, MemoryIndex};
use syncbox_sync::{ContentStore, Engine, PullStore, SyncError, Vault};
use syncbox_transport::{Client, Http, Request, Response, Result as TResult, TransportError};

// ---- the fake server ---------------------------------------------------------

/// One committed revision as the fake stores it (no vault_id needed: it keys by
/// the path, like the real store).
#[derive(Clone)]
struct Stored {
    revision: u64,
    parent: u64,
    dir_id: String,
    cipher_name: String,
    manifest: String,
    size: u64,
    modified_unix: i64,
    deleted: bool,
}

#[derive(Deserialize)]
struct CommitWire {
    parent: u64,
    revision: RevisionWire,
}

#[derive(Deserialize)]
struct RevisionWire {
    #[serde(default)]
    #[allow(dead_code)]
    revision: u64,
    parent: u64,
    dir_id: String,
    cipher_name: String,
    manifest: String,
    size: u64,
    modified_unix: i64,
    deleted: bool,
}

#[derive(Serialize)]
struct RevisionOut {
    revision: u64,
    parent: u64,
    dir_id: String,
    cipher_name: String,
    manifest: String,
    size: u64,
    modified_unix: i64,
    deleted: bool,
}

/// The in-memory stand-in for the Go API + store.
#[derive(Default)]
struct FakeServer {
    chunks: HashMap<String, Vec<u8>>,
    log: Vec<Stored>, // a single vault's global revision log
    /// When set, the Nth chunk PUT attempt (1-based) fails as a dropped
    /// connection — the shape of a sync interrupted mid-transfer.
    fail_put_number: Option<usize>,
    /// The same for chunk GETs.
    fail_get_number: Option<usize>,
    /// Attempts and successes, so a resume test can prove the client never
    /// re-sent or re-fetched what the server already had.
    put_attempts: usize,
    put_ok: usize,
    get_attempts: usize,
    get_ok: usize,
}

impl FakeServer {
    fn head(&self) -> u64 {
        self.log.last().map_or(0, |r| r.revision)
    }

    fn json(status: u16, value: &impl Serialize) -> Response {
        Response {
            status,
            body: serde_json::to_vec(value).expect("serialisable"),
        }
    }

    fn error(&self, status: u16, code: &str, reason: &str) -> Response {
        Response {
            status,
            body: serde_json::to_vec(&json!({ "code": code, "reason": reason }))
                .expect("serialisable"),
        }
    }

    fn handle(&mut self, request: Request) -> TResult<Response> {
        let (path, query) = match request.path.split_once('?') {
            Some((p, q)) => (p, q),
            None => (request.path.as_str(), ""),
        };

        // The token endpoint is the only unauthenticated one.
        if request.method.as_str() == "POST" && path == "/api/v1/auth/token" {
            return Ok(Self::json(
                200,
                &json!({ "token": "tok", "expires_unix": i64::MAX }),
            ));
        }
        if request.authorization.as_deref() != Some("Bearer tok") {
            return Ok(self.error(401, "unauthorized", "missing or bad token"));
        }

        let rest = path
            .strip_prefix("/api/v1/vaults/")
            .ok_or_else(|| TransportError::Malformed(format!("unknown path {path}")))?;
        let (_vault, tail) = rest
            .split_once('/')
            .ok_or_else(|| TransportError::Malformed("no tail".into()))?;

        match (request.method.as_str(), tail) {
            ("GET", "revisions") => self.list_revisions(query),
            ("POST", "revisions") => self.commit(&request.body),
            ("POST", "chunks/exists") => self.chunks_exist(&request.body),
            ("PUT", other) if other.starts_with("chunks/") => {
                self.put_attempts += 1;
                if self.fail_put_number == Some(self.put_attempts) {
                    return Err(TransportError::Transport(
                        "the test dropped the upload".into(),
                    ));
                }
                let id = &other["chunks/".len()..];
                self.chunks
                    .entry(id.to_owned())
                    .or_insert_with(|| request.body.clone());
                self.put_ok += 1;
                Ok(Self::json(201, &json!({ "stored": request.body.len() })))
            }
            ("GET", other) if other.starts_with("chunks/") => {
                self.get_attempts += 1;
                if self.fail_get_number == Some(self.get_attempts) {
                    return Err(TransportError::Transport(
                        "the test dropped the download".into(),
                    ));
                }
                let id = &other["chunks/".len()..];
                match self.chunks.get(id) {
                    Some(bytes) => {
                        self.get_ok += 1;
                        Ok(Response {
                            status: 200,
                            body: bytes.clone(),
                        })
                    }
                    None => Ok(self.error(404, "not_found", "no such chunk")),
                }
            }
            _ => Ok(self.error(404, "not_found", "no such route")),
        }
    }

    fn list_revisions(&self, query: &str) -> TResult<Response> {
        let since = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("since="))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let revisions: Vec<RevisionOut> = self
            .log
            .iter()
            .filter(|r| r.revision > since)
            .map(|r| RevisionOut {
                revision: r.revision,
                parent: r.parent,
                dir_id: r.dir_id.clone(),
                cipher_name: r.cipher_name.clone(),
                manifest: r.manifest.clone(),
                size: r.size,
                modified_unix: r.modified_unix,
                deleted: r.deleted,
            })
            .collect();
        Ok(Self::json(
            200,
            &json!({ "revisions": revisions, "upto": self.head() }),
        ))
    }

    fn commit(&mut self, body: &[u8]) -> TResult<Response> {
        let request: CommitWire = serde_json::from_slice(body)
            .map_err(|e| TransportError::Malformed(format!("commit body: {e}")))?;
        let head = self.head();
        if request.parent != head || request.revision.parent != head {
            return Ok(self.error(409, "conflict", "parent is not the head"));
        }
        let stored = Stored {
            revision: head + 1,
            parent: head,
            dir_id: request.revision.dir_id,
            cipher_name: request.revision.cipher_name,
            manifest: request.revision.manifest,
            size: request.revision.size,
            modified_unix: request.revision.modified_unix,
            deleted: request.revision.deleted,
        };
        let assigned = stored.revision;
        self.log.push(stored);
        Ok(Self::json(201, &json!({ "revision": assigned })))
    }

    fn chunks_exist(&self, body: &[u8]) -> TResult<Response> {
        let request: HashMap<String, Vec<String>> = serde_json::from_slice(body)
            .map_err(|e| TransportError::Malformed(format!("exists body: {e}")))?;
        let ids = request.get("ids").cloned().unwrap_or_default();
        let missing: Vec<String> = ids
            .into_iter()
            .filter(|id| !self.chunks.contains_key(id))
            .collect();
        Ok(Self::json(200, &json!({ "missing": missing })))
    }
}

/// The fake wrapped so several clients share one store, as clients of one server
/// would. A newtype so the `Http` impl is for a local type.
#[derive(Clone)]
struct Shared(Rc<RefCell<FakeServer>>);

impl Http for Shared {
    fn send(&mut self, request: Request) -> TResult<Response> {
        self.0.borrow_mut().handle(request)
    }
}

// ---- harness -----------------------------------------------------------------

fn keys() -> MasterKeys {
    MasterKeys {
        primary: MasterKey::from_bytes(&[0x20; 32]).unwrap(),
        hmac: MasterKey::from_bytes(&[0x00; 32]).unwrap(),
    }
}

/// A client on the shared fake, already authenticated.
fn client(shared: &Shared) -> Client<Shared> {
    let mut client = Client::new("http://fake.test", shared.clone());
    client.token("password").expect("token");
    client
}

fn engine(client_root: &Path) -> Engine<MemoryIndex> {
    let vault = Vault::new(keys(), "vault", client_root).expect("vault");
    Engine::new(MemoryIndex::new(), vault)
}

fn read_client(root: &Path, rel: &str) -> Option<Vec<u8>> {
    std::fs::read(root.join(rel)).ok()
}

fn write_client(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn push_then_pull_reproduces_the_file() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();

    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    write_client(a_root.path(), "hello.txt", b"hello from a");
    let report = a.sync_once(&mut a_client, "2026-10-16").unwrap();
    assert_eq!(report.uploaded, 1);
    assert!(report.chunks_uploaded >= 1);
    assert!(!report.is_quiet(), "an upload is not a quiet pass");

    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(report.downloaded, 1);
    assert_eq!(
        read_client(b_root.path(), "hello.txt").as_deref(),
        Some(&b"hello from a"[..]),
        "B reproduces A's bytes"
    );

    // A settled vault now has nothing to do.
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert!(report.is_quiet(), "no drift on a settled pass: {report:?}");
}

#[test]
fn an_early_edit_uploads_only_the_chunks_that_changed() {
    use syncbox_crypto::content::{CHUNK_MIN, CHUNK_TARGET};

    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);

    // Several chunks' worth of high-entropy bytes; content-defined splitting gives
    // roughly one chunk per ~128 KiB here, so this lands on a dozen or more.
    let original = pseudorandom(CHUNK_TARGET * 16);
    write_client(a_root.path(), "big.bin", &original);
    let first = a.sync_once(&mut a_client, "2026-10-16").unwrap();
    assert!(first.chunks_uploaded >= 4, "a multi-chunk file uploaded");

    // Insert a chunk-sized blob near the front, shifting every later byte.
    let mut edited = original.clone();
    edited.splice(1..1, pseudorandom(CHUNK_MIN));
    write_client(a_root.path(), "big.bin", &edited);

    let second = a.sync_once(&mut a_client, "2026-10-16").unwrap();
    assert_eq!(second.uploaded, 1, "one file re-committed");
    assert!(
        second.chunks_uploaded < first.chunks_uploaded,
        "delta: uploaded {} of {} chunks, later chunks were reused",
        second.chunks_uploaded,
        first.chunks_uploaded
    );

    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(
        read_client(b_root.path(), "big.bin").as_deref(),
        Some(&edited[..]),
        "B rebuilds the edited file byte for byte"
    );
}

#[test]
fn a_both_sides_edit_becomes_a_conflicted_copy() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);

    // Both start from the same synced content.
    write_client(a_root.path(), "notes.txt", b"base");
    a.sync_once(&mut a_client, "2026-10-16").unwrap();
    b.sync_once(&mut b_client, "2026-10-16").unwrap();

    // Then both diverge before either syncs.
    write_client(a_root.path(), "notes.txt", b"a's version");
    write_client(b_root.path(), "notes.txt", b"b's version");

    // A wins the canonical name.
    a.sync_once(&mut a_client, "2026-10-16").unwrap();

    // B, behind on the server but with its own edits, keeps them as a copy.
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(report.conflicts, 1, "B recorded one conflict");

    assert_eq!(
        read_client(b_root.path(), "notes.txt").as_deref(),
        Some(&b"a's version"[..]),
        "the server's winner takes the canonical name"
    );
    let copy = "notes (conflicted copy 2026-10-16).txt";
    assert_eq!(
        read_client(b_root.path(), copy).as_deref(),
        Some(&b"b's version"[..]),
        "B's own bytes survive under a conflicted name"
    );

    // A eventually learns about B's copy as a new file.
    a.sync_once(&mut a_client, "2026-10-16").unwrap();
    assert_eq!(
        read_client(a_root.path(), copy).as_deref(),
        Some(&b"b's version"[..]),
        "A pulls B's conflicted copy too, so nothing is lost"
    );
}

#[test]
fn a_local_delete_propagates_as_a_tombstone() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);

    write_client(a_root.path(), "gone.txt", b"temporary");
    a.sync_once(&mut a_client, "2026-10-16").unwrap();
    b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert!(read_client(b_root.path(), "gone.txt").is_some());

    std::fs::remove_file(a_root.path().join("gone.txt")).unwrap();
    let report = a.sync_once(&mut a_client, "2026-10-16").unwrap();
    assert_eq!(report.deleted, 1, "the delete is committed");

    b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(
        read_client(b_root.path(), "gone.txt"),
        None,
        "B removes the file the tombstone deletes"
    );
}

#[test]
fn a_file_in_a_shared_subdirectory_round_trips() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    // Both peers share the directory structure, so the child dir id is known to
    // both and the file can be placed (a peer-only directory an id cannot name is
    // out of scope and is skipped).
    std::fs::create_dir_all(a_root.path().join("docs")).unwrap();
    std::fs::create_dir_all(b_root.path().join("docs")).unwrap();

    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    write_client(a_root.path(), "docs/report.md", b"# title");
    a.sync_once(&mut a_client, "2026-10-16").unwrap();

    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(report.downloaded, 1);
    assert_eq!(report.skipped, 0, "the known directory let it be placed");
    assert_eq!(
        read_client(b_root.path(), "docs/report.md").as_deref(),
        Some(&b"# title"[..])
    );
}

/// A deterministic pseudorandom buffer with enough entropy that the content-defined
/// splitter produces many chunks (rather than one run of a repeated byte).
fn pseudorandom(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    for _ in 0..len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.push((state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8);
    }
    out
}

// ---- the pull→store tee ------------------------------------------------------

/// A [`PullStore`] that records what a pull downloaded, behind a shared handle so the
/// test can inspect it after the engine (which owns the store) has synced. This stands
/// in for the local ciphertext store a mounted vault reads from. `Arc<Mutex<..>>` so it
/// satisfies the engine's `Send + Sync` store bound, as a real threaded client's would.
#[derive(Clone, Default)]
struct TeeStore(Arc<Mutex<Tee>>);

#[derive(Default)]
struct Tee {
    manifests: HashMap<(String, String), Vec<u8>>,
    chunks: HashMap<String, Vec<u8>>,
}

impl PullStore for TeeStore {
    fn cache_chunk(&mut self, id: &ChunkId, bytes: &[u8]) -> std::io::Result<()> {
        self.0
            .lock()
            .unwrap()
            .chunks
            .insert(id.as_str().to_owned(), bytes.to_vec());
        Ok(())
    }

    fn cache_manifest(
        &mut self,
        dir_id: &DirId,
        cipher_name: &str,
        manifest: &[u8],
    ) -> std::io::Result<()> {
        self.0.lock().unwrap().manifests.insert(
            (dir_id.as_str().to_owned(), cipher_name.to_owned()),
            manifest.to_vec(),
        );
        Ok(())
    }
}

// The tee is also readable, so a folderless engine can push dirty records back out of
// it — the same two lookups the engine makes against a real `DiskStore`.
impl ContentStore for TeeStore {
    fn manifest(&self, dir_id: &DirId, cipher_name: &str) -> Option<Vec<u8>> {
        self.0
            .lock()
            .unwrap()
            .manifests
            .get(&(dir_id.as_str().to_owned(), cipher_name.to_owned()))
            .cloned()
    }

    fn chunk(&self, id: &ChunkId) -> Option<Vec<u8>> {
        self.0.lock().unwrap().chunks.get(id.as_str()).cloned()
    }
}

/// Stages a file the way a mount write would: seal it through the vault, drop the
/// manifest + chunks into the store, and record a **dirty** index entry. No plaintext
/// file is ever written — this is the state a folderless push has to notice and ship.
fn stage_dirty(tee: &TeeStore, index: &mut MemoryIndex, vault: &Vault, path: &str, bytes: &[u8]) {
    let (dir_id, cipher_name, _name) = vault.locate(path).unwrap();
    let sealed = vault.seal(&dir_id, &cipher_name, bytes).unwrap();
    tee.0.lock().unwrap().manifests.insert(
        (dir_id.as_str().to_owned(), cipher_name.clone()),
        sealed.manifest.clone(),
    );
    for (id, stored) in &sealed.chunks {
        tee.0
            .lock()
            .unwrap()
            .chunks
            .insert(id.as_str().to_owned(), stored.clone());
    }
    let mut entry = FileEntry::fresh(path, dir_id, &cipher_name);
    entry.chunk_ids = sealed.chunk_ids;
    entry.size = bytes.len() as u64;
    index.put_file(entry);
}

#[test]
fn a_pull_populates_a_store_a_mount_can_read_from() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(b_root.path().join("docs")).unwrap();

    // A uploads a file into a subdirectory.
    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    write_client(a_root.path(), "docs/report.md", b"# server-only content");
    a.sync_once(&mut a_client, "2026-10-16").unwrap();

    // B pulls, with a local content store installed on the engine.
    let tee = TeeStore::default();
    let store = tee.clone(); // a second handle to the same recording
    let mut b = engine(b_root.path()).with_store(store);
    let mut b_client = client(&shared);
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(report.downloaded, 1, "B downloaded A's file");

    // The store now holds the manifest and chunks for that file, under its vault
    // coordinates — independently enough to decrypt it WITHOUT the server or B's copy
    // on disk, which is exactly what a read-only mount does via `Vault::open`.
    let (dir_id, cipher_name, _name) = b.vault.locate("docs/report.md").unwrap();
    let recorded = tee.0.lock().unwrap();
    let manifest = recorded
        .manifests
        .get(&(dir_id.as_str().to_owned(), cipher_name.clone()))
        .expect("the pull stored the manifest under the file's coordinates");
    let (plaintext, ids) = b
        .vault
        .open(&dir_id, &cipher_name, manifest, &mut |id| {
            recorded
                .chunks
                .get(id.as_str())
                .cloned()
                .ok_or(SyncError::Integrity("chunk missing from tee store"))
        })
        .expect("reconstructs from the store alone");
    assert_eq!(plaintext, b"# server-only content");
    assert!(!ids.is_empty(), "the chunk ids were recorded");
}

// ---- folderless sync (the mount is the interface) ----------------------------

#[test]
fn a_folderless_push_ships_dirty_store_records_and_their_tombstones() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let vault_dir = tempfile::tempdir().unwrap();
    let tee = TeeStore::default();
    let mut e = engine(vault_dir.path())
        .with_store(tee.clone())
        .folderless();

    // Two mount-writes, staged the way FsMut leaves them: content in the store,
    // dirty records in the index, no plaintext on disk anywhere.
    stage_dirty(
        &tee,
        &mut e.index,
        &e.vault,
        "plan.txt",
        b"written through the mount",
    );
    stage_dirty(&tee, &mut e.index, &e.vault, "notes.md", b"# mount notes");

    let mut e_client = client(&shared);
    let report = e.sync_once(&mut e_client, "2026-10-16").unwrap();
    assert_eq!(report.uploaded, 2, "both dirty records reached the server");
    assert!(e.index.file("plan.txt").unwrap().is_clean());
    assert!(
        !vault_dir.path().join("plan.txt").exists(),
        "a folderless pass writes no plaintext"
    );

    // A plain folder client pulls both — the push went through the normal pipeline.
    let b_root = tempfile::tempdir().unwrap();
    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(report.downloaded, 2);
    assert_eq!(
        read_client(b_root.path(), "plan.txt").unwrap(),
        b"written through the mount"
    );
    assert_eq!(
        read_client(b_root.path(), "notes.md").unwrap(),
        b"# mount notes"
    );

    // The mount deletes a file: exactly the bookkeeping FsMut::unlink leaves behind.
    let entry = e.index.file("plan.txt").unwrap();
    e.index.note_delete(&entry);
    e.index.remove_file("plan.txt");
    let report = e.sync_once(&mut e_client, "2026-10-16").unwrap();
    assert_eq!(report.deleted, 1, "the queued tombstone is committed");
    assert!(
        e.index.pending_deletes().is_empty(),
        "the queue drains only once the server has it"
    );

    // The folder client mirrors the deletion.
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(report.deleted, 1);
    assert!(read_client(b_root.path(), "plan.txt").is_none());
}

#[test]
fn a_folderless_local_edit_outranks_a_newer_server_revision() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let vault_dir = tempfile::tempdir().unwrap();
    let tee = TeeStore::default();
    let mut e = engine(vault_dir.path())
        .with_store(tee.clone())
        .folderless();
    let mut e_client = client(&shared);

    stage_dirty(
        &tee,
        &mut e.index,
        &e.vault,
        "shared.txt",
        b"v1 from the mount",
    );
    e.sync_once(&mut e_client, "2026-10-16").unwrap();

    // B (a folder client) pulls v1, then commits its own v2.
    let b_root = tempfile::tempdir().unwrap();
    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    b.sync_once(&mut b_client, "2026-10-16").unwrap();
    write_client(b_root.path(), "shared.txt", b"v2 from the folder client");
    b.sync_once(&mut b_client, "2026-10-16").unwrap();

    // Back on the mount device, a fresh edit is dirty when the pass runs: the server
    // is newer, but the store's bytes are this device's newest word.
    stage_dirty(
        &tee,
        &mut e.index,
        &e.vault,
        "shared.txt",
        b"v2 from the mount",
    );
    let report = e.sync_once(&mut e_client, "2026-10-16").unwrap();
    assert_eq!(
        report.conflicts, 1,
        "the newer server revision meets a dirty record"
    );
    assert_eq!(
        report.downloaded, 0,
        "nothing was pulled over the local edit"
    );
    assert_eq!(report.uploaded, 1, "our edit is committed over it");

    // The mount's bytes win the canonical name; B picks them up next pass (with its
    // own v2 kept as a conflicted copy, folder mode's usual rescue).
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(report.downloaded, 1);
    assert_eq!(
        read_client(b_root.path(), "shared.txt").unwrap(),
        b"v2 from the mount"
    );
}

// ---- conflict edge cases ------------------------------------------------------

#[test]
fn a_peer_rename_lands_as_a_rename_not_a_conflict() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    write_client(a_root.path(), "plan.txt", b"the only version");
    a.sync_once(&mut a_client, "2026-10-16").unwrap();

    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    b.sync_once(&mut b_client, "2026-10-16").unwrap();

    // A renames, and syncs the tombstone-plus-new-name pair.
    std::fs::rename(
        a_root.path().join("plan.txt"),
        a_root.path().join("plan-final.txt"),
    )
    .unwrap();
    let report = a.sync_once(&mut a_client, "2026-10-16").unwrap();
    assert_eq!(report.deleted, 1, "the old name was tombstoned");
    assert_eq!(report.uploaded, 1, "the new name was committed");
    assert_eq!(report.conflicts, 0);

    // B sees the same move, with no conflict: an unchanged local copy under a
    // tombstoned name simply goes away, and the new name lands beside it.
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(report.conflicts, 0, "a clean copy stashes nothing");
    assert_eq!(report.deleted, 1);
    assert_eq!(report.downloaded, 1);
    assert!(read_client(b_root.path(), "plan.txt").is_none());
    assert_eq!(
        read_client(b_root.path(), "plan-final.txt").as_deref(),
        Some(&b"the only version"[..])
    );

    a.sync_once(&mut a_client, "2026-10-16").unwrap();
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert!(report.is_quiet(), "the rename is fully settled: {report:?}");
}

#[test]
fn a_rename_and_a_peer_edit_both_survive() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    write_client(a_root.path(), "x.txt", b"base");
    a.sync_once(&mut a_client, "2026-10-16").unwrap();

    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    b.sync_once(&mut b_client, "2026-10-16").unwrap();

    // A renames x away before syncing; meanwhile B edits x and syncs first.
    std::fs::rename(a_root.path().join("x.txt"), a_root.path().join("y.txt")).unwrap();
    write_client(b_root.path(), "x.txt", b"b's edit");
    b.sync_once(&mut b_client, "2026-10-16").unwrap();

    // A's pass: the peer's edited x comes back down (its name is not A's to
    // steal), and the rename goes up as a new file. Two names, nothing lost.
    let report = a.sync_once(&mut a_client, "2026-10-16").unwrap();
    assert_eq!(report.downloaded, 1, "B's edited x was pulled");
    assert_eq!(report.uploaded, 1, "the renamed y was committed");
    assert_eq!(report.conflicts, 0);
    assert_eq!(
        read_client(a_root.path(), "x.txt").as_deref(),
        Some(&b"b's edit"[..])
    );
    assert_eq!(
        read_client(a_root.path(), "y.txt").as_deref(),
        Some(&b"base"[..])
    );

    // B learns y; its x is already current. Both settle.
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(report.downloaded, 1);
    assert_eq!(
        read_client(b_root.path(), "y.txt").as_deref(),
        Some(&b"base"[..])
    );
    a.sync_once(&mut a_client, "2026-10-16").unwrap();
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert!(report.is_quiet(), "both names settled: {report:?}");
}

#[test]
fn a_peer_delete_stashes_my_unsynced_edit_as_a_conflicted_copy() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    write_client(a_root.path(), "note.txt", b"shared");
    a.sync_once(&mut a_client, "2026-10-16").unwrap();

    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    b.sync_once(&mut b_client, "2026-10-16").unwrap();

    // B deletes and commits the tombstone while A's own edit never made it up.
    std::fs::remove_file(b_root.path().join("note.txt")).unwrap();
    b.sync_once(&mut b_client, "2026-10-16").unwrap();
    write_client(a_root.path(), "note.txt", b"my unsynced edit");

    // A's pass: the tombstone takes the canonical name, but A's drifted bytes
    // are stashed as a conflicted copy first — and uploaded as a new file.
    let report = a.sync_once(&mut a_client, "2026-10-16").unwrap();
    assert_eq!(report.conflicts, 1, "the drifted local copy was stashed");
    assert_eq!(report.deleted, 1, "the tombstone still landed locally");
    assert_eq!(report.uploaded, 1, "the copy was pushed as its own file");
    assert!(read_client(a_root.path(), "note.txt").is_none());
    let copy = "note (conflicted copy 2026-10-16).txt";
    assert_eq!(
        read_client(a_root.path(), copy).as_deref(),
        Some(&b"my unsynced edit"[..]),
        "an unsynced edit must not vanish under a peer's delete"
    );

    // B sees the rescued copy on its next pass.
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(report.downloaded, 1);
    assert_eq!(
        read_client(b_root.path(), copy).as_deref(),
        Some(&b"my unsynced edit"[..])
    );
}

#[test]
fn a_server_edit_outranks_a_local_delete() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    write_client(a_root.path(), "f.txt", b"base");
    a.sync_once(&mut a_client, "2026-10-16").unwrap();

    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    b.sync_once(&mut b_client, "2026-10-16").unwrap();

    // A deletes locally (nothing synced about it) while B edits and commits.
    std::fs::remove_file(a_root.path().join("f.txt")).unwrap();
    write_client(b_root.path(), "f.txt", b"b's newer edit");
    b.sync_once(&mut b_client, "2026-10-16").unwrap();

    // The server holds a NEWER revision of f.txt, not a tombstone, so A's
    // delete-vs-edit resolves server-wins: the file comes back down and A
    // commits nothing. (This is the counterpart of a_peer_delete_…: deletes
    // and edits are only tombstones-versus-revisions, never both at once.)
    let report = a.sync_once(&mut a_client, "2026-10-16").unwrap();
    assert_eq!(report.downloaded, 1, "the newer server revision came back");
    assert_eq!(
        report.uploaded, 0,
        "A's empty-handed delete committed nothing"
    );
    assert_eq!(report.deleted, 0);
    assert_eq!(
        read_client(a_root.path(), "f.txt").as_deref(),
        Some(&b"b's newer edit"[..])
    );
    let report = a.sync_once(&mut a_client, "2026-10-16").unwrap();
    assert!(
        report.is_quiet(),
        "resurrected and settled in one pass: {report:?}"
    );
}

#[test]
fn a_folderless_dirty_record_outranks_a_tombstone_and_revives_the_file() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let vault_dir = tempfile::tempdir().unwrap();
    let tee = TeeStore::default();
    let mut e = engine(vault_dir.path())
        .with_store(tee.clone())
        .folderless();
    let mut e_client = client(&shared);

    stage_dirty(&tee, &mut e.index, &e.vault, "doc.txt", b"v1");
    e.sync_once(&mut e_client, "2026-10-16").unwrap();

    // B pulls, then deletes the file for everyone.
    let b_root = tempfile::tempdir().unwrap();
    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    b.sync_once(&mut b_client, "2026-10-16").unwrap();
    std::fs::remove_file(b_root.path().join("doc.txt")).unwrap();
    b.sync_once(&mut b_client, "2026-10-16").unwrap();

    // The mount writes again: a dirty record meets the peer's tombstone. Folder
    // mode's rule (the local edit wins the canonical name) applies unchanged —
    // a delete is just another newer revision, and loses to local-wins.
    stage_dirty(
        &tee,
        &mut e.index,
        &e.vault,
        "doc.txt",
        b"v2 after the delete",
    );
    let report = e.sync_once(&mut e_client, "2026-10-16").unwrap();
    assert_eq!(report.conflicts, 1, "the tombstone met a dirty record");
    assert_eq!(
        report.uploaded, 1,
        "our record committed over the tombstone"
    );
    assert_eq!(report.deleted, 0, "the tombstone was not echoed back down");

    // B, which deleted the file, now sees it revived with the mount's bytes —
    // the cost of local-wins, paid in resurrection rather than lost edits.
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(report.downloaded, 1);
    assert_eq!(
        read_client(b_root.path(), "doc.txt").as_deref(),
        Some(&b"v2 after the delete"[..])
    );
}

#[test]
fn both_sides_deleting_the_same_file_converges_quietly() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    write_client(a_root.path(), "gone.txt", b"doomed");
    a.sync_once(&mut a_client, "2026-10-16").unwrap();

    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    b.sync_once(&mut b_client, "2026-10-16").unwrap();

    // Both delete; A commits the tombstone first, and B's copy is already gone
    // when the tombstone arrives — nothing to stash, nothing to echo back.
    std::fs::remove_file(a_root.path().join("gone.txt")).unwrap();
    a.sync_once(&mut a_client, "2026-10-16").unwrap();
    std::fs::remove_file(b_root.path().join("gone.txt")).unwrap();
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(report.deleted, 1, "B applied the server's tombstone");
    assert_eq!(report.conflicts, 0);
    assert_eq!(report.uploaded, 0);

    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert!(report.is_quiet(), "one tombstone for one death: {report:?}");
    let report = a.sync_once(&mut a_client, "2026-10-16").unwrap();
    assert!(report.is_quiet(), "A agrees: {report:?}");
}

#[test]
fn unicode_and_case_distinct_names_round_trip() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    let b_root = tempfile::tempdir().unwrap();

    // Names the whole pipeline must carry byte-exactly: case-distinct siblings
    // in one directory, unicode directories that differ only by case, spaces
    // and combining-ish scripts in file names.
    let files: &[(&str, &[u8])] = &[
        ("S.txt", b"capital"),
        ("s.txt", b"small"),
        ("Café/ÄÖÜ.txt", b"upper dir"),
        ("café/äöü.txt", b"lower dir"),
        ("sp ace/naïve ✓.md", b"spaces and ticks"),
    ];
    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    for (name, bytes) in files {
        write_client(a_root.path(), name, bytes);
    }
    let report = a.sync_once(&mut a_client, "2026-10-16").unwrap();
    assert_eq!(report.uploaded, files.len());

    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    // The peer's subdirectories exist on B too — the engine names files under
    // directories it can resolve, and a directory that exists nowhere local is
    // unnameable from an opaque id (a documented skip, not this test's subject).
    // B's OWN unicode dirs must map to the same ids A's words encrypt to,
    // case-distinctly: that resolution is exactly what is under test here.
    for dir in ["Café", "café", "sp ace"] {
        std::fs::create_dir_all(b_root.path().join(dir)).unwrap();
    }
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(
        report.downloaded,
        files.len(),
        "every distinct name arrived"
    );
    assert_eq!(report.skipped, 0, "no name failed to resolve");
    for (name, bytes) in files {
        assert_eq!(
            read_client(b_root.path(), name).as_deref(),
            Some(*bytes),
            "{name} round-tripped"
        );
    }

    a.sync_once(&mut a_client, "2026-10-16").unwrap();
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert!(report.is_quiet(), "no case folding, no churn: {report:?}");
}

// ---- interruption and resume --------------------------------------------------

/// Pseudo-random bytes from a fixed LCG: no early repetition (so every chunk is
/// distinct and a resume cannot dedup past what it must prove) and no pattern
/// the content-defined chunker could ride past its target — a fixed length cuts
/// into several chunks.
fn filler(len: usize) -> Vec<u8> {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

#[test]
fn a_push_dropped_midway_resumes_from_the_chunks_already_uploaded() {
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    let bytes = filler(200_000);
    write_client(a_root.path(), "video.part", &bytes);

    // The third chunk's transfer dies: the pass ends in error with the first two
    // landed and no commit made — the record is still dirty by construction.
    shared.0.borrow_mut().fail_put_number = Some(3);
    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    assert!(
        a.sync_once(&mut a_client, "2026-10-16").is_err(),
        "a dropped transfer must fail the pass, not pretend"
    );
    assert_eq!(
        shared.0.borrow().chunks.len(),
        2,
        "the first two chunks landed"
    );

    // The next pass re-offers every chunk and uploads only the server's shortfall:
    // resume is what content addressing already promises, and this pins it.
    let mut a2 = engine(a_root.path());
    let mut a_client2 = client(&shared);
    let report = a2.sync_once(&mut a_client2, "2026-10-16").unwrap();
    let total = shared.0.borrow().chunks.len();
    assert!(
        total >= 3,
        "the fixture must span several chunks; got {total}"
    );
    assert_eq!(report.uploaded, 1);
    assert_eq!(
        report.chunks_uploaded,
        total - 2,
        "only the missing chunks went up the second time"
    );
    assert_eq!(
        shared.0.borrow().put_attempts,
        total + 1,
        "exactly one dropped attempt and no wasted bytes"
    );

    // The server's copy still rebuilds the file byte for byte.
    let b_root = tempfile::tempdir().unwrap();
    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(
        std::fs::read(b_root.path().join("video.part")).unwrap(),
        bytes,
        "the resumed push stored the same content as an uninterrupted one would"
    );
}

#[test]
fn an_interrupted_pull_resumes_from_the_chunks_already_stored() {
    // A server that already holds a multi-chunk file.
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    let bytes = filler(200_000);
    write_client(a_root.path(), "movie.part", &bytes);
    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    a.sync_once(&mut a_client, "2026-10-16").unwrap();
    let total = shared.0.borrow().chunks.len();
    assert!(
        total >= 3,
        "the fixture must span several chunks; got {total}"
    );

    // B pulls through a store, and the second chunk's download drops.
    let tee = TeeStore::default();
    let b_root = tempfile::tempdir().unwrap();
    shared.0.borrow_mut().fail_get_number = Some(2);
    let mut b = engine(b_root.path()).with_store(tee.clone());
    let mut b_client = client(&shared);
    assert!(b.sync_once(&mut b_client, "2026-10-16").is_err());

    // The interruption leaves a head start, and not a half-written promise:
    // chunk one is durably cached, and no manifest or plaintext landed — the
    // file does not exist anywhere until it is whole.
    {
        let t = tee.0.lock().unwrap();
        assert_eq!(t.chunks.len(), 1, "the first downloaded chunk was staged");
        assert!(
            t.manifests.is_empty(),
            "the manifest lands last, only when the whole file is local"
        );
    }
    assert!(!b_root.path().join("movie.part").exists());
    assert_eq!(
        std::fs::read_dir(b_root.path().join(".syncbox-tmp"))
            .expect("the interrupted pull left its staging directory")
            .count(),
        1,
        "the half-pull exists only as a staged part-file"
    );

    // The next pull reads through the store first: chunk one never goes back to
    // the wire, and the pass finishes from where the drop stopped it.
    shared.0.borrow_mut().fail_get_number = None;
    let mut b2 = engine(b_root.path()).with_store(tee.clone());
    let mut b2_client = client(&shared);
    let report = b2.sync_once(&mut b2_client, "2026-10-16").unwrap();
    assert_eq!(report.downloaded, 1);
    assert_eq!(
        report.resumed_chunks, 1,
        "chunk one came from the store, not the server"
    );
    assert_eq!(
        shared.0.borrow().get_attempts,
        total + 1,
        "one dropped attempt, and not one chunk ever re-fetched"
    );
    assert_eq!(
        std::fs::read(b_root.path().join("movie.part")).unwrap(),
        bytes,
        "resumed bytes are byte-identical to a clean pull"
    );
}

#[test]
fn pull_staging_is_invisible_to_the_folder_scan() {
    // A pull interrupted mid-file leaves its part-file in the tree's staging
    // directory — and the scan that decides what to push must never see it, or a
    // half-download would climb back to the server as a file of its own.
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    write_client(a_root.path(), "quiet.txt", b"nothing to stage here");
    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    a.sync_once(&mut a_client, "2026-10-16").unwrap();

    let b_root = tempfile::tempdir().unwrap();
    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    b.sync_once(&mut b_client, "2026-10-16").unwrap();

    // An abandoned part-file, as an interrupted pull would leave behind, plus one
    // freshly staged: neither may be scanned, pushed, or reported.
    let stage = b_root.path().join(".syncbox-tmp");
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(stage.join("ABCD-EF12.part"), b"half a file").unwrap();

    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert!(
        report.is_quiet(),
        "staging leaked into the pass: {report:?}"
    );

    // A deeper directory of the same name is the user's, not staging, and still
    // syncs — the skip is surgical, not a name ban.
    let nested = b_root.path().join("work").join(".syncbox-tmp");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("notes.txt"), b"real user content").unwrap();
    let report = b.sync_once(&mut b_client, "2026-10-16").unwrap();
    assert_eq!(
        report.uploaded, 1,
        "a nested .syncbox-tmp is just a directory"
    );

    let c_root = tempfile::tempdir().unwrap();
    // The known-directory rule still applies on the way down: C creates the
    // directory so it can name the files beneath it, exactly as with any folder.
    std::fs::create_dir_all(c_root.path().join("work/.syncbox-tmp")).unwrap();
    let c_root = c_root.path();
    let mut c = engine(c_root);
    let mut c_client = client(&shared);
    c.sync_once(&mut c_client, "2026-10-16").unwrap();
    assert_eq!(
        std::fs::read(c_root.join("work/.syncbox-tmp/notes.txt")).unwrap(),
        b"real user content",
        "it arrives intact"
    );
}

#[test]
fn a_clean_pass_reclaims_its_empty_staging_directory() {
    // `.syncbox-tmp` is scaffolding: folder-mode pulls assemble files inside
    // it, and the folder scan is trained to skip it. A pass that finished
    // with nothing half-fetched earned the right to hide it again — an empty
    // dot-directory squatting in the user's tree is pure debris.
    let shared = Shared(Rc::new(RefCell::new(FakeServer::default())));
    let a_root = tempfile::tempdir().unwrap();
    write_client(a_root.path(), "doc.txt", b"complete on the first pass");
    let mut a = engine(a_root.path());
    let mut a_client = client(&shared);
    a.sync_once(&mut a_client, "2026-10-16").unwrap();

    let b_root = tempfile::tempdir().unwrap();
    let mut b = engine(b_root.path());
    let mut b_client = client(&shared);
    b.sync_once(&mut b_client, "2026-10-16").unwrap();

    assert_eq!(
        std::fs::read(b_root.path().join("doc.txt")).unwrap(),
        b"complete on the first pass",
        "the file itself arrived whole, as ever"
    );
    assert!(
        !b_root.path().join(".syncbox-tmp").exists(),
        "a completed pass reclaimed its empty staging directory"
    );

    // The user's own directory of the same name, deeper in the tree, is not
    // scaffolding and must survive a hundred clean passes.
    std::fs::create_dir_all(b_root.path().join("notes/.syncbox-tmp")).unwrap();
    std::fs::write(b_root.path().join("notes/.syncbox-tmp/keep.txt"), b"mine").unwrap();
    let mut b2 = engine(b_root.path());
    let mut b2_client = client(&shared);
    b2.sync_once(&mut b2_client, "2026-10-17").unwrap();
    assert_eq!(
        std::fs::read(b_root.path().join("notes/.syncbox-tmp/keep.txt")).unwrap(),
        b"mine",
        "the tidy is root-scoped; the user's directory is untouched"
    );
}
