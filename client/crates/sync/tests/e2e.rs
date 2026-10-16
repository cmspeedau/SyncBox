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

use serde::{Deserialize, Serialize};
use serde_json::json;
use syncbox_crypto::{MasterKey, MasterKeys};
use syncbox_index::MemoryIndex;
use syncbox_sync::{Engine, Vault};
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
                let id = &other["chunks/".len()..];
                self.chunks
                    .entry(id.to_owned())
                    .or_insert_with(|| request.body.clone());
                Ok(Self::json(201, &json!({ "stored": request.body.len() })))
            }
            ("GET", other) if other.starts_with("chunks/") => {
                let id = &other["chunks/".len()..];
                match self.chunks.get(id) {
                    Some(bytes) => Ok(Response {
                        status: 200,
                        body: bytes.clone(),
                    }),
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
