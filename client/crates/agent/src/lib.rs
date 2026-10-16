//! The desktop app's sync controller, with no GUI in it.
//!
//! The window is a thin shell; everything it shows and does lives here, behind
//! plain Rust types that [`syncbox_sync`], [`syncbox_index`], and
//! [`syncbox_transport`] already provide. The point of the split is the same one
//! that keeps the five core crates Tauri-free: the [`Agent`] is unit-testable
//! against the in-process fake server, so the tray's "synced / syncing / failed"
//! states are asserted on a headless box, not eyeballed in a window.
//!
//! [`Agent`] owns an *unlocked session*: an [`Engine`] over an [`Index`] and a
//! [`Vault`]. It does **not** own a server connection — the transport is supplied
//! per [`Agent::sync_once`], exactly as [`Engine::sync_once`] takes one. That is
//! what lets a test hand the agent a scripted fake, and lets the desktop keep one
//! connection pool (or a SOCKS proxy) underneath the same engine.
//!
//! Authentication is the caller's job too: build a [`Client`], call
//! [`Client::token`], then pass it to [`Agent::sync_once`]. [`Agent::unlock`]
//! deliberately stops short of contacting the server, so a window can unlock a
//! vault offline and sync once the network returns.
//!
//! Locking the vault is dropping the [`Agent`]: the master keys live inside the
//! [`Vault`] it owns, so nothing survives the drop.
//!
//! For a running desktop, [`Agent::spawn_loop`] moves the session onto a worker
//! thread that syncs on an interval (and whenever [`SyncWorker::request_sync`] is
//! pressed) and publishes an [`AgentStatus`] the tray reads without ever blocking
//! on the network. The worker [`SyncWorker`] is the handle the window holds;
//! dropping it stops the loop.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use syncbox_index::{Index, SqliteIndex};
use syncbox_sync::{Engine, SyncReport, Vault};
use syncbox_transport::{Client, Http, TransportError};

mod worker;

// Re-exported so a window can read the Backups panel's rows without naming the
// transport crate directly.
pub use syncbox_transport::dto::{BackupManifest, Snapshot};
pub use worker::SyncWorker;

/// How far the session is from showing a settled vault.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SyncState {
    /// No keys in hand: nothing can sync until the vault is unlocked.
    #[default]
    Locked,
    /// Unlocked and settled, or sitting between passes.
    Idle,
    /// A pass is running right now. Only a background loop can be observed in
    /// this state; a single [`Agent::sync_once`] leaves it before returning.
    Syncing,
    /// The last pass failed. See [`AgentStatus::last_error`].
    Error,
}

/// A snapshot of what the session is doing, for the tray and the status panel.
///
/// Cheap to clone and safe to hand to a UI thread on every tick.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentStatus {
    /// Where the session is in its lifecycle.
    pub state: SyncState,
    /// Unix seconds of the most recent *successful* pass.
    pub last_sync_unix: Option<i64>,
    /// A human-readable reason for the last failure, if any.
    pub last_error: Option<String>,
    /// What the most recent pass did, for the "last synced: 2 up, 1 down" line.
    pub last_report: Option<SyncReport>,
    /// How many passes have finished, success or failure. A window watches this
    /// tick over to know the loop is alive without reading wall-clock time.
    pub passes: u32,
}

impl AgentStatus {
    /// True when no keys are in hand.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.state == SyncState::Locked
    }

    /// True when unlocked and the last pass found nothing to do — the state the
    /// tray icon shows as a quiet "up to date".
    #[must_use]
    pub fn is_settled(&self) -> bool {
        self.state == SyncState::Idle
            && match self.last_report {
                None => true,
                Some(report) => report.is_quiet(),
            }
    }
}

/// One entry in the activity feed the Backups/sync panels scroll through.
///
/// Kept coarse on purpose: [`SyncReport`] carries counts, not per-file paths, so
/// an event says "the last pass uploaded 3 and hit a conflict" rather than
/// naming files. A per-file feed is a later step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncEvent {
    /// A pass finished and changed the local or remote tree.
    Done {
        /// What it did.
        report: SyncReport,
        /// Unix seconds it finished.
        at_unix: i64,
    },
    /// A pass failed before finishing.
    Failed {
        /// Human-readable reason.
        error: String,
        /// Unix seconds it failed.
        at_unix: i64,
    },
}

/// Where the pieces a session needs live on disk and on the server.
///
/// Mirrors the `syncbox sync once` flags so the CLI and the app configure the
/// same thing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Server origin, e.g. `https://sync.example`.
    pub server: String,
    /// The server's id for the vault being synced.
    pub vault_id: String,
    /// Directory holding `vault.json` (the wrapped keys).
    pub vault_dir: PathBuf,
    /// The plaintext folder kept in sync with the vault.
    pub folder: PathBuf,
    /// Where the SQLite index lives; defaults to `<vault_dir>/index.db`.
    pub index: Option<PathBuf>,
}

impl Config {
    /// The index path, falling back to one beside `vault.json` as the CLI does.
    #[must_use]
    pub fn index_path(&self) -> PathBuf {
        self.index
            .clone()
            .unwrap_or_else(|| self.vault_dir.join("index.db"))
    }
}

/// Anything that can go wrong assembling or running a session.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// Unlocking the vault (wrong password, unreadable header).
    #[error(transparent)]
    Vault(#[from] syncbox_vault::VaultError),
    /// Opening the local index database.
    #[error(transparent)]
    Index(#[from] rusqlite::Error),
    /// A sync pass failed.
    #[error(transparent)]
    Sync(#[from] syncbox_sync::SyncError),
    /// A transport call failed directly.
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// Result alias used across this crate.
pub type Result<T> = std::result::Result<T, AgentError>;

/// How many [`SyncEvent`]s the agent remembers for the activity panel.
const HISTORY_LIMIT: usize = 50;

/// An unlocked sync session, and the state machine the window renders.
///
/// Generic over the [`Index`] so the lifecycle is tested against
/// [`syncbox_index::MemoryIndex`] and runs on [`SqliteIndex`] in the app, with no
/// branching — the same reason [`Engine`] is generic.
#[derive(Debug)]
pub struct Agent<I: Index> {
    engine: Engine<I>,
    status: AgentStatus,
    history: Vec<SyncEvent>,
}

impl<I: Index> Agent<I> {
    /// Wraps an already-assembled engine. The session starts [`SyncState::Idle`]
    /// (unlocked, nothing running).
    #[must_use]
    pub fn from_engine(engine: Engine<I>) -> Self {
        Self {
            engine,
            status: AgentStatus {
                state: SyncState::Idle,
                ..Default::default()
            },
            history: Vec::new(),
        }
    }

    /// The vault's server-side id.
    #[must_use]
    pub fn vault_id(&self) -> &str {
        self.engine.vault.vault_id()
    }

    /// The plaintext folder this session keeps in sync.
    #[must_use]
    pub fn folder(&self) -> &Path {
        self.engine.vault.plaintext_root()
    }

    /// The current lifecycle state.
    #[must_use]
    pub fn state(&self) -> SyncState {
        self.status.state
    }

    /// A cloneable snapshot of the session's state.
    #[must_use]
    pub fn status(&self) -> AgentStatus {
        self.status.clone()
    }

    /// Recent sync outcomes, oldest first, for the activity panel.
    #[must_use]
    pub fn history(&self) -> &[SyncEvent] {
        &self.history
    }

    /// Lists the server's snapshots, newest first, for the Backups panel.
    ///
    /// These ride the admin route, which a server run without a backup target
    /// answers `501 not_configured`. That surfaces here as an
    /// [`AgentError::Transport`] [`TransportError::Refused`] whose code is
    /// `not_configured`, which the panel renders as "this server has no backups
    /// configured" rather than a red failure. Backups are orthogonal to sync, so
    /// these do not touch [`Agent::status`].
    ///
    /// # Errors
    ///
    /// Propagates transport and decoding errors.
    pub fn backups<H: Http>(&mut self, client: &mut Client<H>) -> Result<Vec<Snapshot>> {
        Ok(client.backups()?)
    }

    /// Asks the server to take a snapshot now ("Back up now") and returns it.
    ///
    /// # Errors
    ///
    /// As [`Agent::backups`], including `not_configured`.
    pub fn back_up_now<H: Http>(&mut self, client: &mut Client<H>) -> Result<Snapshot> {
        Ok(client.create_backup()?)
    }

    /// Runs one pull-then-push pass and folds the outcome into [`Self::status`]
    /// and [`Self::history`].
    ///
    /// This mirrors [`Engine::sync_once`] but records the result, so the tray can
    /// show the most recent pass rather than re-running one to ask. `now` is the
    /// `YYYY-MM-DD` date that labels conflicted copies; the caller supplies it so
    /// the pass stays deterministic under test (the app passes today's date).
    ///
    /// The `client` must already be authenticated; a `401` from it surfaces as an
    /// [`SyncState::Error`], which is how the window learns to prompt for the
    /// password again.
    ///
    /// # Errors
    ///
    /// Propagates the underlying sync/transport error. On failure the session is
    /// left [`SyncState::Error`] with [`AgentStatus::last_error`] set; a later
    /// successful pass clears both.
    pub fn sync_once<H: Http>(&mut self, client: &mut Client<H>, now: &str) -> Result<SyncReport> {
        self.status.state = SyncState::Syncing;
        let at = now_unix();
        match self.engine.sync_once(client, now) {
            Ok(report) => {
                self.status.last_report = Some(report);
                self.status.last_error = None;
                self.status.last_sync_unix = Some(at);
                self.status.state = SyncState::Idle;
                self.status.passes += 1;
                self.push_event(SyncEvent::Done {
                    report,
                    at_unix: at,
                });
                Ok(report)
            }
            Err(error) => {
                let reason = error.to_string();
                self.status.last_error = Some(reason.clone());
                self.status.state = SyncState::Error;
                self.status.passes += 1;
                self.push_event(SyncEvent::Failed {
                    error: reason,
                    at_unix: at,
                });
                Err(error.into())
            }
        }
    }

    /// Appends an event, keeping only the last [`HISTORY_LIMIT`].
    fn push_event(&mut self, event: SyncEvent) {
        self.history.push(event);
        if self.history.len() > HISTORY_LIMIT {
            self.history.remove(0);
        }
    }
}

impl Agent<SqliteIndex> {
    /// Unlocks the vault in `config` and opens its durable index, returning a
    /// ready-to-sync session.
    ///
    /// Does not contact the server. Authenticate a [`Client`] separately and pass
    /// it to [`Agent::sync_once`].
    ///
    /// # Errors
    ///
    /// [`AgentError::Vault`] for a wrong password or missing header;
    /// [`AgentError::Index`] if the database cannot be opened.
    pub fn unlock(config: &Config, password: &str) -> Result<Self> {
        let keys = syncbox_vault::unlock(&config.vault_dir, password)?;
        let index = SqliteIndex::open(config.index_path())?;
        let vault = Vault::new(keys, config.vault_id.clone(), config.folder.clone())?;
        Ok(Self::from_engine(Engine::new(index, vault)))
    }
}

/// Unix seconds now, at the edge of the system. Falls back to `0` if the clock
/// is before the epoch, which a `last_sync_unix` of `Some(0)` tolerates.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use syncbox_crypto::{MasterKey, MasterKeys};
    use syncbox_index::MemoryIndex;
    use syncbox_transport::{Method, Request, Response};

    use super::*;

    fn keys() -> MasterKeys {
        MasterKeys {
            primary: MasterKey::from_bytes(&[0x20; 32]).unwrap(),
            hmac: MasterKey::from_bytes(&[0x00; 32]).unwrap(),
        }
    }

    /// An agent over an empty in-memory index and an empty folder: a settled
    /// session with nothing to send.
    fn idle_agent(dir: &Path) -> Agent<MemoryIndex> {
        let vault = Vault::new(keys(), "vault", dir).expect("vault");
        Agent::from_engine(Engine::new(MemoryIndex::default(), vault))
    }

    /// Answers whatever the engine asks for with scripted replies, defaulting to
    /// an empty revision log (a vault already fully caught up).
    struct FakeServer {
        replies: VecDeque<(u16, String)>,
        calls: Vec<(Method, String)>,
    }

    impl FakeServer {
        fn quiet() -> Self {
            Self {
                replies: VecDeque::new(),
                calls: Vec::new(),
            }
        }
        fn failing(first_status: u16) -> Self {
            Self {
                replies: VecDeque::from([(
                    first_status,
                    r#"{"code":"boom","reason":"server exploded"}"#.to_string(),
                )]),
                calls: Vec::new(),
            }
        }
    }

    impl Http for FakeServer {
        fn send(&mut self, request: Request) -> syncbox_transport::Result<Response> {
            self.calls.push((request.method, request.path));
            let (status, body) = self
                .replies
                .pop_front()
                .unwrap_or_else(|| (200, r#"{"revisions":[],"upto":0}"#.to_string()));
            Ok(Response {
                status,
                body: body.into_bytes(),
            })
        }
    }

    fn authed(http: FakeServer) -> Client<FakeServer> {
        let mut client = Client::new("https://srv", http);
        client.token = "t".into(); // skip the token exchange in a test
        client
    }

    #[test]
    fn a_fresh_agent_is_idle_with_no_report() {
        let dir = tempfile::tempdir().unwrap();
        let agent = idle_agent(dir.path());
        assert_eq!(agent.state(), SyncState::Idle);
        let status = agent.status();
        assert!(status.last_report.is_none());
        assert!(status.last_sync_unix.is_none());
        assert!(agent.history().is_empty());
    }

    #[test]
    fn a_quiet_pass_keeps_the_session_idle() {
        let dir = tempfile::tempdir().unwrap();
        let mut agent = idle_agent(dir.path());
        let mut client = authed(FakeServer::quiet());

        let report = agent.sync_once(&mut client, "2026-10-17").expect("pass");
        assert!(report.is_quiet(), "nothing to do on a caught-up vault");
        assert_eq!(agent.state(), SyncState::Idle);
        assert!(agent.status().is_settled());
        assert!(agent.status().last_sync_unix.is_some());
        assert_eq!(agent.history().len(), 1);
        assert!(matches!(
            agent.history()[0],
            SyncEvent::Done {
                report: r,
                ..
            } if r.is_quiet()
        ));
        // The only thing a caught-up pass does on the wire is read the log.
        assert_eq!(client.http.calls.len(), 1, "one revisions call");
        assert_eq!(client.http.calls[0].0, Method::Get);
        assert!(
            client.http.calls[0]
                .1
                .contains("/api/v1/vaults/vault/revisions?since="),
            "hit the revision log: {:?}",
            client.http.calls[0].1
        );
    }

    #[test]
    fn a_failed_pass_moves_to_error_and_records_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let mut agent = idle_agent(dir.path());
        let mut client = authed(FakeServer::failing(500));

        let err = agent
            .sync_once(&mut client, "2026-10-17")
            .expect_err("500 on the log read");
        assert!(agent.state() == SyncState::Error);
        let status = agent.status();
        assert!(status.last_error.is_some(), "reason recorded: {err}");
        assert!(
            status.last_sync_unix.is_none(),
            "a failed pass is not a sync"
        );
        assert!(matches!(agent.history()[0], SyncEvent::Failed { .. }));
    }

    #[test]
    fn a_recovery_after_an_error_clears_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut agent = idle_agent(dir.path());

        let mut broken = authed(FakeServer::failing(500));
        assert!(agent.sync_once(&mut broken, "2026-10-17").is_err());
        assert_eq!(agent.state(), SyncState::Error);

        let mut healthy = authed(FakeServer::quiet());
        agent
            .sync_once(&mut healthy, "2026-10-17")
            .expect("recovered");
        assert_eq!(agent.state(), SyncState::Idle);
        assert!(agent.status().last_error.is_none(), "the error is cleared");
        // Both outcomes are in the feed, oldest first.
        assert_eq!(agent.history().len(), 2);
        assert!(matches!(agent.history()[0], SyncEvent::Failed { .. }));
        assert!(matches!(agent.history()[1], SyncEvent::Done { .. }));
    }

    #[test]
    fn unlocking_builds_a_settled_session_against_a_real_vault() {
        // Exercises the Config -> unlock -> Idle wiring: create a vault header on
        // disk, then unlock it into a session whose index file lands beside it.
        let dir = tempfile::tempdir().unwrap();
        let params = syncbox_crypto::kdf::Params::default();
        syncbox_vault::create(dir.path(), "hunter2", &params).expect("create");

        let config = Config {
            server: "https://srv".into(),
            vault_id: "vault-1".into(),
            vault_dir: dir.path().to_path_buf(),
            folder: dir.path().join("files"),
            index: None,
        };
        assert_eq!(config.index_path(), dir.path().join("index.db"));

        let agent = Agent::unlock(&config, "hunter2").expect("unlock");
        assert_eq!(agent.state(), SyncState::Idle);
        assert_eq!(agent.vault_id(), "vault-1");
        assert_eq!(agent.folder(), dir.path().join("files"));

        // The wrong password is a Vault error, not a panic.
        assert!(Agent::unlock(&config, "wrong").is_err());
    }

    #[test]
    fn index_path_uses_the_override_or_falls_back_beside_the_header() {
        let override_config = Config {
            server: "https://srv".into(),
            vault_id: "v".into(),
            vault_dir: PathBuf::from("/vault"),
            folder: PathBuf::from("/files"),
            index: Some(PathBuf::from("/elsewhere/index.db")),
        };
        assert_eq!(
            override_config.index_path(),
            PathBuf::from("/elsewhere/index.db")
        );

        let defaulting = Config {
            index: None,
            ..override_config
        };
        assert_eq!(defaulting.index_path(), PathBuf::from("/vault/index.db"));
    }

    fn scripted(replies: Vec<(u16, String)>) -> FakeServer {
        FakeServer {
            replies: VecDeque::from(replies),
            calls: Vec::new(),
        }
    }

    #[test]
    fn the_agent_lists_snapshots_through_the_admin_route() {
        let dir = tempfile::tempdir().unwrap();
        let mut agent = idle_agent(dir.path());
        let body = r#"[{"ID":"snap-a","CreatedAt":"2026-10-17T10:00:00Z",
            "Manifest":{"version":1,"chunk_bytes":10,"chunks":[{"id":"A","size":10,"sha256":"aa"}]}}]"#;
        let mut client = authed(scripted(vec![(200, body.to_string())]));

        let snapshots = agent.backups(&mut client).expect("list");
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].id, "snap-a");
        assert_eq!(snapshots[0].manifest.chunk_count(), 1);
        assert_eq!(client.http.calls[0].0, Method::Get);
        assert_eq!(client.http.calls[0].1, "/admin/backups");
    }

    #[test]
    fn the_agent_takes_a_snapshot_with_back_up_now() {
        let dir = tempfile::tempdir().unwrap();
        let mut agent = idle_agent(dir.path());
        let body = r#"{"ID":"snap-b","CreatedAt":"2026-10-17T11:00:00Z","Manifest":{"version":1,"chunks":[]}}"#;
        let mut client = authed(scripted(vec![(201, body.to_string())]));

        let snapshot = agent.back_up_now(&mut client).expect("created");
        assert_eq!(snapshot.id, "snap-b");
        assert_eq!(client.http.calls[0].0, Method::Post);
        assert_eq!(client.http.calls[0].1, "/admin/backups");
    }

    #[test]
    fn backups_without_a_target_surface_as_not_configured() {
        let dir = tempfile::tempdir().unwrap();
        let mut agent = idle_agent(dir.path());
        let mut client = authed(scripted(vec![(
            501,
            r#"{"code":"not_configured","reason":"no backup target is configured"}"#.to_string(),
        )]));

        let err = agent.backups(&mut client).expect_err("501");
        assert!(matches!(
            err,
            AgentError::Transport(TransportError::Refused { ref code, .. })
                if code == "not_configured"
        ));
    }
}
