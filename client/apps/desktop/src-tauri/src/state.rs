//! The window's shared state: the background [`SyncWorker`]s and what it takes to
//! (re)start them. Everything expensive — the unlocked agents, their indexes, the
//! HTTP clients — lives on the worker threads; this holds only the handles plus
//! the credentials a pass needs.
//!
//! One vault can live in as many folders as the user wants. Each folder is its
//! own copy with its own index, converging with the others through the server
//! exactly as two machines would, so the window runs one worker per folder over
//! keys unlocked once. Locking the vault drops every worker (its `Drop` stops the
//! loop), which drops the agents and the master keys with them — nothing sensitive
//! survives a lock.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use syncbox_agent::{index_path_for, Agent, Folder, SyncWorker};
use syncbox_transport::dto::SpaceMode;
use syncbox_transport::{Client, UreqHttp};

use crate::spaces::{self, Space};

/// How often the loops run a pass when nothing is requested. A manual `Sync now`
/// and file-change pushes run ahead of this.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(60);

/// The managed state, wrapped once so commands can share it cheaply.
pub type Shared = Arc<Mutex<AppState>>;

/// What the frontend submits to start a session: the server to dial and the
/// *server* password it buys a token with, the space to open, the directory
/// holding its local state (the `vault.json` header for a vault), and the
/// folders to keep in sync.
///
/// The vault password is deliberately absent: it is asked for in the unlock
/// window and reaches only [`AppState::unlock_vault`], never this description
/// of the session.
#[derive(Clone, Debug)]
pub struct Session {
    /// Server origin, e.g. `https://sync.example`.
    pub server: String,
    /// The server password — the same secret the web login asks for. It
    /// authenticates every pass; it is not the password that unlocks a vault
    /// header.
    pub server_password: String,
    /// The server's id for the vault.
    pub vault_id: String,
    /// Directory holding `vault.json` (and, per folder, the local indexes).
    pub vault_dir: PathBuf,
    /// The plaintext folders kept in sync.
    pub folders: Vec<PathBuf>,
    /// What the space stores: a vault derives keys, a sync space has none and
    /// the password authenticates to the server only.
    pub mode: SpaceMode,
}

/// A session chosen but not yet unlocked: the vault password is still to come
/// from the unlock window. Held in memory only, and dropped the moment it is
/// used, cancelled or locked — it carries the server password, so it must not
/// outlive the attempt.
#[derive(Clone, Debug)]
pub struct Pending {
    /// The session the password will unlock.
    pub session: Session,
    /// The space's display name, for the unlock window's title.
    pub name: String,
}

/// The space a running session serves, in the words the settings window may
/// show: what it is called, which server it lives on, what the server keeps
/// there, and where this machine keeps its own state for it.
///
/// No password is among these — a window that reads this back cannot be handed
/// a secret by it.
#[derive(Clone, Debug)]
pub struct Running {
    /// The space's display name, as `list_vaults` called it (or the id, for a
    /// hand-typed space).
    pub name: String,
    /// The server's id for the space — its durable handle, and what marks the
    /// remembered row as the running one.
    pub vault_id: String,
    /// The server origin the loops dial.
    pub server: String,
    /// What the space stores: a vault, or a sync space in the clear.
    pub mode: SpaceMode,
    /// The space's local state directory — the `vault.json` header plus each
    /// folder's index. `usage` reads it through here, so the frontend never
    /// repeats a path it never chose.
    pub vault_dir: PathBuf,
}

/// Everything the shell tracks about the current session.
#[derive(Default)]
pub struct AppState {
    workers: Vec<SyncWorker>,
    /// The space the workers are serving, if a session is running.
    running: Option<Running>,
    /// The session whose vault password window is open, if any.
    pending: Option<Pending>,
    /// The spaces this machine has opened before, newest first — metadata only,
    /// so a row can come back locked without a credential being kept. Loaded at
    /// start-up and updated on every successful unlock.
    known: Vec<Space>,
}

impl AppState {
    /// Unlocks the space once and starts one background loop per folder,
    /// replacing any running session. `vault_password` unlocks the vault header
    /// — a sync space has no header, so it is empty and unused there (the server
    /// token comes from [`Session::server_password`]). `name` is the space's
    /// display name, kept only to tell the settings window what to call it.
    ///
    /// Blocking: Argon2id runs on unlock and each loop's first pass authenticates
    /// immediately. Callers run this on a blocking thread (see `commands`).
    ///
    /// # Errors
    ///
    /// A human-readable reason if the space cannot be unlocked (wrong vault
    /// password, unreadable header, index cannot be opened) or if no folder was
    /// given.
    pub fn unlock_vault(
        &mut self,
        session: Session,
        name: String,
        vault_password: String,
    ) -> Result<(), String> {
        // End the previous loops before replacing the session so two never run.
        self.stop_workers();

        validate(&session, &vault_password)?;

        let folders: Vec<Folder> = session
            .folders
            .iter()
            .map(|path| Folder {
                path: path.clone(),
                index: index_path_for(&session.vault_dir, path),
            })
            .collect();

        // One call for both modes: a vault derives its keys here, a sync space
        // holds none and the password authenticates to the server only.
        let agents = Agent::open_folders(
            &session.vault_dir,
            &session.vault_id,
            session.mode,
            &vault_password,
            &folders,
        )
        .map_err(|e| e.to_string())?;

        self.running = Some(Running {
            name,
            vault_id: session.vault_id.clone(),
            server: session.server.clone(),
            mode: session.mode,
            vault_dir: session.vault_dir.clone(),
        });
        // The attempt is over, whatever it was waiting on.
        self.pending = None;

        let mut workers = Vec::with_capacity(agents.len());
        for agent in agents {
            // Build a fresh, re-authenticated client for every pass: that is where
            // an expired token gets refreshed, and why a factory (not a single
            // client) is handed to each loop. A failed token exchange is left for
            // the pass to surface as an error state; the next pass dials out again.
            let server = session.server.clone();
            let server_password = session.server_password.clone();
            let client_factory = move || {
                let mut client = Client::new(&server, UreqHttp::new(&server));
                let _ = client.token(&server_password);
                client
            };
            workers.push(agent.spawn_loop(SYNC_INTERVAL, client_factory, crate::today));
        }
        self.workers = workers;
        Ok(())
    }

    /// Holds the session the unlock window is about to unlock, replacing any
    /// older one — one window, one pending session behind it.
    pub fn set_pending(&mut self, session: Session, name: String) {
        self.pending = Some(Pending { session, name });
    }

    /// What the open unlock window and the main window's waiting card may know:
    /// the space's name and mode. Never a secret.
    #[must_use]
    pub fn pending_info(&self) -> Option<(&str, SpaceMode)> {
        self.pending
            .as_ref()
            .map(|pending| (pending.name.as_str(), pending.session.mode))
    }

    /// Takes the pending session — the unlock is starting and owns it now.
    pub fn take_pending(&mut self) -> Option<(Session, String)> {
        self.pending
            .take()
            .map(|pending| (pending.session, pending.name))
    }

    /// Forgets a pending session (a cancel, or a lock).
    pub fn clear_pending(&mut self) {
        self.pending = None;
    }

    /// Stops the loops and forgets the credentials (drops the keys with them).
    pub fn lock_vault(&mut self) {
        self.stop_workers();
        // A pending unlock dies with the session: it carries the server
        // password, and a lock is the statement that no session is running —
        // so the settings window has nothing left to describe either.
        self.pending = None;
        self.running = None;
    }

    /// The live status handles, one per synced folder.
    #[must_use]
    pub fn workers(&self) -> &[SyncWorker] {
        &self.workers
    }

    /// The chosen space's local state directory, once a session has named it —
    /// `None` before the first unlock, so `usage` knows there are no indexes
    /// to read yet.
    #[must_use]
    pub fn vault_dir(&self) -> Option<&Path> {
        self.running
            .as_ref()
            .map(|running| running.vault_dir.as_path())
    }

    /// The space the workers serve, in showable words — nothing a window may
    /// not see. `None` while locked.
    #[must_use]
    pub fn running(&self) -> Option<&Running> {
        self.running.as_ref()
    }

    /// The spaces this machine remembers, newest first. Metadata only: a window
    /// that reads this gets names, modes and paths, never a credential.
    #[must_use]
    pub fn known(&self) -> &[Space] {
        &self.known
    }

    /// Replaces the remembered spaces — start-up's read from disk.
    pub fn set_known(&mut self, known: Vec<Space>) {
        self.known = known;
    }

    /// Remembers a successfully unlocked space, newest first. Returns the entry
    /// it replaced, if the same server and id were already known.
    pub fn remember(&mut self, space: Space) -> Option<Space> {
        spaces::remember(&mut self.known, space)
    }

    /// Holds every folder's passes, or lets them run again.
    ///
    /// A pause is not a lock: the keys stay in hand, and nothing in the folders
    /// is touched — edits made while held wait on disk for the resume pass.
    pub fn set_paused(&mut self, paused: bool) {
        for worker in &self.workers {
            worker.set_paused(paused);
        }
    }

    /// Whether the loops are held. Empty (locked) reads as not paused: a locked
    /// vault is not a paused one.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.workers.iter().any(SyncWorker::is_paused)
    }

    fn stop_workers(&mut self) {
        for worker in self.workers.drain(..) {
            worker.stop();
        }
    }
}

/// What every unlock needs before it touches the disk: at least one folder, and
/// a password when the space is a vault. A sync space has no header to unlock,
/// so whatever the window sent for it goes unused.
///
/// # Errors
///
/// The message the form shows verbatim.
fn validate(session: &Session, vault_password: &str) -> Result<(), String> {
    if session.folders.is_empty() {
        return Err("add at least one folder to keep in sync".into());
    }
    // A vault with no password is a typo, not an attempt: say so plainly rather
    // than let the header's own "wrong password" stand in for it.
    if session.mode.is_encrypted() && vault_password.trim().is_empty() {
        return Err("the vault password is required".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(mode: SpaceMode) -> Session {
        Session {
            server: "https://sync.example".into(),
            server_password: "server-secret".into(),
            vault_id: "v1".into(),
            vault_dir: PathBuf::from("/home/me/.syncbox/v1"),
            folders: vec![PathBuf::from("/home/me/Syncbox")],
            mode,
        }
    }

    #[test]
    fn a_pending_session_is_taken_once_and_can_be_put_back() {
        let mut state = AppState::default();
        assert!(state.pending_info().is_none(), "nothing pending to start");
        assert!(state.take_pending().is_none());

        state.set_pending(session(SpaceMode::Vault), "Files synced".into());
        let info = state.pending_info().expect("the pending session");
        assert_eq!(info.0, "Files synced");
        assert!(info.1.is_encrypted());

        let (taken, name) = state.take_pending().expect("the pending session");
        assert_eq!(name, "Files synced");
        assert!(state.pending_info().is_none(), "taking empties the slot");
        assert!(
            state.take_pending().is_none(),
            "and does not hand it out twice"
        );

        // A failed unlock puts it back, so the window can retry.
        state.set_pending(taken, name);
        assert!(state.pending_info().is_some());
        state.clear_pending();
        assert!(state.pending_info().is_none());
    }

    #[test]
    fn locking_drops_a_pending_unlock() {
        let mut state = AppState::default();
        assert!(state.running().is_none(), "no session, no space to show");
        state.set_pending(session(SpaceMode::Vault), "Files synced".into());
        state.lock_vault();
        assert!(
            state.pending_info().is_none(),
            "a lock leaves no session, and no server password with it"
        );
        assert!(state.running().is_none(), "and nothing to describe");
        assert!(
            state.vault_dir().is_none(),
            "so there are no indexes to read"
        );
    }

    #[test]
    fn a_remembered_space_is_kept_newest_first() {
        use crate::spaces::Space;

        let mut state = AppState::default();
        assert!(state.known().is_empty(), "nothing remembered yet");
        let space = Space {
            server: "https://sync.example".into(),
            vault_id: "v1".into(),
            name: "Files synced".into(),
            mode: SpaceMode::Vault,
            vault_dir: PathBuf::from("/home/me/.syncbox/v1"),
            folders: vec![PathBuf::from("/home/me/Syncbox")],
        };
        state.remember(space.clone());
        assert_eq!(state.known().len(), 1);
        assert!(
            state.running().is_none(),
            "remembering a space is not unlocking it"
        );

        let mut other = space;
        other.vault_id = "v2".into();
        state.remember(other);
        assert_eq!(
            state
                .known()
                .iter()
                .map(|s| s.vault_id.as_str())
                .collect::<Vec<_>>(),
            vec!["v2", "v1"]
        );
    }

    #[test]
    fn an_unlock_needs_folders_and_a_vault_needs_its_password() {
        let mut empty = session(SpaceMode::Vault);
        empty.folders.clear();
        assert_eq!(
            validate(&empty, "pw").unwrap_err(),
            "add at least one folder to keep in sync"
        );
        // A whitespace password is no password.
        assert_eq!(
            validate(&session(SpaceMode::Vault), "  ").unwrap_err(),
            "the vault password is required"
        );
        // A sync space has no header, so an empty password is not its problem.
        assert!(validate(&session(SpaceMode::Vault), "pw").is_ok());
        assert!(validate(&session(SpaceMode::Sync), "").is_ok());
    }
}
