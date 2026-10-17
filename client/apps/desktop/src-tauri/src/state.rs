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

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use syncbox_agent::{index_path_for, Agent, Folder, SyncWorker};
use syncbox_transport::{Client, UreqHttp};

/// How often the loops run a pass when nothing is requested. A manual `Sync now`
/// and file-change pushes run ahead of this.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(60);

/// The managed state, wrapped once so commands can share it cheaply.
pub type Shared = Arc<Mutex<AppState>>;

/// What the frontend submits to start a session, minus the transient password:
/// the server to dial, the vault to unlock, the header to unlock it from, and the
/// folders to keep in sync.
#[derive(Clone, Debug)]
pub struct Session {
    /// Server origin, e.g. `https://sync.example`.
    pub server: String,
    /// The server's id for the vault.
    pub vault_id: String,
    /// Directory holding `vault.json`.
    pub vault_dir: PathBuf,
    /// The plaintext folders kept in sync.
    pub folders: Vec<PathBuf>,
}

/// Everything the shell tracks about the current session.
#[derive(Default)]
pub struct AppState {
    workers: Vec<SyncWorker>,
    server: String,
    password: String,
}

impl AppState {
    /// Unlocks the vault once and starts one background loop per folder,
    /// replacing any running session.
    ///
    /// Blocking: Argon2id runs on unlock and each loop's first pass authenticates
    /// immediately. Callers run this on a blocking thread (see `commands`).
    ///
    /// # Errors
    ///
    /// A human-readable reason if the vault cannot be unlocked (wrong password,
    /// unreadable header, index cannot be opened) or if no folder was given.
    pub fn unlock_vault(&mut self, session: Session, password: String) -> Result<(), String> {
        // End the previous loops before replacing the session so two never run.
        self.stop_workers();

        if session.folders.is_empty() {
            return Err("add at least one folder to keep in sync".into());
        }

        let folders: Vec<Folder> = session
            .folders
            .iter()
            .map(|path| Folder {
                path: path.clone(),
                index: index_path_for(&session.vault_dir, path),
            })
            .collect();

        let agents =
            Agent::unlock_folders(&session.vault_dir, &session.vault_id, &password, &folders)
                .map_err(|e| e.to_string())?;

        self.server = session.server.clone();
        self.password = password.clone();

        let mut workers = Vec::with_capacity(agents.len());
        for agent in agents {
            // Build a fresh, re-authenticated client for every pass: that is where
            // an expired token gets refreshed, and why a factory (not a single
            // client) is handed to each loop. A failed token exchange is left for
            // the pass to surface as an error state; the next pass dials out again.
            let server = session.server.clone();
            let password = password.clone();
            let client_factory = move || {
                let mut client = Client::new(&server, UreqHttp::new(&server));
                let _ = client.token(&password);
                client
            };
            workers.push(agent.spawn_loop(SYNC_INTERVAL, client_factory, crate::today));
        }
        self.workers = workers;
        Ok(())
    }

    /// Stops the loops and forgets the credentials (drops the keys with them).
    pub fn lock_vault(&mut self) {
        self.stop_workers();
        self.server.clear();
        self.password.clear();
    }

    /// The live status handles, one per synced folder.
    #[must_use]
    pub fn workers(&self) -> &[SyncWorker] {
        &self.workers
    }

    fn stop_workers(&mut self) {
        for worker in self.workers.drain(..) {
            worker.stop();
        }
    }
}
