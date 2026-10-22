//! The background sync loop: an [`Agent`] moved onto a worker thread, and the
//! [`SyncWorker`] handle a window reads.
//!
//! The design keeps the expensive thing — the [`Agent`]'s engine, index, and the
//! [`Client`] it dials out with — owned *exclusively* by the worker thread. The
//! handle shares only a small, cheap [`AgentStatus`] snapshot behind a mutex, so
//! reading the tray's state never waits on a network round-trip: the worker flips
//! the shared status to [`SyncState::Syncing`] before a pass, then publishes the
//! outcome after it, and a reader takes the mutex for microseconds either way.
//!
//! The caller supplies a client factory rather than a single client. That keeps
//! re-authentication (a `401` after the token expires) in the app's hands — its
//! factory rebuilds an authenticated [`Client`] each pass — and lets a test hand
//! in a `Send` fake.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use syncbox_index::Index;
use syncbox_transport::{Client, Http};

use crate::{Agent, AgentStatus, SyncEvent, SyncState};

/// The state the worker and the handle share: a status snapshot plus the two
/// flags the loop waits on. Everything here is plain data, so the mutex is held
/// only long enough to copy a few fields.
struct Shared {
    inner: Mutex<Inner>,
    /// Notified whenever the status is refreshed or a control flag is raised.
    wake: Condvar,
}

#[derive(Default)]
struct Inner {
    status: AgentStatus,
    history: Vec<SyncEvent>,
    /// A one-shot "sync now" request from [`SyncWorker::request_sync`].
    dirty: bool,
    /// Set to end the loop on the next check.
    stop: bool,
    /// The user's pause: while set, no pass runs. A queued request (`dirty`)
    /// is left standing rather than consumed, so resuming runs that pass at
    /// once instead of at the end of an interval.
    paused: bool,
    /// One-file reads waiting for the loop's exclusive agent. Hydration is a
    /// read, so it is served even while passes are paused.
    hydrate: Vec<Hydrate>,
}

/// One placeholder waiting to be filled, and the channel the caller blocks on.
struct Hydrate {
    path: String,
    reply: Sender<std::result::Result<(), String>>,
}

impl Shared {
    fn new(status: AgentStatus, history: Vec<SyncEvent>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                status,
                history,
                dirty: false,
                stop: false,
                paused: false,
                hydrate: Vec::new(),
            }),
            wake: Condvar::new(),
        }
    }

    /// Overwrites the shared snapshot from the agent and wakes any reader. The
    /// pause belongs to the loop, not the agent, so it is re-applied here —
    /// otherwise the next publish would quietly drop it.
    fn publish<I: Index>(&self, agent: &Agent<I>) {
        let mut inner = self.inner.lock().expect("sync state lock poisoned");
        let mut status = agent.status();
        status.paused = inner.paused;
        inner.status = status;
        inner.history = agent.history().to_vec();
        self.wake.notify_all();
    }

    /// Marks a pass as starting (without touching the last report) so the tray
    /// shows "Syncing" while the network call is in flight.
    fn mark_syncing(&self) {
        let mut inner = self.inner.lock().expect("sync state lock poisoned");
        inner.status.state = SyncState::Syncing;
        self.wake.notify_all();
    }

    fn request_stop(&self) {
        let mut inner = self.inner.lock().expect("sync state lock poisoned");
        inner.stop = true;
        self.wake.notify_all();
    }

    /// Takes every waiting hydrate request, so the loop can answer them without
    /// holding the lock across a network call.
    fn take_hydrates(&self) -> Vec<Hydrate> {
        let mut inner = self.inner.lock().expect("sync state lock poisoned");
        std::mem::take(&mut inner.hydrate)
    }

    /// Answers anything still waiting when the loop ends, so a caller never
    /// blocks on a thread that is already gone.
    fn fail_hydrates(&self, reason: &str) {
        for request in self.take_hydrates() {
            let _ = request.reply.send(Err(reason.to_owned()));
        }
    }
}

/// Why the loop woke.
enum Next {
    /// The handle asked the loop to end.
    Stop,
    /// Run a sync pass now.
    Pass,
    /// Answer the queued one-file reads before waiting again.
    Hydrate,
}

/// Waits out the interval, or until a stop, a manual sync request, a hydrate
/// request, or a resume arrives.
fn wait_next_tick(shared: &Shared, interval: Duration) -> Next {
    let mut inner = shared.inner.lock().expect("sync state lock poisoned");
    let mut started = Instant::now();
    loop {
        if inner.stop {
            return Next::Stop;
        }
        // Hydration is a read, not a pass: serve it even while the loops are
        // paused. Checking before `paused` is what lets an opened placeholder
        // fill while syncing is held.
        if !inner.hydrate.is_empty() {
            return Next::Hydrate;
        }
        // Paused: no pass, however the clock stands. Waiting on the same
        // condvar means a resume (or stop) is seen at once, and restarting the
        // interval afterwards gives a resumed loop a full interval before its
        // next unprompted pass. A standing `dirty` request is deliberately not
        // consumed here: it is the pass resume runs immediately.
        if inner.paused {
            let (guard, _waited) = shared
                .wake
                .wait_timeout(inner, interval)
                .expect("sync state lock poisoned");
            inner = guard;
            started = Instant::now();
            continue;
        }
        if inner.dirty {
            inner.dirty = false;
            return Next::Pass; // run the next pass immediately
        }
        let elapsed = started.elapsed();
        if elapsed >= interval {
            return Next::Pass; // the interval elapsed; run the next pass
        }
        let (guard, _waited) = shared
            .wake
            .wait_timeout(inner, interval - elapsed)
            .expect("sync state lock poisoned");
        inner = guard;
    }
}

/// One pass: flip to Syncing, run it, publish the result. A failed pass is
/// recorded as [`SyncState::Error`] by the agent and left for the next tick.
fn run_pass<I, H, N>(agent: &mut Agent<I>, shared: &Shared, client: &mut Client<H>, now: &N)
where
    I: Index,
    H: Http,
    N: Fn() -> String,
{
    shared.mark_syncing();
    let _ = agent.sync_once(client, &now());
    shared.publish(agent);
}

/// The worker thread body: sync immediately, then on every tick until stopped.
fn run<I, H, F, N>(
    mut agent: Agent<I>,
    interval: Duration,
    mut factory: F,
    now_fn: N,
    shared: &Shared,
) where
    I: Index + Send + 'static,
    H: Http + Send + 'static,
    F: FnMut() -> Client<H>,
    N: Fn() -> String,
{
    // The first pass runs at once, as it always has.
    let mut client = factory();
    run_pass(&mut agent, shared, &mut client, &now_fn);
    loop {
        match wait_next_tick(shared, interval) {
            Next::Stop => {
                shared.fail_hydrates("the sync loop stopped");
                break;
            }
            Next::Pass => {
                let mut client = factory();
                run_pass(&mut agent, shared, &mut client, &now_fn);
            }
            Next::Hydrate => {
                let requests = shared.take_hydrates();
                if requests.is_empty() {
                    continue;
                }
                let mut client = factory();
                for request in requests {
                    let outcome = agent
                        .hydrate(&mut client, &request.path)
                        .map_err(|error| error.to_string());
                    let _ = request.reply.send(outcome);
                }
                // Hydration does not move the sync state, but publishing wakes
                // any reader waiting on the snapshot the loop has been holding.
                shared.publish(&agent);
            }
        }
    }
}

/// The window's handle to a background sync loop started by [`Agent::spawn_loop`].
///
/// Reads are cheap and never block on the worker: [`SyncWorker::status`] and
/// [`SyncWorker::history`] copy the shared snapshot. Dropping the handle asks the
/// loop to stop; [`SyncWorker::stop`] also waits for the thread to finish.
#[must_use = "dropping the handle stops the background sync loop"]
pub struct SyncWorker {
    shared: Arc<Shared>,
    vault_id: String,
    folder: PathBuf,
    handle: Mutex<Option<JoinHandle<()>>>,
    /// Guards against a double join if `stop()` runs and then `Drop` fires.
    joined: AtomicBool,
}

impl<I: Index + Send + 'static> Agent<I> {
    /// Moves this session onto a background thread that runs a pass immediately,
    /// then every `interval`, and again on each [`SyncWorker::request_sync`].
    ///
    /// `client_factory` builds an authenticated [`Client`] for each pass (the app
    /// authenticates inside it, so an expired token is refreshed on the next
    /// pass); `now_fn` supplies the `YYYY-MM-DD` date used to label conflicted
    /// copies. The [`SyncWorker`] handle reads status without blocking on the
    /// network; dropping it (or calling [`SyncWorker::stop`]) ends the loop.
    pub fn spawn_loop<H, F, N>(self, interval: Duration, client_factory: F, now_fn: N) -> SyncWorker
    where
        H: Http + Send + 'static,
        F: FnMut() -> Client<H> + Send + 'static,
        N: Fn() -> String + Send + 'static,
    {
        let vault_id = self.vault_id().to_owned();
        let folder = self.folder().to_path_buf();
        let shared = Arc::new(Shared::new(self.status(), self.history().to_vec()));

        let thread_shared = Arc::clone(&shared);
        let handle = thread::Builder::new()
            .name("syncbox-agent".to_owned())
            .spawn(move || run(self, interval, client_factory, now_fn, &thread_shared))
            .expect("failed to spawn the sync worker thread");

        SyncWorker {
            shared,
            vault_id,
            folder,
            handle: Mutex::new(Some(handle)),
            joined: AtomicBool::new(false),
        }
    }
}

impl SyncWorker {
    /// The vault's server-side id (copied at spawn, readable without the worker).
    #[must_use]
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    /// The plaintext folder being synced (copied at spawn).
    #[must_use]
    pub fn folder(&self) -> &Path {
        self.folder.as_path()
    }

    /// The latest status snapshot.
    #[must_use]
    pub fn status(&self) -> AgentStatus {
        self.shared
            .inner
            .lock()
            .expect("sync state lock poisoned")
            .status
            .clone()
    }

    /// The current lifecycle state.
    #[must_use]
    pub fn state(&self) -> SyncState {
        self.status().state
    }

    /// Recent sync outcomes, oldest first.
    #[must_use]
    pub fn history(&self) -> Vec<SyncEvent> {
        self.shared
            .inner
            .lock()
            .expect("sync state lock poisoned")
            .history
            .clone()
    }

    /// Asks for a pass to run now, rather than waiting for the next tick. The
    /// loop picks it up as soon as its current pass finishes — or, if the loop
    /// is paused, at the moment it resumes.
    pub fn request_sync(&self) {
        let mut inner = self.shared.inner.lock().expect("sync state lock poisoned");
        inner.dirty = true;
        self.shared.wake.notify_all();
    }

    /// Fetches one placeholder's bytes from the server, blocking until the
    /// worker answers.
    ///
    /// The agent is owned by the loop thread, so a platform placeholder API
    /// (FileProvider, CFAPI) hands the path here rather than reaching into the
    /// engine. Hydration is a read: it runs even while the loops are paused and
    /// does not start a sync pass. The worker's current pass, if any, finishes
    /// first.
    ///
    /// # Errors
    ///
    /// The agent's reason (unknown path, an unsettled entry, a file with local
    /// content, a revision the server no longer lists) as text, or a timeout if
    /// the loop never answers.
    pub fn hydrate(&self, path: &str) -> Result<(), String> {
        // A large placeholder can take minutes on a slow link; the timeout is
        // only the backstop for a loop that has gone away without draining.
        self.hydrate_with_timeout(path, Duration::from_secs(600))
    }

    /// [`SyncWorker::hydrate`] with a caller-chosen wait, so tests never hang on
    /// a regression in the wake-up path.
    fn hydrate_with_timeout(&self, path: &str, timeout: Duration) -> Result<(), String> {
        let (reply, answer) = mpsc::channel();
        {
            let mut inner = self.shared.inner.lock().expect("sync state lock poisoned");
            if inner.stop {
                return Err("the sync loop is stopping".into());
            }
            inner.hydrate.push(Hydrate {
                path: path.to_owned(),
                reply,
            });
            self.shared.wake.notify_all();
        }
        answer
            .recv_timeout(timeout)
            .map_err(|_| "the sync loop did not answer the hydrate request".to_owned())?
    }

    /// Holds the loop's passes (or lets them run again).
    ///
    /// Pausing touches nothing on disk and drops no keys. A pass is a scan, so
    /// there is no queue to drain: edits made while the loop is held simply sit
    /// in the folder until the resume pass reads them. Resuming therefore runs
    /// a pass at once — waiting an interval would make "resume" feel like
    /// nothing happened.
    pub fn set_paused(&self, paused: bool) {
        let mut inner = self.shared.inner.lock().expect("sync state lock poisoned");
        inner.paused = paused;
        inner.status.paused = paused;
        if !paused {
            inner.dirty = true;
        }
        self.shared.wake.notify_all();
    }

    /// Whether the loop is holding its passes.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.shared
            .inner
            .lock()
            .expect("sync state lock poisoned")
            .paused
    }

    /// Blocks until the status satisfies `pred`, or `timeout` elapses.
    ///
    /// This is how a window (or a test) reacts to a state change without
    /// polling: the worker notifies the same condvar it updates the status on.
    /// `pred` sees only the passed-in snapshot — it must not call back into the
    /// handle (which would take the same mutex). Returns the satisfying status,
    /// or `None` on timeout.
    pub fn wait_until<F>(&self, pred: F, timeout: Duration) -> Option<AgentStatus>
    where
        F: Fn(&AgentStatus) -> bool,
    {
        let deadline = Instant::now() + timeout;
        let mut inner = self.shared.inner.lock().expect("sync state lock poisoned");
        loop {
            if pred(&inner.status) {
                return Some(inner.status.clone());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (guard, _waited) = self
                .shared
                .wake
                .wait_timeout(inner, remaining)
                .expect("sync state lock poisoned");
            inner = guard;
        }
    }

    /// Signals the loop to stop and waits for the worker thread to finish.
    pub fn stop(mut self) {
        self.shared.request_stop();
        self.join();
    }

    /// Joins the worker thread once.
    fn join(&mut self) {
        if self.joined.swap(true, Ordering::AcqRel) {
            return; // already joined
        }
        if let Some(handle) = self.handle.get_mut().expect("handle lock poisoned").take() {
            let _ = handle.join();
        }
    }
}

impl Drop for SyncWorker {
    fn drop(&mut self) {
        // Best effort: a detached loop exits after its in-flight pass, because
        // dropping a handle only asks for a stop — call `stop` to wait.
        self.shared.request_stop();
    }
}

#[cfg(test)]
mod tests {
    use syncbox_crypto::{MasterKey, MasterKeys};
    use syncbox_index::MemoryIndex;
    use syncbox_sync::{Engine, Vault};
    use syncbox_transport::{Request, Response};

    use super::*;

    fn keys() -> MasterKeys {
        MasterKeys {
            primary: MasterKey::from_bytes(&[0x20; 32]).unwrap(),
            hmac: MasterKey::from_bytes(&[0x00; 32]).unwrap(),
        }
    }

    fn idle_agent(dir: &Path) -> Agent<MemoryIndex> {
        let vault = Vault::new(keys(), "vault", dir).expect("vault");
        Agent::from_engine(Engine::new(MemoryIndex::default(), vault))
    }

    /// A `Send` fake that answers an empty revision log: every pass is quiet.
    #[derive(Clone, Copy)]
    struct Quiet;

    impl Http for Quiet {
        fn send(&mut self, _request: Request) -> syncbox_transport::Result<Response> {
            Ok(Response {
                status: 200,
                body: br#"{"revisions":[],"upto":0}"#.to_vec(),
            })
        }
    }

    /// A `Send` fake that always fails the log read, so passes land in Error.
    #[derive(Clone, Copy)]
    struct Broken;

    impl Http for Broken {
        fn send(&mut self, _request: Request) -> syncbox_transport::Result<Response> {
            Ok(Response {
                status: 500,
                body: br#"{"code":"boom","reason":"server exploded"}"#.to_vec(),
            })
        }
    }

    fn quiet_factory() -> impl FnMut() -> Client<Quiet> + Send + 'static {
        || {
            let mut client = Client::new("https://srv", Quiet);
            client.token = "t".into();
            client
        }
    }

    fn broken_factory() -> impl FnMut() -> Client<Broken> + Send + 'static {
        || {
            let mut client = Client::new("https://srv", Broken);
            client.token = "t".into();
            client
        }
    }

    fn today() -> impl Fn() -> String + Send + 'static {
        || "2026-10-17".to_string()
    }

    #[test]
    fn the_loop_runs_an_initial_pass_and_settles() {
        let dir = tempfile::tempdir().unwrap();
        let agent = idle_agent(dir.path());
        // A long interval, so exactly the immediate pass runs.
        let worker = agent.spawn_loop(Duration::from_secs(30), quiet_factory(), today());

        let status = worker
            .wait_until(|s| s.last_sync_unix.is_some(), Duration::from_secs(2))
            .expect("the first pass finished");
        assert_eq!(status.state, SyncState::Idle);
        assert!(status.is_settled());
        assert_eq!(status.passes, 1);
        assert_eq!(worker.history().len(), 1);
        assert_eq!(worker.vault_id(), "vault");
        assert_eq!(worker.folder(), dir.path());

        worker.stop();
    }

    #[test]
    fn request_sync_runs_another_pass_ahead_of_the_interval() {
        let dir = tempfile::tempdir().unwrap();
        let agent = idle_agent(dir.path());
        let worker = agent.spawn_loop(Duration::from_secs(30), quiet_factory(), today());

        worker
            .wait_until(|s| s.passes >= 1, Duration::from_secs(2))
            .expect("first pass");

        worker.request_sync();
        let second = worker.wait_until(|s| s.passes >= 2, Duration::from_secs(2));
        assert!(second.is_some(), "a manual request runs a second pass");
        assert_eq!(worker.history().len(), 2);

        worker.stop();
    }

    #[test]
    fn a_failing_loop_shows_error_and_keeps_trying() {
        let dir = tempfile::tempdir().unwrap();
        let agent = idle_agent(dir.path());
        let worker = agent.spawn_loop(Duration::from_millis(20), broken_factory(), today());

        let status = worker
            .wait_until(|s| s.state == SyncState::Error, Duration::from_secs(2))
            .expect("a failing pass is surfaced");
        assert!(status.last_error.is_some());
        // A failed pass is not a successful sync.
        assert!(status.last_sync_unix.is_none());

        // Snapshot the feed while the loop keeps retrying, then stop it. Every
        // outcome on a permanently-failing server is a Failed event.
        let events = worker.history();
        worker.stop();
        assert!(!events.is_empty());
        assert!(events.iter().all(|e| matches!(e, SyncEvent::Failed { .. })));
    }

    #[test]
    fn pausing_holds_every_pass_and_the_request_until_resume() {
        let dir = tempfile::tempdir().unwrap();
        let agent = idle_agent(dir.path());
        let worker = agent.spawn_loop(Duration::from_millis(20), quiet_factory(), today());
        worker
            .wait_until(|s| s.passes >= 1, Duration::from_secs(2))
            .expect("first pass");

        worker.set_paused(true);
        let paused = worker
            .wait_until(|s| s.paused, Duration::from_secs(2))
            .expect("the pause is published");
        assert_eq!(paused.state, SyncState::Idle, "pausing is not a failure");

        // A manual request while paused runs nothing — and is not thrown away:
        // it is the pass resume runs at once, rather than after an interval.
        worker.request_sync();
        thread::sleep(Duration::from_millis(150)); // several intervals' worth
        let held = worker.status();
        assert_eq!(held.passes, paused.passes, "no pass runs while paused");
        assert!(held.paused, "and the pause is still on");

        worker.set_paused(false);
        let resumed = worker
            .wait_until(|s| s.passes > held.passes, Duration::from_secs(2))
            .expect("resume runs the standing request");
        assert!(!resumed.paused);

        worker.stop();
    }

    #[test]
    fn hydrate_is_answered_while_paused_and_is_not_a_pass() {
        let dir = tempfile::tempdir().unwrap();
        let agent = idle_agent(dir.path());
        let worker = agent.spawn_loop(Duration::from_secs(30), quiet_factory(), today());
        let first = worker
            .wait_until(|s| s.passes >= 1, Duration::from_secs(2))
            .expect("first pass");
        worker.set_paused(true);
        worker
            .wait_until(|s| s.paused, Duration::from_secs(2))
            .expect("pause published");

        // The idle index knows nothing, so this fails before any network call —
        // the point is that the paused loop answers it at all, without running
        // a pass.
        let error = worker
            .hydrate_with_timeout("missing.txt", Duration::from_secs(2))
            .unwrap_err();
        assert!(error.contains("knows no file"), "reason: {error}");
        let after = worker.status();
        assert_eq!(after.passes, first.passes, "hydration is not a sync pass");
        assert!(after.paused, "and the pause is still on");

        worker.stop();
    }

    #[test]
    fn a_paused_loop_still_stops() {
        let dir = tempfile::tempdir().unwrap();
        let agent = idle_agent(dir.path());
        // A long interval, so the only pass is the immediate one.
        let worker = agent.spawn_loop(Duration::from_secs(30), quiet_factory(), today());
        worker
            .wait_until(|s| s.passes >= 1, Duration::from_secs(2))
            .expect("first pass");
        worker.set_paused(true);
        assert!(worker.is_paused());
        // Joining must not wait for a pass that is never coming.
        worker.stop();
    }

    #[test]
    fn stopping_is_idempotent_and_joining_does_not_hang() {
        let dir = tempfile::tempdir().unwrap();
        let agent = idle_agent(dir.path());
        let worker = agent.spawn_loop(Duration::from_millis(20), quiet_factory(), today());
        worker
            .wait_until(|s| s.last_sync_unix.is_some(), Duration::from_secs(2))
            .expect("first pass");
        // `stop` consumes the handle, then Drop fires on the moved value; the
        // join guard must keep the second one from panicking on an empty handle.
        worker.stop();
    }
}
