//! Cross-process coordination over the ciphertext store, so `gc` can never
//! prune in front of a writer.
//!
//! [`crate::gc::collect`] refuses to run while anything else holds the store:
//! content added after its liveness sets were built would look like an orphan.
//! That promise needs teeth beyond a docstring once GC runs by policy rather
//! than by a human who looked around first — so every holder of the store
//! announces itself with an advisory `flock` on a hidden file in the store
//! directory:
//!
//! * a **mount session** and a **sync pass** hold it *shared*, for as long as
//!   they write;
//! * a **GC pass** holds it *exclusively*, and only ever via a non-blocking
//!   try — a live holder makes GC skip this round rather than queue behind it
//!   or stall the holder.
//!
//! The lock rides the open file description, so a sync pass that wants to GC
//! at the end of its own run *upgrades* its shared hold in place (same fd):
//! one atomic step from reader to writer, and no window in which a second
//! process's GC could slip in mid-pass.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// The lock file inside the store directory. Hidden, and outside the shard
/// trees GC walks (`chunks/`, `manifests/`), so it is never inventory.
pub const STORE_LOCK_FILE: &str = ".store.lock";

/// An advisory `flock` held on the store directory. The lock is held for
/// exactly as long as this value lives.
pub struct StoreLock {
    file: File,
}

impl StoreLock {
    fn open(store_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(store_dir)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // The file's content is irrelevant — the lock is the descriptor.
            .truncate(false)
            .open(store_dir.join(STORE_LOCK_FILE))?;
        Ok(Self { file })
    }

    /// `flock(2)`, restarting across signals.
    fn flock(&self, operation: libc::c_int) -> io::Result<()> {
        loop {
            // SAFETY: `flock` on our own open fd; the only arguments are the
            // descriptor and flag constants, and no memory is shared.
            let rc = unsafe { libc::flock(self.file.as_raw_fd(), operation) };
            if rc == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }

    /// Shares the store for as long as the returned guard lives: a sync pass
    /// or mount session takes this before it writes anything. Blocks only
    /// while a GC pass holds the store exclusively, which is brief.
    ///
    /// # Errors
    ///
    /// I/O failure creating the store directory or lock file.
    pub fn shared(store_dir: &Path) -> io::Result<Self> {
        let lock = Self::open(store_dir)?;
        lock.flock(libc::LOCK_SH)?;
        Ok(lock)
    }

    /// Claims the store exclusively without waiting: `Some` if the store is
    /// now ours alone, `None` if a mount or sync pass is holding it shared.
    /// This is what an unattended GC asks for — busy means skip, not wait.
    ///
    /// # Errors
    ///
    /// I/O failure other than the lock being busy.
    pub fn try_exclusive(store_dir: &Path) -> io::Result<Option<Self>> {
        let lock = Self::open(store_dir)?;
        match lock.flock(libc::LOCK_EX | libc::LOCK_NB) {
            Ok(()) => Ok(Some(lock)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Turns this shared hold into the exclusive one, in place: no other
    /// reader can be admitted in the gap, and no other writer already holds
    /// it (they could not, while we are shared). Linux `flock` converts a lock
    /// on the same descriptor with a plain call — no separate upgrade
    /// operation exists. `false` means the store has other shared holders — a
    /// live mount — so the caller should skip.
    ///
    /// # Errors
    ///
    /// I/O failure other than the lock being busy.
    pub fn try_upgrade(&self) -> io::Result<bool> {
        match self.flock(libc::LOCK_EX | libc::LOCK_NB) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Gives the exclusive hold back to shared, for a caller that meant this
    /// upgrade as a visit (GC at the end of a sync pass), not a takeover —
    /// again a conversion on the same descriptor.
    ///
    /// # Errors
    ///
    /// I/O failure.
    pub fn downgrade(&self) -> io::Result<()> {
        self.flock(libc::LOCK_SH | libc::LOCK_NB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_shared_holder_joins_while_the_first_holds() {
        let dir = tempfile::tempdir().unwrap();
        let _first = StoreLock::shared(dir.path()).unwrap();
        let second = StoreLock::shared(dir.path());
        assert!(second.is_ok(), "shared holders coexist");
    }

    #[test]
    fn exclusive_is_refused_while_anyone_holds_shared() {
        let dir = tempfile::tempdir().unwrap();
        let shared = StoreLock::shared(dir.path()).unwrap();
        assert!(
            StoreLock::try_exclusive(dir.path()).unwrap().is_none(),
            "a live shared holder must make an exclusive try say busy"
        );

        // An in-place upgrade from shared hits the same wall: another reader
        // is a mount we must not prune in front of.
        let ours = StoreLock::shared(dir.path()).unwrap();
        assert!(
            !ours.try_upgrade().unwrap(),
            "other shared holders block the upgrade"
        );

        drop(shared);
        // Now we are the only reader: the upgrade is ours, alone.
        assert!(
            ours.try_upgrade().unwrap(),
            "upgrading the sole shared hold"
        );
        assert!(
            StoreLock::try_exclusive(dir.path()).unwrap().is_none(),
            "the upgraded hold really is exclusive now"
        );
        ours.downgrade().unwrap();
        drop(ours);
        assert!(
            StoreLock::try_exclusive(dir.path()).unwrap().is_some(),
            "and it releases with the guard"
        );
    }

    #[test]
    fn two_exclusive_holders_never_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let first = StoreLock::try_exclusive(dir.path()).unwrap();
        assert!(first.is_some());
        assert!(
            StoreLock::try_exclusive(dir.path()).unwrap().is_none(),
            "the second must not get in"
        );
        drop(first);
        assert!(StoreLock::try_exclusive(dir.path()).unwrap().is_some());
    }

    #[test]
    fn the_lock_file_lives_outside_the_shard_trees() {
        let dir = tempfile::tempdir().unwrap();
        let lock = StoreLock::shared(dir.path()).unwrap();
        assert!(dir.path().join(STORE_LOCK_FILE).exists());
        // GC walks chunks/ and manifests/; a file at the store root is
        // therefore invisible to inventory by construction.
        assert!(!dir.path().join("chunks").exists());
        drop(lock);
    }
}
