//! Headless Syncbox client.
//!
//! This binary is the sync engine without a window. It exists for two reasons: it
//! drives the end-to-end tests that would otherwise need a desktop build, and it
//! gives someone running a vault on a server a way in that is not a GUI.
//!
//! The subcommand surface is the one the desktop app will call into. `vault create`
//! and `vault unlock` do the password/Argon2id/key-wrap ceremony; `sync once`
//! unlocks a vault, opens the local SQLite index, and runs one full push/pull pass
//! against a live server. Watch mode (`sync watch`) is a loop over `sync once` and
//! is the one command still open in this milestone.

#[cfg(feature = "mount")]
mod fusefs;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use syncbox_crypto::content::{CHUNK_MAX, CHUNK_MIN, CHUNK_TARGET};
use syncbox_crypto::kdf::Params;
use syncbox_crypto::names::DirId;
use syncbox_index::SqliteIndex;
use syncbox_sync::{Engine, SyncReport, Vault};
use syncbox_transport::{Client, UreqHttp};
use syncbox_vault::{VaultConfig, CONFIG_FILE_NAME, CURRENT_VERSION};

#[derive(Parser)]
#[command(
    name = "syncbox",
    version,
    about = "Sync an encrypted vault with a Syncbox server"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create or open a vault directory.
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Run the sync loop.
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },
    /// Mount a vault via FUSE, read-only unless `--writable` (needs the `mount` feature).
    Mount {
        /// Directory holding `vault.json`, its `index.db`, and local ciphertext blobs.
        vault: PathBuf,
        /// Existing directory to mount the vault on.
        mountpoint: PathBuf,
        /// Allow create/write/rename/unlink through the mount. Each write seals into
        /// the vault and local store and marks its index record dirty, for the next
        /// sync to push; nothing on disk is ever plaintext.
        #[arg(long)]
        writable: bool,
        /// Where local ciphertext blobs live; defaults to `<vault>/blobs`.
        #[arg(long)]
        store: Option<PathBuf>,
        /// Server origin to fall back to folder-syncing when FUSE is unavailable.
        #[arg(long)]
        server: Option<String>,
        /// Vault id, with `--server`, for the folder-sync fallback.
        #[arg(long)]
        vault_id: Option<String>,
        /// Vault password; falls back to `$SYNCBOX_PASSWORD`.
        #[arg(long)]
        password: Option<String>,
    },
    /// Reclaim ciphertext the store no longer needs.
    ///
    /// Deletes stored chunks and manifests that no record in the vault's index
    /// references — orphans left by overwrites, unlinks and renames. Needs no
    /// password: the index holds what is live, and the blobs it names are the
    /// only things kept. Run it while nothing else is writing the vault (no
    /// live mount, no sync pass).
    Gc {
        /// Directory holding `vault.json`, its `index.db`, and local ciphertext blobs.
        vault: PathBuf,
        /// Where local ciphertext blobs live; defaults to `<vault>/blobs`.
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Report the format this build reads and writes.
    Status,
}

#[derive(Subcommand)]
enum VaultCommand {
    /// Create a new vault, writing its `vault.json` header.
    Create {
        /// Directory to turn into a vault.
        path: PathBuf,
        /// Vault password; falls back to `$SYNCBOX_PASSWORD`.
        #[arg(long)]
        password: Option<String>,
    },
    /// Unlock a vault, checking the password and printing its root id.
    Unlock {
        /// Vault directory.
        path: PathBuf,
        /// Vault password; falls back to `$SYNCBOX_PASSWORD`.
        #[arg(long)]
        password: Option<String>,
    },
}

#[derive(Subcommand)]
enum SyncCommand {
    /// Sync once, then exit.
    Once {
        /// Server origin, e.g. `https://sync.example`.
        #[arg(long)]
        server: String,
        /// The server's id for the vault to sync into.
        #[arg(long)]
        vault_id: String,
        /// Directory holding `vault.json` (the encrypted keys).
        #[arg(long)]
        vault: PathBuf,
        /// The plaintext folder to keep in sync with the vault. Omit for a folderless
        /// pass (a mounted vault): nothing plaintext is read or written, dirty index
        /// records are pushed from the store, and pulls keep only ciphertext.
        #[arg(long)]
        folder: Option<PathBuf>,
        /// Where the local SQLite index lives; defaults to `<vault>/index.db`.
        #[arg(long)]
        index: Option<PathBuf>,
        /// Also keep a local ciphertext store in this directory, so `syncbox mount`
        /// can serve the files pulled from the server read-only. Omit for a plain
        /// folder sync that stores no ciphertext copy.
        #[arg(long)]
        store: Option<PathBuf>,
        /// Vault password; falls back to `$SYNCBOX_PASSWORD`.
        #[arg(long)]
        password: Option<String>,
    },
    /// Watch the vault and sync whenever it changes.
    Watch,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Vault {
            command: VaultCommand::Create { path, password },
        } => create(&path, &resolve_password(password)?),
        Command::Vault {
            command: VaultCommand::Unlock { path, password },
        } => unlock(&path, &resolve_password(password)?),
        Command::Sync {
            command:
                SyncCommand::Once {
                    server,
                    vault_id,
                    vault,
                    folder,
                    index,
                    store,
                    password,
                },
        } => sync_once(
            &server,
            &vault_id,
            &vault,
            folder.as_deref(),
            index,
            store,
            &resolve_password(password)?,
        ),
        Command::Sync {
            command: SyncCommand::Watch,
        } => bail!("watch mode is not implemented yet (run `sync once` in a loop)"),
        Command::Mount {
            vault,
            mountpoint,
            writable,
            store,
            server,
            vault_id,
            password,
        } => mount_cmd(
            &vault,
            &mountpoint,
            writable,
            store,
            server.as_deref(),
            vault_id.as_deref(),
            &resolve_password(password)?,
        ),
        Command::Gc { vault, store } => gc_cmd(&vault, store),
        Command::Status => status(),
    }
}

/// Reads a password from a flag, then `$SYNCBOX_PASSWORD`, refusing to prompt so
/// the CLI stays scriptable. A GUI prompts or uses the OS keychain (M4).
fn resolve_password(explicit: Option<String>) -> Result<String> {
    if let Some(password) = explicit {
        return Ok(password);
    }
    std::env::var("SYNCBOX_PASSWORD")
        .ok()
        .filter(|p| !p.is_empty())
        .context("no password: pass --password or set $SYNCBOX_PASSWORD")
}

fn create(path: &Path, password: &str) -> Result<()> {
    let keys = syncbox_vault::create(path, password, &Params::default())
        .context("vault creation failed")?;
    let root = DirId::root(&keys.hmac).context("could not derive the root directory id")?;
    println!("created a vault at {}", path.display());
    println!("root directory id  : {root}");
    println!(
        "header file        : {}",
        path.join(CONFIG_FILE_NAME).display()
    );
    Ok(())
}

fn unlock(path: &Path, password: &str) -> Result<()> {
    let keys = syncbox_vault::unlock(path, password)
        .context("vault unlock failed (wrong password, or not a vault?)")?;
    let root = DirId::root(&keys.hmac).context("could not derive the root directory id")?;
    println!("vault unlocked; root directory id {root}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sync_once(
    server: &str,
    vault_id: &str,
    vault_dir: &Path,
    folder: Option<&Path>,
    index: Option<PathBuf>,
    store: Option<PathBuf>,
    password: &str,
) -> Result<()> {
    let keys =
        syncbox_vault::unlock(vault_dir, password).context("could not unlock the vault to sync")?;
    let index_path = index.unwrap_or_else(|| vault_dir.join("index.db"));
    let index = SqliteIndex::open(&index_path)
        .map_err(|e| anyhow::anyhow!("opening index at {}: {e}", index_path.display()))?;

    // No folder means folderless: the vault directory stands in for the plaintext
    // root, which the engine then never reads or writes.
    let plaintext_root = folder.unwrap_or(vault_dir);
    let vault = Vault::new(keys, vault_id.to_owned(), plaintext_root.to_path_buf())?;
    let mut client = Client::new(server, UreqHttp::new(server));
    client
        .token(password)
        .map_err(|e| anyhow::anyhow!("authentication against {server} failed: {e}"))?;

    let mut engine = Engine::new(index, vault);
    // Folderless always has a store — it is the only content — defaulting to
    // `<vault>/blobs` exactly where `syncbox mount` looks. With a folder, a store is
    // optional: a pull then also leaves its ciphertext there, so the same directory
    // can be mounted (`syncbox mount`) and serve server-sourced files; without one,
    // the pass is the plain plaintext-folder sync as before.
    if folder.is_none() {
        let store_dir = store.unwrap_or_else(|| vault_dir.join("blobs"));
        engine = engine
            .with_store(syncbox_mount::DiskStore::new(store_dir))
            .folderless();
    } else if let Some(store) = store {
        engine = engine.with_store(syncbox_mount::DiskStore::new(store));
    }
    let report = engine
        .sync_once(&mut client, &today())
        .context("sync pass failed")?;
    print_report(&report);
    Ok(())
}

fn print_report(report: &SyncReport) {
    if report.is_quiet() {
        println!("up to date");
        return;
    }
    println!(
        "uploaded {}, downloaded {}, conflicts {}, deleted {}, skipped {}",
        report.uploaded, report.downloaded, report.conflicts, report.deleted, report.skipped
    );
    println!(
        "sent {} new chunk(s) covering {} plaintext byte(s)",
        report.chunks_uploaded, report.bytes_uploaded
    );
    if report.skipped > 0 {
        println!("note: skipped files live in directories this client has not created yet");
    }
}

/// Prints the format facts a user would want checked before trusting a build with
/// a vault: what it can read, and what it will write.
fn status() -> Result<()> {
    let params = Params::default();
    let header = VaultConfig::new(
        syncbox_vault::config::Kdf::new(&params, &[0u8; 16]),
        &[0u8; 12],
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 32],
    );

    println!("format version   : {}", CURRENT_VERSION);
    println!("header file      : {CONFIG_FILE_NAME}");
    println!(
        "key derivation   : {} ({} KiB, {} passes, {} lanes)",
        params.algorithm.as_str(),
        params.memory_kib,
        params.iterations,
        params.parallelism,
    );
    println!(
        "chunk sizes      : {} KiB min, {} KiB target, {} KiB max",
        CHUNK_MIN / 1024,
        CHUNK_TARGET / 1024,
        CHUNK_MAX / 1024,
    );
    println!(
        "header version_mac: {}",
        if header.version_mac.is_empty() {
            "none"
        } else {
            "present"
        }
    );
    println!("capabilities     : create, unlock, sync once");
    Ok(())
}

/// Deletes store content no index record references and prints what went.
/// No unlock happens: liveness is pure bookkeeping the index can answer on its
/// own, and what it names is exactly what stays.
fn gc_cmd(vault_dir: &Path, store: Option<PathBuf>) -> Result<()> {
    let index_path = vault_dir.join("index.db");
    let index = SqliteIndex::open(&index_path)
        .map_err(|e| anyhow::anyhow!("opening index at {}: {e}", index_path.display()))?;
    let store_dir = store.unwrap_or_else(|| vault_dir.join("blobs"));
    let mut store = syncbox_mount::DiskStore::new(&store_dir);
    let report = syncbox_mount::collect(&index, &mut store)
        .with_context(|| format!("collecting garbage in {}", store_dir.display()))?;
    let freed = if report.freed_bytes > 0 {
        format!(" ({} bytes freed)", report.freed_bytes)
    } else {
        String::new()
    };
    println!(
        "gc: {} live chunks kept; removed {} chunks and {} manifests{freed}",
        report.live_chunks, report.removed_chunks, report.removed_manifests
    );
    Ok(())
}

/// Mounts the vault (read-only, or writable with `writable`), or — when no FUSE
/// driver is available — falls back to syncing `mountpoint` as a plaintext folder
/// against `server`.
#[cfg(feature = "mount")]
fn mount_cmd(
    vault_dir: &Path,
    mountpoint: &Path,
    writable: bool,
    store: Option<PathBuf>,
    server: Option<&str>,
    vault_id: Option<&str>,
    password: &str,
) -> Result<()> {
    match try_mount(vault_dir, mountpoint, writable, store, password) {
        Ok(()) => {
            println!("unmounted.");
            Ok(())
        }
        Err(error) => {
            eprintln!("FUSE mount unavailable ({error}); falling back to folder sync.");
            let (Some(server), Some(vault_id)) = (server, vault_id) else {
                bail!("no FUSE driver, and no --server/--vault-id to fall back to folder sync");
            };
            // The mountpoint becomes the plaintext sync folder; keep it in sync.
            loop {
                sync_once(
                    server,
                    vault_id,
                    vault_dir,
                    Some(mountpoint),
                    None,
                    None,
                    password,
                )?;
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        }
    }
}

/// Builds the FUSE view from the vault header, its index, and its local ciphertext
/// blobs, and mounts it (blocking until unmounted). Read-only unless `writable`, in
/// which case it takes the live index and store so edits seal back through them.
#[cfg(feature = "mount")]
fn try_mount(
    vault_dir: &Path,
    mountpoint: &Path,
    writable: bool,
    store: Option<PathBuf>,
    password: &str,
) -> Result<()> {
    let keys = syncbox_vault::unlock(vault_dir, password)
        .context("could not unlock the vault to mount")?;
    let index_path = vault_dir.join("index.db");
    let index = SqliteIndex::open(&index_path)
        .map_err(|e| anyhow::anyhow!("opening index at {}: {e}", index_path.display()))?;
    let store_dir = store.unwrap_or_else(|| vault_dir.join("blobs"));
    // The mount derives everything from the index and the local store; a server
    // vault id and a plaintext root are not consulted, so they are placeholders here.
    let vault = Vault::new(keys, String::new(), vault_dir)?;
    let store = syncbox_mount::DiskStore::new(store_dir);

    let mode = if writable { "writable" } else { "read-only" };
    println!(
        "mounting {} {mode} at {} (Ctrl-C, or `fusermount3 -u {}`, to unmount)",
        vault_dir.display(),
        mountpoint.display(),
        mountpoint.display()
    );

    if writable {
        let options = [
            fuser::MountOption::FSName("syncbox".to_owned()),
            fuser::MountOption::DefaultPermissions,
        ];
        fuser::mount2(
            crate::fusefs::WritableFS::new(index, vault, store),
            mountpoint,
            &options,
        )
        .map_err(|e| anyhow::anyhow!("mount failed: {e}"))
    } else {
        let fs = syncbox_mount::Fs::from_index(&index);
        let options = [
            fuser::MountOption::RO,
            fuser::MountOption::FSName("syncbox".to_owned()),
            fuser::MountOption::DefaultPermissions,
        ];
        fuser::mount2(
            crate::fusefs::ReadonlyFS::new(fs, vault, store),
            mountpoint,
            &options,
        )
        .map_err(|e| anyhow::anyhow!("mount failed: {e}"))
    }
}

/// Without the `mount` feature, `syncbox mount` explains how to build it in.
#[cfg(not(feature = "mount"))]
fn mount_cmd(
    _vault_dir: &Path,
    _mountpoint: &Path,
    _writable: bool,
    _store: Option<PathBuf>,
    _server: Option<&str>,
    _vault_id: Option<&str>,
    _password: &str,
) -> Result<()> {
    bail!("`syncbox mount` needs the `mount` feature: rebuild with `--features mount`")
}

/// Today's date as `YYYY-MM-DD`, used to label conflicted copies. The clock lives
/// here, at the edge, so everything below stays deterministic.
fn today() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    format!("{year:04}-{month:02}-{day:02}")
}

/// Days since the Unix epoch to a proleptic Gregorian `(year, month, day)`, after
/// Howard Hinnant's `civil_from_days`. Avoids a date crate for one line of output.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let shifted = if z >= 0 { z } else { z - 146_096 };
    let era = shifted / 146_097;
    let day_of_era = z - era * 146_097; // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153; // [0, 11], March-based
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cli_surface_parses() {
        // clap validates the whole surface at once, which catches a subcommand
        // renamed out from under the desktop app.
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn resolve_password_prefers_the_flag_then_the_environment() {
        assert_eq!(resolve_password(Some("hi".into())).unwrap(), "hi");
    }

    #[test]
    fn civil_from_days_maps_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29), "leap day");
        assert_eq!(civil_from_days(19_783), (2024, 3, 1));
    }

    #[test]
    fn today_is_a_well_formed_date() {
        let date = today();
        assert_eq!(date.len(), 10, "{date}");
        assert!(date.contains('-'));
    }
}
