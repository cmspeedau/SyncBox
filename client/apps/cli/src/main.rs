//! Headless Syncbox client.
//!
//! This binary is the sync engine without a window. It exists for two reasons: it
//! drives the end-to-end tests that would otherwise need a desktop build, and it
//! gives someone running a space on a server a way in that is not a GUI.
//!
//! The subcommand surface is the one the desktop app will call into. `vault create`
//! and `vault unlock` do the password/Argon2id/key-wrap ceremony; `sync once`
//! opens the local SQLite index and runs one full push/pull pass against a live
//! server. It reads the space's mode from the server's registry: a **vault** is
//! unlocked with the password and sealed on the client, a **sync space** holds no
//! keys and is sent in the clear. Watch mode (`sync watch`) is a loop over
//! `sync once` and is the one command still open in this milestone.

#[cfg(feature = "mount")]
mod fusefs;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use syncbox_crypto::content::{CHUNK_MAX, CHUNK_MIN, CHUNK_TARGET};
use syncbox_crypto::kdf::Params;
use syncbox_crypto::names::DirId;
use syncbox_index::{Index as _, SqliteIndex};
use syncbox_sync::{Engine, SyncReport, Vault};
use syncbox_transport::dto::SpaceMode;
use syncbox_transport::{Client, Http, TransportError, UreqHttp};
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
    /// only things kept. Runs are coordination-checked: if a live mount or
    /// sync pass holds the store, this refuses rather than pruning in front
    /// of it. `sync once` also collects on its own schedule (`--gc`).
    Gc {
        /// Directory holding `vault.json`, its `index.db`, and local ciphertext blobs.
        vault: PathBuf,
        /// Where local ciphertext blobs live; defaults to `<vault>/blobs`.
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Server snapshots: list, take, verify, and restore them.
    ///
    /// Backups are a server-side facility; these commands talk to the server
    /// directly (no vault directory involved). A server started without a
    /// backup target answers `not_configured`, which these commands report as
    /// plainly as any other refusal.
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    /// Report the format this build reads and writes.
    Status,
}

#[derive(Subcommand)]
enum BackupCommand {
    /// List the server's snapshots, newest first.
    List {
        /// Server origin, e.g. https://sync.example
        #[arg(long)]
        server: String,
        /// Server password; falls back to `$SYNCBOX_PASSWORD`.
        #[arg(long)]
        password: Option<String>,
    },
    /// Ask the server to take a snapshot now.
    Now {
        /// Server origin.
        #[arg(long)]
        server: String,
        /// Server password; falls back to `$SYNCBOX_PASSWORD`.
        #[arg(long)]
        password: Option<String>,
    },
    /// Prove a snapshot on the backup target: the server re-hashes every chunk
    /// and the metadata file against the manifest the snapshot was sealed with.
    Verify {
        /// Snapshot id, as shown by `backup list`.
        id: String,
        /// Server origin.
        #[arg(long)]
        server: String,
        /// Server password; falls back to `$SYNCBOX_PASSWORD`.
        #[arg(long)]
        password: Option<String>,
    },
    /// Copy a snapshot into a fresh directory on the server machine — the
    /// restore drill. The server verifies first and refuses a destination that
    /// already holds a restore. Point a server at the result and let clients
    /// sync against the resurrection.
    Restore {
        /// Snapshot id, as shown by `backup list`.
        id: String,
        /// Server-side destination directory for the restored data directory.
        #[arg(long)]
        dest: String,
        /// Server origin.
        #[arg(long)]
        server: String,
        /// Server password; falls back to `$SYNCBOX_PASSWORD`.
        #[arg(long)]
        password: Option<String>,
    },
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
// A clap subcommand's shape is a CLI surface: exactly one variant is ever
// live, exactly once per process, right before it is destructured. Boxing its
// fields to shave the discriminant would tax the parser for no running cost.
#[allow(clippy::large_enum_variant)]
enum SyncCommand {
    /// Sync once, then exit.
    Once {
        /// Server origin, e.g. `https://sync.example`.
        #[arg(long)]
        server: String,
        /// The server's id for the space to sync into; `--space-id` is an
        /// alias. Omit it to let the server decide: with exactly one space,
        /// that one; with several, name the one you mean. Cannot be combined
        /// with `--vault-name`.
        #[arg(long, visible_alias = "space-id", conflicts_with = "vault_name")]
        vault_id: Option<String>,
        /// The operator's name for the space, resolved against the server's
        /// registry — the pairing story: set a space up on the server, point
        /// this client at `--server` and `--vault-name`.
        #[arg(long)]
        vault_name: Option<String>,
        /// Directory holding `vault.json` (the encrypted keys) for a vault, or
        /// the local index for a sync space. A sync space has no keys, so no
        /// header is needed.
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
        /// Reclaim dead ciphertext from the store at the end of the pass, at most
        /// this often: `off`, or a span like `1d`, `12h`, `45m` (default `1d`).
        /// A due round that finds the store held by a live mount skips this pass
        /// rather than waiting — nothing is ever pruned in front of a writer.
        #[arg(long, default_value = "1d")]
        gc: String,
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
                    vault_name,
                    vault,
                    folder,
                    index,
                    store,
                    gc,
                    password,
                },
        } => sync_once(
            &server,
            vault_id.as_deref(),
            vault_name.as_deref(),
            &vault,
            folder.as_deref(),
            index,
            store,
            &gc,
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
        Command::Backup { command } => backup_cmd(command),
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

/// Which vault on the server does this client mean?
///
/// Resolves which space to sync and the mode its registry entry declares.
///
/// Three doors, deliberately. `--vault-id` (alias `--space-id`) is the expert's
/// door: the id needs no name lookup. `--vault-name` is the pairing story:
/// whatever the operator called the space in the console is what the human
/// types here. And with neither, a server holding exactly one live space picks
/// it — the home-server case, where "point the client at the URL" is the whole
/// configuration. A multi-space server refuses to guess and prints the menu.
///
/// The mode comes from the registry so a sync space is not sealed by mistake.
/// A server that predates the registry, and a space it has no entry for, both
/// read as a vault: that is the encrypted world they always were, and guessing
/// plaintext from an unknown id is the one unrecoverable mistake here.
fn resolve_space<H: Http>(
    client: &mut Client<H>,
    server: &str,
    vault_id: Option<&str>,
    vault_name: Option<&str>,
) -> Result<(String, SpaceMode)> {
    let listing = match client.vaults() {
        Ok(listing) => Some(listing),
        Err(TransportError::Refused { code, .. }) if code == "not_found" => None,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "asking {server} for its spaces failed: {e}"
            ))
        }
    };

    if let Some(id) = vault_id {
        let mode = listing
            .as_ref()
            .and_then(|listing| listing.vaults.iter().find(|v| v.id == id))
            .map_or(SpaceMode::Vault, |v| v.mode.effective());
        return Ok((id.to_owned(), mode));
    }

    let Some(listing) = listing else {
        bail!("{server} does not offer a space registry; name the space with --vault-id")
    };

    // The label a human recognises: name when it has one, id always.
    let label = |v: &syncbox_transport::dto::ServerVault| {
        if v.name.is_empty() {
            v.id.clone()
        } else {
            format!("{} ({})", v.name, v.id)
        }
    };

    if let Some(wanted) = vault_name {
        let matching: Vec<_> = listing.vaults.iter().filter(|v| v.name == wanted).collect();
        return match matching.len() {
            0 => {
                let known: Vec<String> = listing.vaults.iter().map(label).collect();
                bail!(
                    "no space named {wanted:?} on {server}; it knows: {}",
                    if known.is_empty() {
                        "none yet".to_owned()
                    } else {
                        known.join(", ")
                    }
                );
            }
            1 if matching[0].archived => {
                bail!("space {wanted:?} is archived on {server}; un-archive it there first");
            }
            1 => Ok((matching[0].id.clone(), matching[0].mode.effective())),
            n => bail!("{server} has {n} spaces named {wanted:?}; say which by --vault-id"),
        };
    }

    let live: Vec<_> = listing.vaults.iter().filter(|v| !v.archived).collect();
    match live.len() {
        0 => bail!("{server} has no spaces to sync yet; set one up on the server first"),
        1 => {
            println!("using the server's only space: {}", label(live[0]));
            Ok((live[0].id.clone(), live[0].mode.effective()))
        }
        n => {
            let menu: Vec<String> = live.iter().map(|v| label(v)).collect();
            bail!(
                "{server} has {n} spaces — say which you mean with --vault-name or --vault-id: {}",
                menu.join(", ")
            );
        }
    }
}

/// Whether `candidate` is `parent` or sits under it, comparing the two places
/// rather than the two spellings.
///
/// Both paths are made absolute and lexically normalised (`.` dropped, `..`
/// popped), so `./index.db` and `/home/u/Files/index.db` compare as the same
/// place when the working directory is `/home/u/Files`.
fn path_is_inside(candidate: &Path, parent: &Path) -> bool {
    absolute_normalized(candidate).starts_with(absolute_normalized(parent))
}

/// The absolute, lexically normalised form of `path`. No filesystem access, so
/// it works for a path that does not exist yet.
fn absolute_normalized(path: &Path) -> PathBuf {
    let base = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut out = PathBuf::new();
    for component in base.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn sync_once(
    server: &str,
    vault_id: Option<&str>,
    vault_name: Option<&str>,
    vault_dir: &Path,
    folder: Option<&Path>,
    index: Option<PathBuf>,
    store: Option<PathBuf>,
    gc_spec: &str,
    password: &str,
) -> Result<()> {
    // Resolve which vault the server holds before anything local: the
    // exchange is two round trips, and a wrong pairing should fail on the
    // server's answer, not after an Argon2 unlock of keys that turn out to
    // be for the wrong vault.
    let mut client = Client::new(server, UreqHttp::new(server));
    client
        .token(password)
        .map_err(|e| anyhow::anyhow!("authentication against {server} failed: {e}"))?;
    let (vault_id, mode) = resolve_space(&mut client, server, vault_id, vault_name)?;

    // Parse the gc spec before anything expensive: a typo should fail the
    // command at once, not after a full sync pass has already run.
    let gc_policy = parse_gc_spec(gc_spec)?;
    let index_path = index.unwrap_or_else(|| vault_dir.join("index.db"));
    // The folder scan pushes every file it finds, so an index inside the synced
    // folder would be uploaded as a peer's file — and re-uploaded every pass as
    // it changes. A vault keeps its state in `--vault` beside its header; a sync
    // space has no header to make that obvious, so refuse the collision out loud.
    if let Some(folder) = folder {
        if path_is_inside(&index_path, folder) {
            bail!(
                "the local index {} is inside the synced folder {}; keep them apart \
                 (pass --index outside the folder, or a separate --vault directory)",
                index_path.display(),
                folder.display()
            );
        }
    }
    let index = SqliteIndex::open(&index_path)
        .map_err(|e| anyhow::anyhow!("opening index at {}: {e}", index_path.display()))?;

    // No folder means folderless: the vault directory stands in for the plaintext
    // root, which the engine then never reads or writes.
    let plaintext_root = folder.unwrap_or(vault_dir);
    // The registry's mode chooses the codec. A vault needs its header unlocked;
    // a sync space holds no keys, so nothing here reads `vault.json` — and the
    // password only ever authenticated the server above.
    let vault = match mode {
        SpaceMode::Sync => Vault::sync_space(vault_id, plaintext_root.to_path_buf()),
        _ => {
            let keys = syncbox_vault::unlock(vault_dir, password)
                .context("could not unlock the vault to sync")?;
            Vault::new(keys, vault_id, plaintext_root.to_path_buf())?
        }
    };

    // Folderless always has a store — it is the only content — defaulting to
    // `<vault>/blobs` exactly where `syncbox mount` looks. With a folder, a store is
    // optional: a pull then also leaves its ciphertext there, so the same directory
    // can be mounted (`syncbox mount`) and serve server-sourced files; without one,
    // the pass is the plain plaintext-folder sync as before.
    let store_dir = if folder.is_none() {
        Some(store.unwrap_or_else(|| vault_dir.join("blobs")))
    } else {
        store
    };
    // Announce this process as a writer of the store for the whole pass — a pull
    // writes chunks as they arrive even when nothing of the user's is — so a
    // concurrent `syncbox gc` declines its round rather than pruning in front
    // of the staging this pass is doing.
    let store_guard = match &store_dir {
        Some(dir) => Some(
            syncbox_mount::StoreLock::shared(dir)
                .with_context(|| format!("locking store at {}", dir.display()))?,
        ),
        None => None,
    };
    let mut engine = Engine::new(index, vault);
    if let Some(dir) = &store_dir {
        engine = engine.with_store(syncbox_mount::DiskStore::new(dir.clone()));
        if folder.is_none() {
            engine = engine.folderless();
        }
    }
    let report = engine
        .sync_once(&mut client, &today())
        .context("sync pass failed")?;
    print_report(&report);

    // The pass is the quiescent moment GC has been waiting for: nothing else in
    // this process touches store or index now, so the pass upgrades its own
    // shared hold to exclusive and collects, or steps aside if a mount holds
    // the store shared. The engine's index moved into it at construction, so
    // the stamping opens a second connection to the same database — sequential,
    // and SQLite takes the write lock for the single upsert.
    if let (Some(dir), Some(guard)) = (&store_dir, &store_guard) {
        if gc_policy != syncbox_mount::GcPolicy::Off {
            let mut gc_index = SqliteIndex::open(&index_path)
                .map_err(|e| anyhow::anyhow!("opening index at {}: {e}", index_path.display()))?;
            let mut gc_store = syncbox_mount::DiskStore::new(dir);
            match syncbox_mount::maybe_collect(
                &mut gc_index,
                &mut gc_store,
                guard,
                gc_policy,
                unix_now(),
            )
            .context("store gc failed")?
            {
                syncbox_mount::MaybeGc::Collected(r)
                    if r.removed_chunks > 0 || r.removed_manifests > 0 =>
                {
                    println!(
                        "gc: reclaimed {} chunk(s) and {} manifest(s), {} byte(s) freed",
                        r.removed_chunks, r.removed_manifests, r.freed_bytes
                    );
                }
                syncbox_mount::MaybeGc::Collected(_) => println!("gc: store already tight"),
                syncbox_mount::MaybeGc::Busy => {
                    println!("gc skipped: the store is held by a live mount");
                }
                syncbox_mount::MaybeGc::NotDue => {}
            }
        }
    }
    Ok(())
}

/// Parses `--gc`: `off`, or a count with a unit suffix (`1d`, `12h`, `45m`).
/// A zero interval is legal and means "collect at the end of every pass".
fn parse_gc_spec(spec: &str) -> Result<syncbox_mount::GcPolicy> {
    let spec = spec.trim().to_ascii_lowercase();
    if spec == "off" {
        return Ok(syncbox_mount::GcPolicy::Off);
    }
    let per = match spec.chars().last() {
        Some('d') => 86_400,
        Some('h') => 3_600,
        Some('m') => 60,
        _ => bail!("`--gc` wants `off` or a span like `1d`, `12h`, `45m`; got `{spec}`"),
    };
    let count: u64 = spec[..spec.len() - 1]
        .trim()
        .parse()
        .with_context(|| format!("`--gc {spec}` has no leading count"))?;
    Ok(syncbox_mount::GcPolicy::Interval {
        seconds: count.saturating_mul(per),
    })
}

/// Whole seconds since the unix epoch, for stamping GC rounds.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
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
    if report.resumed_chunks > 0 {
        println!(
            "resumed {} chunk(s) from the local store instead of re-downloading them",
            report.resumed_chunks
        );
    }
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
    let mut index = SqliteIndex::open(&index_path)
        .map_err(|e| anyhow::anyhow!("opening index at {}: {e}", index_path.display()))?;
    let store_dir = store.unwrap_or_else(|| vault_dir.join("blobs"));
    // The promise `collect` documents, now enforced rather than requested: a
    // live mount or sync pass holds the store shared, and this non-blocking
    // claim says so instead of pruning in front of it.
    let Some(_guard) = syncbox_mount::StoreLock::try_exclusive(&store_dir)
        .with_context(|| format!("locking store at {}", store_dir.display()))?
    else {
        bail!(
            "the store at {} is held by a live mount or sync pass; nothing was collected",
            store_dir.display()
        );
    };
    let mut store = syncbox_mount::DiskStore::new(&store_dir);
    let report = syncbox_mount::collect(&index, &mut store)
        .with_context(|| format!("collecting garbage in {}", store_dir.display()))?;
    // A manual round resets the auto-collect clock too: the next opportunistic
    // pass waits its interval from this one, not from the last automatic round.
    index.set_meta_value(syncbox_mount::LAST_GC_KEY, &unix_now().to_string());
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

/// Drives the server's backup endpoints: every subcommand shares one
/// authenticated client and one refusal explanation.
fn backup_cmd(command: BackupCommand) -> Result<()> {
    match command {
        BackupCommand::List { server, password } => {
            let mut client = backup_client(&server, &resolve_password(password)?)?;
            let snapshots = client.backups().map_err(explain_backup_failure)?;
            if snapshots.is_empty() {
                println!("no snapshots on {server} yet.");
            }
            for snapshot in snapshots {
                println!(
                    "{}  {}  {} chunks, {} bytes",
                    snapshot.id,
                    snapshot.created_at,
                    snapshot.manifest.chunk_count(),
                    snapshot.manifest.chunk_bytes
                );
            }
        }
        BackupCommand::Now { server, password } => {
            let mut client = backup_client(&server, &resolve_password(password)?)?;
            let snapshot = client.create_backup().map_err(explain_backup_failure)?;
            println!(
                "snapshot {} taken at {} ({} chunks, {} bytes).",
                snapshot.id,
                snapshot.created_at,
                snapshot.manifest.chunk_count(),
                snapshot.manifest.chunk_bytes
            );
        }
        BackupCommand::Verify {
            id,
            server,
            password,
        } => {
            let mut client = backup_client(&server, &resolve_password(password)?)?;
            let report = client.verify_backup(&id).map_err(explain_backup_failure)?;
            println!(
                "snapshot {}: {} chunks ({} bytes) and its metadata verified — every object on the backup target matches the hash its manifest recorded.",
                report.id, report.chunks, report.chunk_bytes
            );
        }
        BackupCommand::Restore {
            id,
            dest,
            server,
            password,
        } => {
            let mut client = backup_client(&server, &resolve_password(password)?)?;
            let report = client
                .restore_backup(&id, &dest)
                .map_err(explain_backup_failure)?;
            println!(
                "snapshot {} restored into {} on the server ({} chunks, {} bytes).",
                report.id, report.dest_dir, report.chunks, report.chunk_bytes
            );
            println!(
                "drill next: start a server pointed at {}, then let a client sync against it — the restored data must serve every file back.",
                report.dest_dir
            );
        }
    }
    Ok(())
}

/// An authenticated admin client for the backup endpoints.
fn backup_client(server: &str, password: &str) -> Result<Client<UreqHttp>> {
    let mut client = Client::new(server, UreqHttp::new(server));
    client
        .token(password)
        .map_err(|e| anyhow::anyhow!("authentication against {server} failed: {e}"))?;
    Ok(client)
}

/// Turns the backup API's stable error codes into advice, not just refusals.
fn explain_backup_failure(error: TransportError) -> anyhow::Error {
    match &error {
        TransportError::Refused { code, reason } if code == "not_configured" => {
            anyhow::anyhow!("the server has no backup target configured ({reason})")
        }
        TransportError::Refused { code, reason } if code == "corrupt_snapshot" => {
            anyhow::anyhow!("the snapshot is CORRUPT on the backup target: {reason}")
        }
        TransportError::Refused { code, reason } if code == "restore_target_occupied" => {
            anyhow::anyhow!("{reason} — restore into a fresh directory instead")
        }
        other => anyhow::anyhow!("backup request failed: {other}"),
    }
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
                    // Folder fallback with no store: there is no ciphertext to
                    // collect, and `off` states that rather than relying on it.
                    "off",
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
    // The session holds the store *shared* until it unmounts — even read-only,
    // because serving a file the store lacks caches what it fetches. `syncbox
    // gc` and the opportunistic gc of a sync pass claim the store non-blocking,
    // so while this runs they politely decline their rounds.
    let _store_guard = syncbox_mount::StoreLock::shared(&store_dir)
        .with_context(|| format!("locking store at {}", store_dir.display()))?;
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
    use syncbox_transport::{Http, Request, Response};

    #[test]
    fn the_gc_spec_parses_off_and_spans() {
        assert_eq!(parse_gc_spec("off").unwrap(), syncbox_mount::GcPolicy::Off);
        assert_eq!(
            parse_gc_spec("OFF").unwrap(),
            syncbox_mount::GcPolicy::Off,
            "case is the user's business"
        );
        assert_eq!(
            parse_gc_spec("1d").unwrap(),
            syncbox_mount::GcPolicy::Interval { seconds: 86_400 }
        );
        assert_eq!(
            parse_gc_spec(" 12 h ").unwrap(),
            syncbox_mount::GcPolicy::Interval { seconds: 43_200 },
            "whitespace is tolerated"
        );
        assert_eq!(
            parse_gc_spec("45m").unwrap(),
            syncbox_mount::GcPolicy::Interval { seconds: 2_700 }
        );
        assert_eq!(
            parse_gc_spec("0h").unwrap(),
            syncbox_mount::GcPolicy::Interval { seconds: 0 },
            "zero means every pass, and says so in numbers"
        );
        parse_gc_spec("daily").expect_err("words are not spans");
        parse_gc_spec("d").expect_err("a unit with no count is a typo");
        parse_gc_spec("1w").expect_err("weeks are not on the menu");
    }

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

    #[test]
    fn an_index_inside_the_synced_folder_is_detected() {
        let files = Path::new("/home/u/Files");
        assert!(path_is_inside(Path::new("/home/u/Files/index.db"), files));
        assert!(path_is_inside(
            Path::new("/home/u/Files/sub/index.db"),
            files
        ));
        assert!(!path_is_inside(Path::new("/home/u/state/index.db"), files));
        assert!(
            !path_is_inside(Path::new("/home/u/Files2/index.db"), files),
            "a shared name prefix is not containment"
        );
        // Relative and dotted spellings resolve to the same place.
        assert!(path_is_inside(Path::new("./index.db"), Path::new(".")));
        assert!(path_is_inside(
            Path::new("Files/../Files/index.db"),
            Path::new("Files")
        ));
    }

    /// Answers `GET /vaults` from a fixed body; nothing else is expected.
    struct Registry(&'static str);

    impl Http for Registry {
        fn send(&mut self, request: Request) -> syncbox_transport::Result<Response> {
            assert!(
                request.path.ends_with("/vaults"),
                "unexpected request {}",
                request.path
            );
            Ok(Response {
                status: 200,
                body: self.0.as_bytes().to_vec(),
            })
        }
    }

    fn registry(body: &'static str) -> Client<Registry> {
        let mut client = Client::new("http://srv", Registry(body));
        // Set the bearer directly: `resolve_space` only reads the registry, and
        // the token exchange is not what is under test.
        client.token = "tok".into();
        client
    }

    #[test]
    fn resolve_space_takes_the_mode_from_the_registry() {
        let mut client = registry(
            r#"{"vaults":[
                {"id":"space-sync","name":"Files","mode":"sync","archived":false},
                {"id":"space-vault","name":"Private","mode":"vault","archived":false}
            ]}"#,
        );
        let (id, mode) = resolve_space(&mut client, "http://srv", None, Some("Files")).unwrap();
        assert_eq!(id, "space-sync");
        assert_eq!(mode, SpaceMode::Sync, "a sync space is read as sync");

        let (id, mode) = resolve_space(&mut client, "http://srv", None, Some("Private")).unwrap();
        assert_eq!(id, "space-vault");
        assert_eq!(mode, SpaceMode::Vault);
    }

    #[test]
    fn an_id_the_registry_does_not_know_stays_a_vault() {
        let mut client = registry(
            r#"{"vaults":[{"id":"space-sync","name":"Files","mode":"sync","archived":false}]}"#,
        );
        // Even the expert door reads the mode, so a sync space is not sealed.
        let (_, mode) = resolve_space(&mut client, "http://srv", Some("space-sync"), None).unwrap();
        assert_eq!(mode, SpaceMode::Sync);
        // An unregistered (or predating) id is the encrypted world it always was.
        let (_, mode) = resolve_space(&mut client, "http://srv", Some("ghost"), None).unwrap();
        assert_eq!(mode, SpaceMode::Vault);
    }
}
