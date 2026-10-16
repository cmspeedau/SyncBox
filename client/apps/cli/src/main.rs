//! Headless Syncbox client.
//!
//! This binary is the sync engine without a window. It exists for two reasons: it
//! drives the end-to-end tests that would otherwise need a desktop build, and it
//! gives someone running a vault on a server a way in that is not a GUI.
//!
//! The subcommand surface is the one the desktop app will call into, so it is
//! settled now even though most of it reports which milestone implements it.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use syncbox_crypto::content::{CHUNK_MAX, CHUNK_MIN, CHUNK_TARGET};
use syncbox_crypto::kdf::Params;
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
    /// Report the format this build reads and writes.
    Status,
}

#[derive(Subcommand)]
enum VaultCommand {
    /// Create a new vault, writing its `vault.json` header.
    Create {
        /// Directory to turn into a vault.
        path: PathBuf,
    },
    /// Unlock a vault and keep it open for a mount.
    Unlock {
        /// Vault directory.
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum SyncCommand {
    /// Sync once, then exit.
    Once,
    /// Watch the vault and sync whenever it changes.
    Watch,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Vault {
            command: VaultCommand::Create { path },
        } => unimplemented_yet("vault creation", "M1", &path.display().to_string()),
        Command::Vault {
            command: VaultCommand::Unlock { path },
        } => unimplemented_yet("vault unlock", "M1", &path.display().to_string()),
        Command::Sync {
            command: SyncCommand::Once,
        } => unimplemented_yet("a sync pass", "M3", "one pass"),
        Command::Sync {
            command: SyncCommand::Watch,
        } => unimplemented_yet("the watcher", "M3", "watch mode"),
        Command::Status => status(),
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
    println!("vault creation   : not implemented until M1");
    Ok(())
}

/// Reports the milestone that supplies a feature, quoting what was asked for so a
/// script's output stays useful.
fn unimplemented_yet(feature: &str, milestone: &str, target: &str) -> Result<()> {
    bail!("{feature} is not implemented until {milestone} (asked for: {target})")
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
    fn an_unimplemented_command_names_its_milestone() {
        let err =
            unimplemented_yet("vault creation", "M1", "/tmp/v").expect_err("must fail until M1");
        assert_eq!(
            err.to_string(),
            "vault creation is not implemented until M1 (asked for: /tmp/v)"
        );
    }
}
