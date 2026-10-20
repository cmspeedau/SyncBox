//! `syncbox-release` — the documents a desktop release publishes.
//!
//! Run from `client/` by `.github/workflows/release.yml` after `cargo-tauri build`:
//!
//! ```sh
//! cargo run -p syncbox-release -- manifest \
//!   --bundles target/release/bundle \
//!   --repo cmspeedau/SyncBox --tag desktop-v0.2.0 --version 0.2.0 \
//!   --out target/release/bundle/update.json
//!
//! cargo run -p syncbox-release -- apt-index \
//!   --deb target/release/bundle/deb/Syncbox_0.2.0_amd64.deb \
//!   --control /tmp/control --out-dir target/release/bundle/apt
//! ```

use std::{fs, io::Read, path::PathBuf, process::ExitCode};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use syncbox_release::{
    apt::{self, AptOptions},
    manifest::{self, Options},
};

#[derive(Debug, Parser)]
#[command(
    name = "syncbox-release",
    about = "Release-side helpers for the desktop app"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Turn the signed bundles into the JSON tauri-plugin-updater fetches
    Manifest(ManifestArgs),
    /// Turn one .deb into a flat, unsigned apt repository
    AptIndex(AptArgs),
}

#[derive(Debug, clap::Args)]
struct ManifestArgs {
    /// Bundle root written by cargo-tauri (contains appimage/, deb/, macos/)
    #[arg(long)]
    bundles: PathBuf,

    /// GitHub repository as owner/name, for the default asset URLs
    #[arg(long)]
    repo: String,

    /// Tag the assets are attached to, e.g. desktop-v0.2.0
    #[arg(long)]
    tag: String,

    /// The version in tauri.conf.json
    #[arg(long)]
    version: String,

    /// Release notes; mutually exclusive with --notes-file
    #[arg(long, conflicts_with = "notes_file")]
    notes: Option<String>,

    /// Read release notes from a file
    #[arg(long, value_name = "PATH")]
    notes_file: Option<PathBuf>,

    /// Architecture of a macOS .app.tar.gz, whose name carries none
    #[arg(long, default_value = "x86_64")]
    mac_arch: String,

    /// Base URL for assets, instead of the repository's Release download path
    #[arg(long)]
    base_url: Option<String>,

    /// RFC 3339 publication time, instead of now
    #[arg(long)]
    pub_date: Option<String>,

    /// Write here instead of stdout
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct AptArgs {
    /// The .deb the index describes; its name becomes Filename:
    #[arg(long)]
    deb: PathBuf,

    /// The control paragraph, as a file or `-` for stdin
    #[arg(long)]
    control: String,

    /// Directory to write Packages, Packages.gz and Release into
    #[arg(long)]
    out_dir: PathBuf,

    /// Suite: and Codename: in Release
    #[arg(long, default_value = "stable")]
    suite: String,

    /// Origin: in Release
    #[arg(long, default_value = "Syncbox")]
    origin: String,

    /// Label: in Release
    #[arg(long, default_value = "Syncbox")]
    label: String,

    /// RFC 2822 Date:, instead of now
    #[arg(long)]
    date: Option<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("syncbox-release: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Manifest(args) => manifest(args),
        Command::AptIndex(args) => apt_index(args),
    }
}

fn manifest(args: ManifestArgs) -> Result<()> {
    let notes = match (args.notes, args.notes_file) {
        (Some(notes), _) => Some(notes),
        (None, Some(path)) => Some(
            fs::read_to_string(&path)
                .with_context(|| format!("cannot read the notes file {}", path.display()))?,
        ),
        (None, None) => None,
    };

    let manifest = manifest::build(&Options {
        bundles: args.bundles,
        repo: args.repo,
        tag: args.tag,
        version: args.version,
        notes,
        mac_arch: args.mac_arch,
        base_url: args.base_url,
        pub_date: args.pub_date,
    })?;

    let mut json = serde_json::to_string_pretty(&manifest)?;
    json.push('\n');

    match args.out {
        Some(path) => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("cannot create {}", parent.display()))?;
            }
            fs::write(&path, &json).with_context(|| format!("cannot write {}", path.display()))?;
            eprintln!(
                "wrote {} platform(s) to {}",
                manifest.platforms.len(),
                path.display()
            );
        }
        None => print!("{json}"),
    }
    Ok(())
}

fn apt_index(args: AptArgs) -> Result<()> {
    let control = if args.control == "-" {
        let mut control = String::new();
        std::io::stdin()
            .read_to_string(&mut control)
            .context("cannot read the control paragraph from stdin")?;
        control
    } else {
        fs::read_to_string(&args.control)
            .with_context(|| format!("cannot read the control at {}", args.control))?
    };

    let index = apt::build(&AptOptions {
        deb: args.deb,
        control,
        out_dir: args.out_dir,
        suite: args.suite,
        origin: args.origin,
        label: args.label,
        date: args.date,
    })?;

    eprintln!("wrote {}", index.packages.display());
    eprintln!("wrote {}", index.packages_gz.display());
    eprintln!("wrote {}", index.release.display());
    Ok(())
}
