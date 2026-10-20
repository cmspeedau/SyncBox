//! What happens after `cargo-tauri build`: the documents a release publishes.
//!
//! The desktop bundles are signed by tauri itself (`createUpdaterArtifacts`), but
//! nothing turns the resulting `.sig` files into the static `update.json` that
//! `tauri-plugin-updater` fetches, or the `.deb` into an apt repository. This crate
//! does those two jobs, so their shape can be tested without a runner, a key or a
//! network.
//!
//! It is not part of the product: the binary is run by `.github/workflows/release.yml`
//! against `client/target/release/bundle`.

pub mod apt;
pub mod manifest;
pub(crate) mod time;

pub use apt::{AptIndex, AptOptions};
pub use manifest::{build, Manifest, Options, Platform};
