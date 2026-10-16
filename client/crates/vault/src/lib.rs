//! The on-disk layout of a Syncbox vault.
//!
//! A vault is an ordinary directory of ciphertext that sits wherever the user
//! put it:
//!
//! ```text
//! vault/
//!   vault.json                 # KDF parameters and the wrapped master keys
//!   d/aa/bb/<dirId>.c9r        # empty marker per directory, for tree discovery
//!   <dirId>/<name>.c9r         # encrypted file, name encrypted for its dir
//!   <dirId>/<name>.c9s/<id>    # indirection for names too long to store
//! ```
//!
//! Nothing outside `vault.json` is guessable from the plaintext tree: directory
//! ids are HMACs and file names are AES-SIV ciphertexts keyed by their directory.
//! Someone with the folder but not the password sees a flat pile of opaque blobs.
//!
//! This crate knows the layout and the header format. Opening a vault, which
//! needs Argon2id and AES-SIV, arrives with M1.

pub mod config;
pub mod error;
pub mod layout;

pub use config::{VaultConfig, CONFIG_FILE_NAME, CURRENT_VERSION};
pub use error::{Result, VaultError};
