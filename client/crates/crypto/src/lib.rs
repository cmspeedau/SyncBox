//! Cryptographic primitives for Syncbox vaults.
//!
//! A vault holds two 256-bit master keys, as Cryptomator does:
//!
//! - [`MasterKey`] `primary`, which encrypts file content and filenames;
//! - [`MasterKey`] `hmac`, which derives directory ids and chunk ids.
//!
//! Both are generated randomly when the vault is created, wrapped with a
//! key-encryption key derived from the user's password with Argon2id, and stored
//! in the vault's `vault.json` header. Nothing else in the system ever sees the
//! password or the unwrapped keys.
//!
//! This crate is deliberately pure: no filesystem access and no plaintext
//! outliving the call that needed it, so the same code can run on desktop now and
//! on a phone later. Key material is zeroized when it is dropped.
//!
//! ## Status
//!
//! M1 is complete: Argon2id, AES-SIV filenames, AES-GCM content, the HKDF key
//! tree, CSPRNG key generation, and the master-key wrap/unwrap that `vault.json`
//! relies on are all implemented and covered by round-trip tests and the vectors
//! in `docs/format.md`.

pub mod content;
mod derive;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod names;
pub mod wrap;

pub use content::ChunkId;
pub use error::{CryptoError, Result};
pub use kdf::{derive_kek, Kek, Params as KdfParams};
pub use keys::{MasterKey, MasterKeys};
pub use names::{child_dir_id, decrypt_filename, encrypt_filename, DirId};
pub use wrap::{header_mac, unwrap_master_keys, wrap_master_keys};
