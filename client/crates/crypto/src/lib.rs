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
//! M1 implements the primitives. Until then the encoders, layout constants, and
//! parameter types here are real and tested, while key derivation, AES-SIV, and
//! AES-GCM entry points return [`CryptoError::Unimplemented`].
//!
//! [`CryptoError::Unimplemented`]: error::CryptoError::Unimplemented

pub mod content;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod names;

pub use content::ChunkId;
pub use error::{CryptoError, Result};
pub use kdf::{derive_kek, Kek, Params as KdfParams};
pub use keys::{MasterKey, MasterKeys};
pub use names::DirId;
