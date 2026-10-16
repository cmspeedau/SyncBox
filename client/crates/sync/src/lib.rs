//! Turning local file changes into the smallest set of chunks the server has
//! never seen, and turning server revisions back into local files.
//!
//! Three ideas carry the crate:
//!
//! 1. **Chunk by content, not by offset.** [`FastCdc`] picks boundaries from the
//!    bytes themselves, so an edit near the start of a large file leaves every
//!    later chunk byte-identical and therefore already present on the server.
//! 2. **The index decides what to send.** [`Engine`] asks the index which files
//!    are dirty instead of hashing the whole vault, which is what keeps a run on
//!    a big vault proportional to what actually changed.
//! 3. **A conflict becomes a second file.** Two clients editing one file both keep
//!    their work: the loser is written beside the winner under the name
//!    [`conflicted_copy_name`] produces. Silent overwrite is not an option.
//!
//! Transfer itself arrives with M3, once the transport crate can talk to a
//! server; the chunking, planning, and naming rules here are real and tested now.

pub mod chunker;
pub mod conflict;
pub mod engine;
pub mod error;

pub use chunker::{Chunk, Chunker, FastCdc, FixedSize};
pub use conflict::conflicted_copy_name;
pub use engine::{Engine, SyncReport};
pub use error::{Result, SyncError};
