//! Talking to a Syncbox server.
//!
//! The server is deliberately close to stupid: it stores opaque chunks under
//! content-addressed ids and hands out revision records it cannot read. Everything
//! that would need a key to make sense of lives in [`dto`] as an already-encrypted
//! blob.
//!
//! The types here are the wire contract and are mirrored by the Go server in
//! `server/internal/api`; `docs/protocol.md` is the document both sides are written
//! against. Field names are snake_case on the wire for exactly that reason.
//!
//! [`Http`] is the seam that keeps this crate free of a TLS stack: the engine codes
//! against the trait, a real client implements it with whatever HTTP library the
//! desktop app already carries, and the tests use a fake.

pub mod client;
pub mod dto;
pub mod error;

#[cfg(feature = "ureq")]
mod ureq_http;

pub use client::{Client, Http, Method, Request, Response};
pub use error::{error_from_status, Result, TransportError};
#[cfg(feature = "ureq")]
pub use ureq_http::UreqHttp;
