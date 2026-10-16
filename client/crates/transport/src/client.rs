//! The client, expressed against a small [`Http`] seam.
//!
//! Keeping the transport behind a trait rather than a concrete HTTP library means
//! three things hold: the crate stays free of a TLS dependency, the sync engine's
//! tests can drive a scripted server without a socket, and the desktop app can put
//! its own connection pool and proxy settings underneath us.

use syncbox_crypto::ChunkId;

use crate::dto::{
    ChunkCheckRequest, ChunkCheckResponse, CommitRequest, CommitResponse, RevisionPage,
    TokenRequest, TokenResponse,
};
use crate::error::{Result, TransportError};

/// An HTTP request, already addressed and authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Method, uppercase.
    pub method: Method,
    /// Path including the `/api/v1` prefix and any query string.
    pub path: String,
    /// Body bytes; empty for a `GET` or `HEAD`.
    pub body: Vec<u8>,
}

/// The methods the protocol uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// Fetch a resource.
    Get,
    /// Fetch headers only, used to ask whether a chunk exists.
    Head,
    /// Submit a body.
    Post,
    /// Store a body at an address, idempotently.
    Put,
}

impl Method {
    /// Method as it appears on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

/// A response body plus its status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Body bytes; empty for a `HEAD`.
    pub body: Vec<u8>,
}

/// Anything that can carry one request.
pub trait Http {
    /// Sends `request` and returns the reply.
    ///
    /// # Errors
    ///
    /// Any [`TransportError`] from the underlying transport, such as a DNS
    /// failure or a timeout.
    fn send(&mut self, request: Request) -> Result<Response>;
}

/// A handle to one vault on one server.
#[derive(Debug)]
pub struct Client<H: Http> {
    /// Server root, without a trailing slash, e.g. `https://sync.example`.
    pub base_url: String,
    /// Bearer token from [`Client::token`].
    pub token: String,
    /// Transport the calls run through.
    pub http: H,
}

impl<H: Http> Client<H> {
    /// A client that has not authenticated yet.
    #[must_use]
    pub fn new(base_url: &str, http: H) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            token: String::new(),
            http,
        }
    }

    /// Absolute URL for a protocol path.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// Exchanges the account password for a bearer token.
    ///
    /// # Errors
    ///
    /// Propagates transport errors and maps a wrong password to
    /// [`TransportError::Refused`].
    pub fn token(&mut self, password: &str) -> Result<TokenResponse> {
        let _ = (
            &self.http,
            TokenRequest {
                password: password.to_owned(),
            },
        );
        Err(TransportError::Unimplemented("token exchange"))
    }

    /// Revisions newer than `since`, oldest first.
    ///
    /// # Errors
    ///
    /// Propagates transport errors, and [`TransportError::Refused`] with code
    /// `not_found` for an unknown vault.
    pub fn revisions(&mut self, vault: &str, since: u64) -> Result<RevisionPage> {
        let _ = (&self.http, vault, since);
        Err(TransportError::Unimplemented("revision listing"))
    }

    /// Which of `ids` the server does not already hold.
    ///
    /// # Errors
    ///
    /// Propagates transport and decoding errors.
    pub fn missing_chunks(&mut self, vault: &str, ids: &[ChunkId]) -> Result<Vec<ChunkId>> {
        let _ = (
            &self.http,
            vault,
            ChunkCheckRequest {
                ids: ids.iter().map(|id| id.as_str().to_owned()).collect(),
            },
            ChunkCheckResponse {
                missing: Vec::new(),
            },
        );
        Err(TransportError::Unimplemented("chunk existence check"))
    }

    /// Uploads one chunk. Idempotent: the id is the address.
    ///
    /// # Errors
    ///
    /// Propagates transport errors.
    pub fn upload_chunk(&mut self, vault: &str, id: &ChunkId, body: &[u8]) -> Result<()> {
        let _ = (&self.http, vault, id, body);
        Err(TransportError::Unimplemented("chunk upload"))
    }

    /// Downloads one chunk.
    ///
    /// # Errors
    ///
    /// Propagates transport errors, and [`TransportError::Refused`] with code
    /// `not_found` for a chunk the server has collected.
    pub fn download_chunk(&mut self, vault: &str, id: &ChunkId) -> Result<Vec<u8>> {
        let _ = (&self.http, vault, id);
        Err(TransportError::Unimplemented("chunk download"))
    }

    /// Commits a new revision, conditional on `parent` still being current.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Refused`] with code `conflict` when another
    /// client committed first, which is the engine's cue to produce a conflicted
    /// copy rather than overwrite.
    pub fn commit(&mut self, vault: &str, request: &CommitRequest) -> Result<CommitResponse> {
        let _ = (&self.http, vault, request);
        Err(TransportError::Unimplemented("revision commit"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records what the engine asked for, so M3's tests can assert on the call
    /// sequence without a server.
    struct Recording {
        calls: Vec<Request>,
    }

    impl Http for Recording {
        fn send(&mut self, request: Request) -> Result<Response> {
            self.calls.push(request);
            Ok(Response {
                status: 200,
                body: Vec::new(),
            })
        }
    }

    #[test]
    fn the_base_url_loses_a_trailing_slash() {
        let client = Client::new("https://sync.example/", Recording { calls: vec![] });
        assert_eq!(
            client.url("/api/v1/vaults/v/revisions"),
            "https://sync.example/api/v1/vaults/v/revisions"
        );
    }

    #[test]
    fn methods_match_the_protocol() {
        assert_eq!(Method::Head.as_str(), "HEAD");
        assert_eq!(Method::Put.as_str(), "PUT");
    }

    #[test]
    fn every_call_is_still_a_stub() {
        let mut client = Client::new("https://sync.example", Recording { calls: vec![] });
        assert!(matches!(
            client.token("hunter2"),
            Err(TransportError::Unimplemented(_))
        ));
        assert!(matches!(
            client.revisions("v", 0),
            Err(TransportError::Unimplemented(_))
        ));
        assert!(matches!(
            client.missing_chunks("v", &[]),
            Err(TransportError::Unimplemented(_))
        ));
        assert!(matches!(
            client.upload_chunk("v", &ChunkId::from_base32("AB"), b"x"),
            Err(TransportError::Unimplemented(_))
        ));
        assert!(matches!(
            client.download_chunk("v", &ChunkId::from_base32("AB")),
            Err(TransportError::Unimplemented(_))
        ));
        assert!(matches!(
            client.commit(
                "v",
                &CommitRequest {
                    parent: 0,
                    revision: crate::dto::Revision {
                        revision: 0,
                        parent: 0,
                        dir_id: String::new(),
                        cipher_name: String::new(),
                        manifest: String::new(),
                        size: 0,
                        modified_unix: 0,
                        deleted: false,
                    },
                }
            ),
            Err(TransportError::Unimplemented(_))
        ));
    }
}
