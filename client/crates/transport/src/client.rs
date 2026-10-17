//! The client, expressed against a small [`Http`] seam.
//!
//! Keeping the transport behind a trait rather than a concrete HTTP library means
//! three things hold: the crate stays free of a TLS dependency, the sync engine's
//! tests can drive a scripted server without a socket, and the desktop app can put
//! its own connection pool and proxy settings underneath us.
//!
//! Each method builds a [`Request`], stamps the bearer token onto it (the client
//! owns the token, the transport does not), sends it through [`Http`], and turns
//! the reply into a typed value. Anything other than a 2xx becomes a
//! [`TransportError`] via [`error_from_status`], so a `409` on commit and a `401`
//! on an expired token are distinguishable by every caller in the same way.

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::Duration;
use syncbox_crypto::ChunkId;

use crate::dto::{
    ChunkCheckRequest, ChunkCheckResponse, CommitRequest, CommitResponse, ErrorResponse,
    RestoreReport, RevisionPage, Snapshot, TokenRequest, TokenResponse, VaultListing, VerifyReport,
};
use crate::error::{error_from_status, Result, TransportError};

/// An HTTP request, already addressed and authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Method, uppercase.
    pub method: Method,
    /// Path including the `/api/v1` prefix and any query string.
    pub path: String,
    /// Body bytes; empty for a `GET` or `HEAD`.
    pub body: Vec<u8>,
    /// Full `Authorization` header value (`"Bearer …"`), or `None` for the
    /// unauthenticated token exchange. The concrete [`Http`] implementation turns
    /// this into the actual header; keeping it on the request means the transport
    /// never has to know what a token is.
    pub authorization: Option<String>,
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

/// Serialises a request body to JSON.
fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| TransportError::Malformed(format!("encode request: {e}")))
}

/// Deserialises a JSON response body, reported as [`TransportError::Malformed`].
fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body)
        .map_err(|e| TransportError::Malformed(format!("decode reply: {e}")))
}

/// Pulls a human-readable reason out of an error body, falling back to a truncated
/// slice of the raw bytes so a non-JSON error (a proxy's HTML page, say) still
/// carries something into the message.
fn reason_of(body: &[u8]) -> String {
    if let Ok(err) = serde_json::from_slice::<ErrorResponse>(body) {
        return err.reason;
    }
    let text = String::from_utf8_lossy(body);
    let trimmed = text.trim();
    trimmed.chars().take(200).collect()
}

/// Turns a non-2xx response into the right error, leaving a success untouched.
///
/// A refusal body carries the server's stable machine-readable code, which is
/// a better key than a status guess — `500 corrupt_snapshot` and a generic
/// `500 internal` are different problems an operator acts on differently. The
/// status mapping only speaks when the body is not a well-formed refusal.
fn ensure_ok(response: &Response) -> Result<()> {
    if (200..300).contains(&response.status) {
        Ok(())
    } else if let Ok(err) = serde_json::from_slice::<ErrorResponse>(&response.body) {
        Err(TransportError::Refused {
            code: err.code,
            reason: err.reason,
        })
    } else {
        Err(error_from_status(
            response.status,
            &reason_of(&response.body),
        ))
    }
}

/// A handle to one vault on one server.
#[derive(Debug)]
pub struct Client<H: Http> {
    /// Server root, without a trailing slash, e.g. `https://sync.example`.
    pub base_url: String,
    /// Bearer token from [`Client::token`].
    pub token: String,
    /// How many times a chunk transfer retries after the server answers
    /// `429 rate_limited` before the refusal is surfaced. Zero never retries.
    pub rate_limit_retries: u32,
    /// The first wait after a `429`, doubled with each retry. Tests shorten it;
    /// production waits the server's `Retry-After` (whole seconds) out anyway.
    pub rate_limit_backoff: Duration,
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
            rate_limit_retries: 4,
            rate_limit_backoff: Duration::from_millis(500),
            http,
        }
    }

    /// Absolute URL for a protocol path.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// Sends one request, attaching the bearer token when the endpoint needs it.
    fn call(
        &mut self,
        method: Method,
        path: String,
        body: Vec<u8>,
        authenticated: bool,
    ) -> Result<Response> {
        let authorization = if authenticated && !self.token.is_empty() {
            Some(format!("Bearer {}", self.token))
        } else {
            None
        };
        self.http.send(Request {
            method,
            path,
            body,
            authorization,
        })
    }

    /// One call to a bulk-transfer endpoint, honouring the server's throttle.
    ///
    /// A `429` means "come back in a second", so we wait and come back — with a
    /// doubling backoff that quickly reaches the whole-second granularity the
    /// server's `Retry-After` header promises. Retrying is safe here precisely
    /// because every endpoint behind this helper is idempotent: chunk bytes are
    /// content-addressed, and the existence check reads. Commit is the one
    /// non-idempotent call, so it retries on a stricter condition — see
    /// [`Client::commit`].
    fn call_transfer(&mut self, method: Method, path: String, body: Vec<u8>) -> Result<Response> {
        let mut backoff = self.rate_limit_backoff;
        for attempt in 0..=self.rate_limit_retries {
            let response = self.call(method, path.clone(), body.clone(), true)?;
            if response.status != 429 || attempt == self.rate_limit_retries {
                return Ok(response);
            }
            std::thread::sleep(backoff);
            backoff *= 2;
        }
        unreachable!("the loop returns on its last attempt")
    }

    /// True for the server's own throttle refusal: the protocol's `429` is the
    /// one carrying a structured `rate_limited` body, and the limiter that
    /// writes it runs before any handler — the refused request was never
    /// processed. A bare `429` from an intermediary says nothing about what
    /// happened downstream, so it never earns a replay here.
    fn is_our_rate_limit(response: &Response) -> bool {
        response.status == 429
            && serde_json::from_slice::<ErrorResponse>(&response.body)
                .is_ok_and(|e| e.code == "rate_limited")
    }

    /// Exchanges the account password for a bearer token, which the client keeps
    /// for every later call.
    ///
    /// # Errors
    ///
    /// Propagates transport errors and maps a wrong password to
    /// [`TransportError::Refused`].
    pub fn token(&mut self, password: &str) -> Result<TokenResponse> {
        let response = self.call(
            Method::Post,
            "/api/v1/auth/token".to_owned(),
            json(&TokenRequest {
                password: password.to_owned(),
            })?,
            false,
        )?;
        ensure_ok(&response)?;
        let issued: TokenResponse = parse(&response.body)?;
        self.token = issued.token.clone();
        Ok(issued)
    }

    /// The server's vault registry, in the client-facing shape.
    ///
    /// A server older than the registry answers 404, surfaced as
    /// [`TransportError::Refused`] with code `not_found` like any other
    /// refusal — callers fall back to an explicit vault id.
    ///
    /// # Errors
    ///
    /// Propagates transport and decoding errors.
    pub fn vaults(&mut self) -> Result<VaultListing> {
        let response = self.call(Method::Get, "/vaults".to_owned(), Vec::new(), true)?;
        ensure_ok(&response)?;
        parse(&response.body)
    }

    /// Revisions newer than `since`, oldest first.
    ///
    /// # Errors
    ///
    /// Propagates transport errors, and [`TransportError::Refused`] with code
    /// `not_found` for an unknown vault.
    pub fn revisions(&mut self, vault: &str, since: u64) -> Result<RevisionPage> {
        let response = self.call(
            Method::Get,
            format!("/api/v1/vaults/{vault}/revisions?since={since}"),
            Vec::new(),
            true,
        )?;
        ensure_ok(&response)?;
        parse(&response.body)
    }

    /// Which of `ids` the server does not already hold.
    ///
    /// # Errors
    ///
    /// Propagates transport and decoding errors.
    pub fn missing_chunks(&mut self, vault: &str, ids: &[ChunkId]) -> Result<Vec<ChunkId>> {
        let body = json(&ChunkCheckRequest {
            ids: ids.iter().map(|id| id.as_str().to_owned()).collect(),
        })?;
        let response = self.call_transfer(
            Method::Post,
            format!("/api/v1/vaults/{vault}/chunks/exists"),
            body,
        )?;
        ensure_ok(&response)?;
        let check: ChunkCheckResponse = parse(&response.body)?;
        Ok(check
            .missing
            .into_iter()
            .map(|id| ChunkId::from_base32(&id))
            .collect())
    }

    /// Uploads one chunk. Idempotent: the id is the address.
    ///
    /// # Errors
    ///
    /// Propagates transport errors.
    pub fn upload_chunk(&mut self, vault: &str, id: &ChunkId, body: &[u8]) -> Result<()> {
        let response = self.call_transfer(
            Method::Put,
            format!("/api/v1/vaults/{vault}/chunks/{}", id.as_str()),
            body.to_vec(),
        )?;
        ensure_ok(&response)
    }

    /// Downloads one chunk.
    ///
    /// # Errors
    ///
    /// Propagates transport errors, and [`TransportError::Refused`] with code
    /// `not_found` for a chunk the server has collected.
    pub fn download_chunk(&mut self, vault: &str, id: &ChunkId) -> Result<Vec<u8>> {
        let response = self.call_transfer(
            Method::Get,
            format!("/api/v1/vaults/{vault}/chunks/{}", id.as_str()),
            Vec::new(),
        )?;
        ensure_ok(&response)?;
        Ok(response.body)
    }

    /// Commits a new revision, conditional on `parent` still being current.
    ///
    /// A commit is not idempotent in general, so it is replayed after `429` only
    /// on one strict condition: the refusal carries the protocol's own
    /// `rate_limited` body, which only this server's limiter writes, and that
    /// limiter refuses *before the handler runs* — the commit never happened, and
    /// a replay is the same request. A `429` from anything else (a proxy, say,
    /// that may already have delivered the request onward) surfaces unretried.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Refused`] with code `conflict` when another
    /// client committed first, which is the engine's cue to produce a conflicted
    /// copy rather than overwrite.
    pub fn commit(&mut self, vault: &str, request: &CommitRequest) -> Result<CommitResponse> {
        let path = format!("/api/v1/vaults/{vault}/revisions");
        let body = json(request)?;
        let mut backoff = self.rate_limit_backoff;
        for attempt in 0..=self.rate_limit_retries {
            let response = self.call(Method::Post, path.clone(), body.clone(), true)?;
            if attempt == self.rate_limit_retries || !Self::is_our_rate_limit(&response) {
                ensure_ok(&response)?;
                return parse(&response.body);
            }
            std::thread::sleep(backoff);
            backoff *= 2;
        }
        unreachable!("the loop returns on its last attempt")
    }

    /// Lists the server's snapshots, newest first.
    ///
    /// A server run with no backup target answers `501 not_configured`, surfaced as
    /// [`TransportError::Refused`] with that code so the UI can explain the empty
    /// list rather than showing a failure.
    ///
    /// # Errors
    ///
    /// Propagates transport and decoding errors.
    pub fn backups(&mut self) -> Result<Vec<Snapshot>> {
        let response = self.call(Method::Get, "/admin/backups".to_owned(), Vec::new(), true)?;
        ensure_ok(&response)?;
        parse(&response.body)
    }

    /// Asks the server to take a snapshot now and returns it.
    ///
    /// # Errors
    ///
    /// Propagates transport and decoding errors; `501 not_configured` when the
    /// server has no backup target.
    pub fn create_backup(&mut self) -> Result<Snapshot> {
        let response = self.call(Method::Post, "/admin/backups".to_owned(), Vec::new(), true)?;
        ensure_ok(&response)?;
        parse(&response.body)
    }

    /// Asks the server to re-hash a snapshot against its own manifest: every
    /// chunk and the metadata file, byte for byte. The answer is either this
    /// proof or a refusal — `404 not_found` for a snapshot that never landed,
    /// `500 corrupt_snapshot` for one whose bytes no longer match.
    ///
    /// # Errors
    ///
    /// Propagates transport and decoding errors.
    pub fn verify_backup(&mut self, id: &str) -> Result<VerifyReport> {
        let response = self.call(
            Method::Post,
            format!("/admin/backups/{id}/verify"),
            Vec::new(),
            true,
        )?;
        ensure_ok(&response)?;
        parse(&response.body)
    }

    /// Asks the server to copy a snapshot into `dest_dir` **on the server's
    /// machine** — the offline restore drill: restore into a fresh directory,
    /// then run a server pointed at it and let clients sync against the
    /// resurrection. The server verifies before it copies, and refuses a
    /// destination that already holds data (`409 restore_target_occupied`).
    ///
    /// # Errors
    ///
    /// Propagates transport and decoding errors.
    pub fn restore_backup(&mut self, id: &str, dest_dir: &str) -> Result<RestoreReport> {
        #[derive(Serialize)]
        struct RestoreRequest<'a> {
            dest_dir: &'a str,
        }
        let response = self.call(
            Method::Post,
            format!("/admin/backups/{id}/restore"),
            json(&RestoreRequest { dest_dir })?,
            true,
        )?;
        ensure_ok(&response)?;
        parse(&response.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    use crate::dto::{Revision, ServerVault, VaultListing};

    /// Records each request and answers from a queued list, so a test can pin both
    /// what the client sent and how it read the reply.
    struct Scripted {
        calls: Vec<Request>,
        replies: VecDeque<Response>,
    }

    impl Scripted {
        fn new(replies: Vec<Response>) -> Self {
            Self {
                calls: Vec::new(),
                replies: replies.into(),
            }
        }

        fn body<T: serde::Serialize>(status: u16, value: &T) -> Response {
            Response {
                status,
                body: serde_json::to_vec(value).expect("serialisable"),
            }
        }
    }

    impl Http for Scripted {
        fn send(&mut self, request: Request) -> Result<Response> {
            self.calls.push(request);
            self.replies
                .pop_front()
                .ok_or(TransportError::Status { status: 599 })
        }
    }

    #[test]
    fn the_base_url_loses_a_trailing_slash() {
        let client = Client::new("https://sync.example/", Scripted::new(vec![]));
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
    fn the_token_call_is_unauthenticated_and_stores_the_bearer() {
        let issued = TokenResponse {
            token: "tok123".into(),
            expires_unix: 999,
        };
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![Scripted::body(200, &issued)]),
        );
        let got = client.token("hunter2").expect("token");
        assert_eq!(got, issued);
        assert_eq!(client.token, "tok123", "kept for later calls");

        let sent = &client.http.calls[0];
        assert_eq!(sent.method, Method::Post);
        assert_eq!(sent.path, "/api/v1/auth/token");
        assert!(
            sent.authorization.is_none(),
            "token exchange carries no bearer"
        );
        let req: TokenRequest = serde_json::from_slice(&sent.body).unwrap();
        assert_eq!(req.password, "hunter2");
    }

    #[test]
    fn vaults_reads_the_registry_authenticated_and_whole() {
        let listing = VaultListing {
            vaults: vec![
                ServerVault {
                    id: "ABCDEFGH".into(),
                    name: "Photos".into(),
                    location: "Syncbox/Photos".into(),
                    archived: false,
                },
                ServerVault {
                    id: "QRSTUVWX".into(),
                    name: String::new(),
                    location: String::new(),
                    archived: true,
                },
            ],
        };
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![Scripted::body(200, &listing)]),
        );
        client.token = "tok123".into();
        let got = client.vaults().expect("listing");
        assert_eq!(got, listing);

        let sent = &client.http.calls[0];
        assert_eq!(sent.method, Method::Get);
        assert_eq!(sent.path, "/vaults");
        assert_eq!(sent.authorization.as_deref(), Some("Bearer tok123"));
    }

    #[test]
    fn later_calls_carry_the_bearer_and_revisions_asks_since() {
        let page = RevisionPage {
            revisions: vec![],
            upto: 7,
        };
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![Scripted::body(200, &page)]),
        );
        client.token = "tok123".into();
        let got = client.revisions("vault", 7).expect("page");
        assert_eq!(got, page);

        let sent = &client.http.calls[0];
        assert_eq!(sent.method, Method::Get);
        assert_eq!(sent.path, "/api/v1/vaults/vault/revisions?since=7");
        assert_eq!(sent.authorization.as_deref(), Some("Bearer tok123"));
    }

    #[test]
    fn a_commit_conflict_surfaces_as_a_conflict() {
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![Scripted::body(
                409,
                &ErrorResponse {
                    code: "conflict".into(),
                    reason: "revision moved".into(),
                },
            )]),
        );
        client.token = "t".into();
        let request = CommitRequest {
            parent: 4,
            revision: Revision {
                revision: 5,
                parent: 4,
                dir_id: "AA".into(),
                cipher_name: "BB".into(),
                manifest: String::new(),
                size: 1,
                modified_unix: 0,
                deleted: false,
            },
        };
        let err = client.commit("vault", &request).expect_err("409");
        assert!(matches!(
            err,
            TransportError::Refused { ref code, .. } if code == "conflict"
        ));
    }

    #[test]
    fn missing_chunks_maps_the_missing_ids() {
        let reply = ChunkCheckResponse {
            missing: vec!["AAAA".into(), "BBBB".into()],
        };
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![Scripted::body(200, &reply)]),
        );
        client.token = "t".into();
        let ids = vec![
            ChunkId::from_base32("AAAA"),
            ChunkId::from_base32("BBBB"),
            ChunkId::from_base32("CCCC"),
        ];
        let missing = client.missing_chunks("vault", &ids).expect("missing");
        assert_eq!(
            missing,
            vec![ChunkId::from_base32("AAAA"), ChunkId::from_base32("BBBB")]
        );
        let sent = &client.http.calls[0];
        let req: ChunkCheckRequest = serde_json::from_slice(&sent.body).unwrap();
        assert_eq!(req.ids.len(), 3, "all ids offered");
    }

    #[test]
    fn chunk_upload_puts_the_bytes_and_download_returns_them() {
        let id = ChunkId::from_base32("ABCD");
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![
                Response {
                    status: 200,
                    body: vec![],
                },
                Response {
                    status: 200,
                    body: b"payload".to_vec(),
                },
            ]),
        );
        client.token = "t".into();
        client
            .upload_chunk("vault", &id, b"payload")
            .expect("upload");
        let got = client.download_chunk("vault", &id).expect("download");
        assert_eq!(got, b"payload");

        let upload = &client.http.calls[0];
        assert_eq!(upload.method, Method::Put);
        assert_eq!(upload.path, "/api/v1/vaults/vault/chunks/ABCD");
        assert_eq!(upload.body, b"payload");
    }

    #[test]
    fn a_missing_chunk_download_is_not_found() {
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![Scripted::body(
                404,
                &ErrorResponse {
                    code: "not_found".into(),
                    reason: "gone".into(),
                },
            )]),
        );
        client.token = "t".into();
        let err = client
            .download_chunk("vault", &ChunkId::from_base32("ABCD"))
            .expect_err("404");
        assert!(matches!(
            err,
            TransportError::Refused { ref code, .. } if code == "not_found"
        ));
    }

    #[test]
    fn backups_lists_snapshots_from_the_admin_route() {
        // The admin endpoint answers in Go's default field casing (ID/CreatedAt/
        // Manifest); parsing it is the whole point of this test.
        let body = r#"[{"ID":"2026-10-16T120000Z-abcd","CreatedAt":"2026-10-16T12:00:00Z",
            "Manifest":{"version":1,"id":"x","server_version":"0.1.0","chunk_bytes":42,
            "chunks":[{"id":"A","size":42,"sha256":"deadbeef"}]}}]"#;
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![Response {
                status: 200,
                body: body.as_bytes().to_vec(),
            }]),
        );
        client.token = "t".into();
        let list = client.backups().expect("list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "2026-10-16T120000Z-abcd");
        assert_eq!(list[0].manifest.chunk_bytes, 42);
        assert_eq!(list[0].manifest.chunk_count(), 1);

        let sent = &client.http.calls[0];
        assert_eq!(sent.method, Method::Get);
        assert_eq!(sent.path, "/admin/backups");
        assert_eq!(sent.authorization.as_deref(), Some("Bearer t"));
    }

    #[test]
    fn create_backup_posts_to_the_admin_route() {
        let body = r#"{"ID":"snap1","CreatedAt":"2026-10-16T13:00:00Z","Manifest":{"version":1,"chunks":[]}}"#;
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![Response {
                status: 201,
                body: body.as_bytes().to_vec(),
            }]),
        );
        client.token = "t".into();
        let snapshot = client.create_backup().expect("created");
        assert_eq!(snapshot.id, "snap1");
        assert_eq!(snapshot.manifest.chunk_count(), 0);

        let sent = &client.http.calls[0];
        assert_eq!(sent.method, Method::Post);
        assert_eq!(sent.path, "/admin/backups");
    }

    #[test]
    fn verify_backup_posts_to_the_snapshot_verify_route() {
        let body = r#"{"id":"snap1","chunks":7,"chunk_bytes":123,"metadata_sha256":"ab12"}"#;
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![Response {
                status: 200,
                body: body.as_bytes().to_vec(),
            }]),
        );
        client.token = "t".into();
        let report = client.verify_backup("snap1").expect("verified");
        assert_eq!(report.id, "snap1");
        assert_eq!(report.chunks, 7);
        assert_eq!(report.metadata_sha256, "ab12");

        let sent = &client.http.calls[0];
        assert_eq!(sent.method, Method::Post);
        assert_eq!(sent.path, "/admin/backups/snap1/verify");
    }

    #[test]
    fn restore_backup_sends_the_destination_and_reads_the_report() {
        let body = r#"{"id":"snap1","dest_dir":"/srv/restored","chunks":7,"chunk_bytes":123}"#;
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![Response {
                status: 200,
                body: body.as_bytes().to_vec(),
            }]),
        );
        client.token = "t".into();
        let report = client
            .restore_backup("snap1", "/srv/restored")
            .expect("restored");
        assert_eq!(report.dest_dir, "/srv/restored");
        assert_eq!(report.chunks, 7);

        let sent = &client.http.calls[0];
        assert_eq!(sent.path, "/admin/backups/snap1/restore");
        assert_eq!(
            String::from_utf8(sent.body.clone()).expect("utf-8 body"),
            r#"{"dest_dir":"/srv/restored"}"#
        );
    }

    #[test]
    fn a_corrupt_snapshot_surfaces_as_a_refusal() {
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![Response {
                status: 500,
                body:
                    br#"{"code":"corrupt_snapshot","reason":"snapshot is corrupt: sha mismatch"}"#
                        .to_vec(),
            }]),
        );
        client.token = "t".into();
        let error = client.verify_backup("snap1").expect_err("must fail");
        match error {
            TransportError::Refused { code, reason } => {
                assert_eq!(code, "corrupt_snapshot");
                assert!(reason.contains("sha mismatch"), "{reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_rate_limited_chunk_get_retries_until_the_burst_clears() {
        let refusal = Scripted::body(
            429,
            &ErrorResponse {
                code: "rate_limited".into(),
                reason: "too many requests".into(),
            },
        );
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![
                refusal.clone(),
                refusal,
                Response {
                    status: 200,
                    body: b"payload".to_vec(),
                },
            ]),
        );
        client.token = "t".into();
        client.rate_limit_backoff = Duration::from_millis(1);
        let body = client
            .download_chunk("vault", &ChunkId::from_base32("AB12"))
            .expect("third try lands");
        assert_eq!(body, b"payload");
        assert_eq!(client.http.calls.len(), 3, "two refusals then the payload");
    }

    #[test]
    fn a_rate_limit_that_never_clears_surfaces_as_a_refusal() {
        let refusal = Scripted::body(
            429,
            &ErrorResponse {
                code: "rate_limited".into(),
                reason: "still too many".into(),
            },
        );
        let replies = (0..3).map(|_| refusal.clone()).collect();
        let mut client = Client::new("https://sync.example", Scripted::new(replies));
        client.token = "t".into();
        client.rate_limit_backoff = Duration::from_millis(1);
        client.rate_limit_retries = 2; // three total attempts, all refusals
        let error = client
            .upload_chunk("vault", &ChunkId::from_base32("AB12"), b"x")
            .expect_err("must give up");
        assert!(matches!(
            error,
            TransportError::Refused { ref code, .. } if code == "rate_limited"
        ));
        assert_eq!(client.http.calls.len(), 3);
    }

    #[test]
    fn a_commit_refused_by_the_servers_limiter_is_replayed() {
        // The protocol's own 429 body proves the refusal happened before the
        // handler, so replaying the commit cannot double-apply.
        let refusal = Scripted::body(
            429,
            &ErrorResponse {
                code: "rate_limited".into(),
                reason: "slow down".into(),
            },
        );
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![
                refusal,
                Response {
                    status: 201,
                    body: br#"{"revision":7}"#.to_vec(),
                },
            ]),
        );
        client.token = "t".into();
        client.rate_limit_backoff = Duration::from_millis(1);
        let response = client
            .commit(
                "vault",
                &CommitRequest {
                    parent: 0,
                    revision: Revision {
                        revision: 0,
                        parent: 0,
                        dir_id: "AA".into(),
                        cipher_name: "BB".into(),
                        manifest: String::new(),
                        size: 0,
                        modified_unix: 0,
                        deleted: true,
                    },
                },
            )
            .expect("the replay lands");
        assert_eq!(response.revision, 7);
        assert_eq!(client.http.calls.len(), 2);
    }

    #[test]
    fn a_bare_429_never_buys_a_commit_replay() {
        // A 429 without the protocol's rate_limited body could have come from an
        // intermediary that already forwarded the request — surface it, do not
        // risk a second commit.
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![Response {
                status: 429,
                body: b"<html>proxy busy</html>".to_vec(),
            }]),
        );
        client.token = "t".into();
        client.rate_limit_backoff = Duration::from_millis(1);
        let error = client
            .commit(
                "vault",
                &CommitRequest {
                    parent: 0,
                    revision: Revision {
                        revision: 0,
                        parent: 0,
                        dir_id: "AA".into(),
                        cipher_name: "BB".into(),
                        manifest: String::new(),
                        size: 0,
                        modified_unix: 0,
                        deleted: true,
                    },
                },
            )
            .expect_err("one call, no replay");
        assert!(matches!(
            error,
            TransportError::Refused { ref code, .. } if code == "rate_limited"
        ));
        assert_eq!(client.http.calls.len(), 1);
    }

    #[test]
    fn backups_reports_not_configured() {
        let mut client = Client::new(
            "https://sync.example",
            Scripted::new(vec![Scripted::body(
                501,
                &ErrorResponse {
                    code: "not_configured".into(),
                    reason: "no backup target is configured".into(),
                },
            )]),
        );
        client.token = "t".into();
        let err = client.backups().expect_err("501");
        assert!(matches!(
            err,
            TransportError::Refused { ref code, .. } if code == "not_configured"
        ));
    }
}
