//! The CLI's concrete [`Http`] implementation, over `ureq`.
//!
//! The `syncbox-transport` crate stays free of a TLS stack behind a trait; this is
//! where that trait gets a real socket. It uses `ureq` because the sync engine runs
//! a blocking request/response flow and `ureq` needs no async runtime — the same
//! call the desktop app would make, just without a shared agent pool (which M4 can
//! introduce without touching anything above this file).
//!
//! A non-2xx reply is *not* an error here: it is turned back into a [`Response`]
//! with its status and body so `syncbox_transport` can classify it (a `409` is a
//! conflict, a `401` an expired token). Only a request that never reached the
//! server — DNS, TLS, connection refused — becomes a [`TransportError::Transport`].

use std::io::Read;

use syncbox_transport::{Http, Method, Request, Response, Result, TransportError};

/// Sends requests to a fixed server origin over HTTPS/HTTP.
pub struct UreqHttp {
    agent: ureq::Agent,
    base_url: String,
}

impl UreqHttp {
    /// Points the transport at `base_url` (no trailing slash), e.g.
    /// `https://sync.example`.
    #[must_use]
    pub fn new(base_url: &str) -> Self {
        Self {
            agent: ureq::AgentBuilder::new().build(),
            base_url: base_url.trim_end_matches('/').to_owned(),
        }
    }
}

impl Http for UreqHttp {
    fn send(&mut self, request: Request) -> Result<Response> {
        let url = format!("{}{}", self.base_url, request.path);
        let mut call = match request.method {
            Method::Get => self.agent.get(&url),
            Method::Post => self.agent.post(&url),
            Method::Put => self.agent.put(&url),
            Method::Head => self.agent.head(&url),
        };

        if let Some(authorization) = &request.authorization {
            call = call.set("Authorization", authorization);
        }
        // The body's media type is implied by the method in this protocol: every
        // POST carries JSON, every PUT a raw chunk.
        call = match request.method {
            Method::Post => call.set("Content-Type", "application/json"),
            Method::Put => call.set("Content-Type", "application/octet-stream"),
            _ => call,
        };

        let outcome = if request.body.is_empty() && request.method != Method::Put {
            call.call()
        } else {
            call.send_bytes(&request.body)
        };

        let (status, body) = match outcome {
            Ok(response) => (response.status(), read_body(response)?),
            // ureq raises on 4xx/5xx; recover the status and body for the caller.
            Err(ureq::Error::Status(status, response)) => (status, read_body(response)?),
            Err(other) => return Err(TransportError::Transport(other.to_string())),
        };

        Ok(Response { status, body })
    }
}

fn read_body(response: ureq::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut body)
        .map_err(|e| TransportError::Transport(format!("reading response body: {e}")))?;
    Ok(body)
}
