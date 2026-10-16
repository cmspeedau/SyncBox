//! Errors from talking to the server.

use thiserror::Error;

/// Everything that can go wrong in this crate.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The server answered with a status we cannot act on.
    #[error("server returned {status}")]
    Status {
        /// HTTP status code.
        status: u16,
    },

    /// The server refused the request and said why.
    #[error("server refused the request ({code}): {reason}")]
    Refused {
        /// Machine-readable code from the error body.
        code: String,
        /// Human-readable message from the error body.
        reason: String,
    },

    /// A response body was not the shape the protocol promises.
    #[error("malformed response: {0}")]
    Malformed(String),

    /// The request never became a response: a DNS failure, a refused connection,
    /// a TLS error, or a timeout. Distinct from an HTTP status, which the server
    /// did send.
    #[error("transport failure: {0}")]
    Transport(String),

    /// A body did not fit the size the caller was prepared for.
    #[error("response of {actual} bytes exceeds the {limit} byte limit")]
    TooLarge {
        /// Size received.
        actual: usize,
        /// Size allowed.
        limit: usize,
    },
}

/// Result alias used across this crate.
pub type Result<T> = std::result::Result<T, TransportError>;

/// Maps an HTTP status to an error the caller can branch on.
///
/// Keeping this here means every method reports a `401` the same way, so the
/// client can react to "the token expired" in one place.
#[must_use]
pub fn error_from_status(status: u16, reason: &str) -> TransportError {
    match status {
        401 | 403 => TransportError::Refused {
            code: "unauthorized".to_owned(),
            reason: reason.to_owned(),
        },
        404 => TransportError::Refused {
            code: "not_found".to_owned(),
            reason: reason.to_owned(),
        },
        409 => TransportError::Refused {
            code: "conflict".to_owned(),
            reason: reason.to_owned(),
        },
        429 => TransportError::Refused {
            code: "rate_limited".to_owned(),
            reason: reason.to_owned(),
        },
        // Backups endpoints answer this when the server runs with no
        // SYNCBOX_BACKUP_TARGET, so the UI can say "not configured" rather than a
        // bare 501.
        501 => TransportError::Refused {
            code: "not_configured".to_owned(),
            reason: reason.to_owned(),
        },
        other => TransportError::Status { status: other },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failures_are_distinguishable() {
        let err = error_from_status(401, "token expired");
        assert!(matches!(
            err,
            TransportError::Refused { ref code, .. } if code == "unauthorized"
        ));
        assert_eq!(
            err.to_string(),
            "server refused the request (unauthorized): token expired"
        );
    }

    #[test]
    fn a_conflict_is_reported_as_a_conflict() {
        // The engine resolves a 409 by refetching the revision and producing a
        // conflicted copy, so the distinction has to survive the mapping.
        assert!(matches!(
            error_from_status(409, "revision moved"),
            TransportError::Refused { ref code, .. } if code == "conflict"
        ));
    }

    #[test]
    fn a_backup_without_a_target_is_not_configured() {
        // The Backups panel branches on this code to explain why it is empty.
        assert!(matches!(
            error_from_status(501, "no backup target"),
            TransportError::Refused { ref code, .. } if code == "not_configured"
        ));
    }

    #[test]
    fn unknown_statuses_keep_their_number() {
        assert_eq!(
            error_from_status(503, "backing off").to_string(),
            "server returned 503"
        );
    }
}
