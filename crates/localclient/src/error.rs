//! Error types for the LocalAPI client, mirroring Go's `client/local`
//! error model (AccessDeniedError, PreconditionsFailedError, httpStatusError).

use thiserror::Error;

/// Errors returned by [`LocalClient`](super::LocalClient) methods.
#[derive(Debug, Error)]
pub enum LocalClientError {
    /// Failed to connect to the daemon socket.
    #[error("failed to connect to daemon: {0}")]
    Connect(String),

    /// HTTP 403 — access denied (socket permissions / operator restriction).
    #[error("Access denied: {0}")]
    AccessDenied(String),

    /// HTTP 412 — precondition failed.
    #[error("Preconditions failed: {0}")]
    PreconditionsFailed(String),

    /// Non-200 HTTP status with no specific typed mapping.
    #[error("HTTP {status}: {message}")]
    HttpStatus {
        /// The HTTP status code.
        status: u16,
        /// The error message extracted from the response body.
        message: String,
    },

    /// JSON decode failure.
    #[error("JSON decode error: {0}")]
    Json(String),

    /// I/O error (read/write on the socket).
    #[error("I/O error: {0}")]
    Io(String),

    /// The daemon returned 404 for a whois lookup — no peer owns that IP.
    #[error("no match for IP")]
    PeerNotFound,
}

impl From<std::io::Error> for LocalClientError {
    fn from(e: std::io::Error) -> Self {
        LocalClientError::Io(e.to_string())
    }
}
