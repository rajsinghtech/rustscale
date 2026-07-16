//! Streaming reader for the `watch-ipn-bus` LocalAPI endpoint. The daemon
//! sends newline-delimited JSON [`Notify`](rustscale_ipn::Notify) messages
//! over a long-lived HTTP/1.1 connection (connection-close delimited, no
//! Content-Length). This module provides [`WatchIpnBus`] which wraps the
//! safesocket [`Connection`](rustscale_safesocket::Connection) and yields
//! decoded `Notify` messages one at a time.

use std::collections::VecDeque;

use rustscale_ipn::Notify;
use rustscale_safesocket::Connection;
use tokio::io::AsyncReadExt;

use crate::LocalClientError;

/// Keep LocalAPI streaming responses bounded even if a compromised or buggy
/// daemon never terminates an HTTP header or JSON frame.
const MAX_STREAM_HEADER_BYTES: usize = 64 * 1024;
const MAX_NOTIFY_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Raw pcap byte stream returned by `POST /localapi/v0/debug-capture`.
pub struct DebugCapture {
    stream: Connection,
    buffered: Vec<u8>,
    header_consumed: bool,
}

impl DebugCapture {
    pub(super) fn new(stream: Connection) -> Self {
        Self {
            stream,
            buffered: Vec::with_capacity(8192),
            header_consumed: false,
        }
    }

    /// Read raw pcap bytes, returning zero at EOF.
    pub async fn read(&mut self, out: &mut [u8]) -> Result<usize, LocalClientError> {
        self.consume_header().await?;
        if !self.buffered.is_empty() {
            let len = out.len().min(self.buffered.len());
            out[..len].copy_from_slice(&self.buffered[..len]);
            self.buffered.drain(..len);
            return Ok(len);
        }
        self.stream
            .read(out)
            .await
            .map_err(|e| LocalClientError::Io(e.to_string()))
    }

    /// Close the capture connection and ask the LocalAPI handler to clean up.
    pub async fn close(&mut self) -> Result<(), LocalClientError> {
        use tokio::io::AsyncWriteExt;
        self.stream
            .shutdown()
            .await
            .map_err(|e| LocalClientError::Io(e.to_string()))
    }

    async fn consume_header(&mut self) -> Result<(), LocalClientError> {
        while !self.header_consumed {
            if let Some(pos) = self.buffered.windows(4).position(|w| w == b"\r\n\r\n") {
                let header = &self.buffered[..pos];
                if !header.starts_with(b"HTTP/1.1 200 ") {
                    return Err(LocalClientError::HttpStatus {
                        status: 0,
                        message: String::from_utf8_lossy(header).into_owned(),
                    });
                }
                self.buffered.drain(..pos + 4);
                self.header_consumed = true;
                break;
            }
            let mut tmp = [0u8; 4096];
            let count = self
                .stream
                .read(&mut tmp)
                .await
                .map_err(|e| LocalClientError::Io(e.to_string()))?;
            if count == 0 {
                return Err(LocalClientError::Io(
                    "capture closed before HTTP response".into(),
                ));
            }
            self.buffered.extend_from_slice(&tmp[..count]);
            if self.buffered.len() > MAX_STREAM_HEADER_BYTES
                && !self.buffered.windows(4).any(|bytes| bytes == b"\r\n\r\n")
            {
                return Err(LocalClientError::Io(
                    "capture response header too large".into(),
                ));
            }
        }
        Ok(())
    }
}

/// A streaming reader for `GET /localapi/v0/watch-ipn-bus`.
///
/// Created by
/// [`LocalClient::watch_ipn_bus`](super::LocalClient::watch_ipn_bus).
/// Call [`next`](Self::next) repeatedly to receive `Notify` messages until
/// the daemon closes the connection (returns `Ok(None)`) or an error occurs.
///
/// The first line(s) after the HTTP headers are the initial `Notify` message
/// (if `NotifyInitialState`/`NotifyInitialPrefs`/`NotifyInitialStatus` bits
/// are set in the mask). Subsequent lines are state-change notifications.
pub struct WatchIpnBus {
    stream: Connection,
    /// Buffered bytes read from the socket that haven't been split into
    /// complete lines yet.
    buf: Vec<u8>,
    /// Decoded complete lines waiting to be handed to `next()`.
    pending: VecDeque<Notify>,
    /// Whether we've consumed the HTTP response header yet.
    header_consumed: bool,
    /// Whether the stream has hit EOF (daemon closed the connection).
    eof: bool,
}

impl WatchIpnBus {
    pub(super) fn new(stream: Connection) -> Self {
        Self {
            stream,
            buf: Vec::with_capacity(8192),
            pending: VecDeque::new(),
            header_consumed: false,
            eof: false,
        }
    }

    /// Receive the next `Notify` message. Returns `Ok(None)` when the
    /// daemon has closed the connection (graceful shutdown).
    ///
    /// A malformed HTTP response or JSON frame is returned as an error. Frames
    /// are never silently skipped: doing so could hide the state transition a
    /// caller is waiting for.
    pub async fn next(&mut self) -> Result<Option<Notify>, LocalClientError> {
        // Return any pending decoded messages first.
        if let Some(n) = self.pending.pop_front() {
            return Ok(Some(n));
        }

        loop {
            // Try to extract complete lines from the buffer.
            if self.try_extract_lines()? {
                if let Some(n) = self.pending.pop_front() {
                    return Ok(Some(n));
                }
            }

            if self.eof {
                if !self.header_consumed {
                    return Err(LocalClientError::Io(
                        "watch stream closed before HTTP response".into(),
                    ));
                }
                if self.buf.is_empty() {
                    return Ok(None);
                }
                if self.buf.len() > MAX_NOTIFY_FRAME_BYTES {
                    return Err(LocalClientError::Io(
                        "watch notification frame too large".into(),
                    ));
                }
                let line = std::mem::take(&mut self.buf);
                return decode_notify(&line).map(Some);
            }

            // Read more data from the socket.
            let mut tmp = [0u8; 4096];
            let n = self
                .stream
                .read(&mut tmp)
                .await
                .map_err(|e| LocalClientError::Io(e.to_string()))?;
            if n == 0 {
                self.eof = true;
            } else {
                self.buf.extend_from_slice(&tmp[..n]);
            }
        }
    }

    /// Split the buffer into lines and decode them. The first time this is
    /// called, it also strips the HTTP response header (everything up to
    /// `\r\n\r\n`).
    ///
    /// Returns `true` if at least one complete line was extracted.
    fn try_extract_lines(&mut self) -> Result<bool, LocalClientError> {
        // Strip and validate the HTTP header on the first call.
        if !self.header_consumed {
            let Some(pos) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                if self.buf.len() > MAX_STREAM_HEADER_BYTES {
                    return Err(LocalClientError::Io(
                        "watch response header too large".into(),
                    ));
                }
                return Ok(false);
            };
            if pos + 4 > MAX_STREAM_HEADER_BYTES {
                return Err(LocalClientError::Io(
                    "watch response header too large".into(),
                ));
            }
            validate_watch_header(&self.buf[..pos])?;
            self.buf.drain(..pos + 4);
            self.header_consumed = true;
        }

        if self.buf.len() > MAX_NOTIFY_FRAME_BYTES && !self.buf.contains(&b'\n') {
            return Err(LocalClientError::Io(
                "watch notification frame too large".into(),
            ));
        }

        let mut found = false;
        loop {
            let Some(pos) = self.buf.iter().position(|&b| b == b'\n') else {
                break;
            };
            if pos > MAX_NOTIFY_FRAME_BYTES {
                return Err(LocalClientError::Io(
                    "watch notification frame too large".into(),
                ));
            }
            let mut line = self.buf.drain(..=pos).collect::<Vec<u8>>();
            line.pop(); // newline
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() {
                continue;
            }
            self.pending.push_back(decode_notify(&line)?);
            found = true;
        }
        Ok(found)
    }

    /// Close the connection gracefully.
    pub async fn close(&mut self) -> Result<(), LocalClientError> {
        use tokio::io::AsyncWriteExt;
        self.stream
            .shutdown()
            .await
            .map_err(|e| LocalClientError::Io(e.to_string()))
    }
}

fn validate_watch_header(header: &[u8]) -> Result<(), LocalClientError> {
    let text = std::str::from_utf8(header)
        .map_err(|_| LocalClientError::Io("non-UTF-8 watch response header".into()))?;
    let status_line = text
        .split("\r\n")
        .next()
        .ok_or_else(|| LocalClientError::Io("missing watch response status".into()))?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| LocalClientError::Io("invalid watch response status".into()))?;
    if !version.starts_with("HTTP/1.") {
        return Err(LocalClientError::Io(
            "invalid watch response HTTP version".into(),
        ));
    }
    if !(200..300).contains(&status) {
        // Do not reflect a LocalAPI response body. Besides keeping error
        // handling bounded, this prevents accidental disclosure if a daemon
        // includes sensitive details in an error response.
        if status == 403 {
            return Err(LocalClientError::AccessDenied(
                "watch-ipn-bus request denied".into(),
            ));
        }
        return Err(LocalClientError::HttpStatus {
            status,
            message: "watch-ipn-bus request failed".into(),
        });
    }
    Ok(())
}

fn decode_notify(line: &[u8]) -> Result<Notify, LocalClientError> {
    serde_json::from_slice(line)
        .map_err(|error| LocalClientError::Json(format!("invalid watch notification: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_header_requires_successful_http_status() {
        validate_watch_header(b"HTTP/1.1 200 OK\r\nContent-Type: application/json").unwrap();
        assert!(matches!(
            validate_watch_header(b"HTTP/1.1 403 Forbidden"),
            Err(LocalClientError::AccessDenied(_))
        ));
        assert!(validate_watch_header(b"not HTTP").is_err());
    }

    #[test]
    fn notify_decoder_rejects_malformed_and_invalid_states() {
        assert!(decode_notify(br#"{"State":6}"#).is_ok());
        assert!(decode_notify(b"not-json").is_err());
        assert!(decode_notify(br#"{"State":99}"#).is_err());
    }
}
