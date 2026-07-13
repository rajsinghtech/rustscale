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
    /// If a line cannot be parsed as JSON, it is skipped (with the error
    /// surfaced via `Err` so the caller can decide whether to continue).
    pub async fn next(&mut self) -> Result<Option<Notify>, LocalClientError> {
        // Return any pending decoded messages first.
        if let Some(n) = self.pending.pop_front() {
            return Ok(Some(n));
        }

        loop {
            // If we've hit EOF and have no more complete lines, we're done.
            if self.eof && self.buf.is_empty() {
                return Ok(None);
            }

            // Try to extract complete lines from the buffer.
            if self.try_extract_lines()? {
                if let Some(n) = self.pending.pop_front() {
                    return Ok(Some(n));
                }
            }

            if self.eof {
                // EOF with no complete lines remaining.
                return Ok(None);
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
        // Strip the HTTP header on the first call.
        if !self.header_consumed {
            let Some(pos) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                return Ok(false);
            };
            // Remove the header (including the \r\n\r\n separator).
            self.buf.drain(..pos + 4);
            self.header_consumed = true;
        }

        let mut found = false;
        loop {
            let Some(pos) = self.buf.iter().position(|&b| b == b'\n') else {
                break;
            };
            let line_bytes = self.buf.drain(..=pos).collect::<Vec<u8>>();
            // Trim trailing \r and \n.
            let line = line_bytes
                .iter()
                .copied()
                .filter(|&b| b != b'\r' && b != b'\n')
                .collect::<Vec<u8>>();
            if line.is_empty() {
                continue;
            }
            if let Ok(notify) = serde_json::from_slice::<Notify>(&line) {
                self.pending.push_back(notify);
                found = true;
            }
            // Skip unparseable lines (could be a partial or keepalive).
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
