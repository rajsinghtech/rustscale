//! Streaming reader for the `watch-ipn-bus` LocalAPI endpoint. The daemon
//! sends newline-delimited JSON [`Notify`](rustscale_ipn::Notify) messages
//! over a long-lived HTTP/1.1 connection (chunked or connection-close
//! delimited). This module provides [`WatchIpnBus`] which wraps the
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
const MAX_HTTP_CHUNK_BYTES: usize = MAX_NOTIFY_FRAME_BYTES;
const MAX_CHUNK_LINE_BYTES: usize = 1024;
const MAX_CHUNK_EXTENSION_BYTES: usize = 512;
const MAX_TRAILER_LINE_BYTES: usize = 8 * 1024;
const MAX_CHUNK_TRAILER_BYTES: usize = 64 * 1024;

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
/// Both HTTP/1.1 chunked responses (as emitted by upstream's `net/http`) and
/// connection-close-delimited responses are supported.
pub struct WatchIpnBus {
    stream: Connection,
    header_buf: Vec<u8>,
    body_buf: Vec<u8>,
    pending: VecDeque<Notify>,
    body_decoder: Option<WatchBodyDecoder>,
    eof: bool,
    body_complete: bool,
}

impl WatchIpnBus {
    pub(super) fn new(stream: Connection) -> Self {
        Self {
            stream,
            header_buf: Vec::with_capacity(8192),
            body_buf: Vec::with_capacity(8192),
            pending: VecDeque::new(),
            body_decoder: None,
            eof: false,
            body_complete: false,
        }
    }

    /// Receive the next `Notify` message. Returns `Ok(None)` when the HTTP
    /// response body ends cleanly.
    ///
    /// Malformed HTTP framing or JSON is returned as an error. Frames are
    /// never silently skipped because that could hide a state transition.
    pub async fn next(&mut self) -> Result<Option<Notify>, LocalClientError> {
        if let Some(notify) = self.pending.pop_front() {
            return Ok(Some(notify));
        }

        loop {
            self.extract_frames()?;
            if let Some(notify) = self.pending.pop_front() {
                return Ok(Some(notify));
            }

            if self.body_complete {
                if self.body_buf.is_empty() {
                    return Ok(None);
                }
                if self.body_buf.len() > MAX_NOTIFY_FRAME_BYTES {
                    return Err(LocalClientError::Io(
                        "watch notification frame too large".into(),
                    ));
                }
                let frame = std::mem::take(&mut self.body_buf);
                return decode_notify(&frame).map(Some);
            }

            if self.eof {
                let decoder = self.body_decoder.as_mut().ok_or_else(|| {
                    LocalClientError::Io("watch stream closed before HTTP response".into())
                })?;
                let decoded = decoder.finish()?;
                self.body_buf.extend_from_slice(&decoded);
                self.body_complete = true;
                continue;
            }

            let mut bytes = [0u8; 4096];
            let count = self
                .stream
                .read(&mut bytes)
                .await
                .map_err(|error| LocalClientError::Io(error.to_string()))?;
            if count == 0 {
                self.eof = true;
            } else {
                self.ingest(&bytes[..count])?;
            }
        }
    }

    fn ingest(&mut self, bytes: &[u8]) -> Result<(), LocalClientError> {
        if self.body_decoder.is_none() {
            self.header_buf.extend_from_slice(bytes);
            let Some(header_end) = self
                .header_buf
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
            else {
                if self.header_buf.len() > MAX_STREAM_HEADER_BYTES {
                    return Err(LocalClientError::Io(
                        "watch response header too large".into(),
                    ));
                }
                return Ok(());
            };
            if header_end + 4 > MAX_STREAM_HEADER_BYTES {
                return Err(LocalClientError::Io(
                    "watch response header too large".into(),
                ));
            }

            let decoder = parse_watch_header(&self.header_buf[..header_end])?;
            let body = self.header_buf.split_off(header_end + 4);
            self.header_buf.clear();
            self.body_decoder = Some(decoder);
            if !body.is_empty() {
                self.decode_body_bytes(&body)?;
            }
        } else {
            self.decode_body_bytes(bytes)?;
        }
        Ok(())
    }

    fn decode_body_bytes(&mut self, bytes: &[u8]) -> Result<(), LocalClientError> {
        let decoder = self.body_decoder.as_mut().expect("body decoder installed");
        let decoded = decoder.push(bytes)?;
        self.body_buf.extend_from_slice(&decoded);
        self.body_complete = decoder.is_complete();
        Ok(())
    }

    fn extract_frames(&mut self) -> Result<(), LocalClientError> {
        loop {
            let Some(newline) = self.body_buf.iter().position(|byte| *byte == b'\n') else {
                break;
            };
            if newline > MAX_NOTIFY_FRAME_BYTES {
                return Err(LocalClientError::Io(
                    "watch notification frame too large".into(),
                ));
            }
            let mut frame = self.body_buf.drain(..=newline).collect::<Vec<_>>();
            frame.pop();
            if frame.last() == Some(&b'\r') {
                frame.pop();
            }
            if !frame.is_empty() {
                self.pending.push_back(decode_notify(&frame)?);
            }
        }
        if self.body_buf.len() > MAX_NOTIFY_FRAME_BYTES {
            return Err(LocalClientError::Io(
                "watch notification frame too large".into(),
            ));
        }
        Ok(())
    }

    /// Close the connection gracefully.
    pub async fn close(&mut self) -> Result<(), LocalClientError> {
        use tokio::io::AsyncWriteExt;
        self.stream
            .shutdown()
            .await
            .map_err(|error| LocalClientError::Io(error.to_string()))
    }
}

#[derive(Debug)]
enum WatchBodyDecoder {
    CloseDelimited { finished: bool },
    Chunked(ChunkedDecoder),
}

impl WatchBodyDecoder {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, LocalClientError> {
        match self {
            Self::CloseDelimited { finished } => {
                if *finished {
                    return Err(http_framing_error("bytes after response body"));
                }
                Ok(bytes.to_vec())
            }
            Self::Chunked(decoder) => decoder.push(bytes),
        }
    }

    fn finish(&mut self) -> Result<Vec<u8>, LocalClientError> {
        match self {
            Self::CloseDelimited { finished } => {
                *finished = true;
                Ok(Vec::new())
            }
            Self::Chunked(decoder) => {
                decoder.finish()?;
                Ok(Vec::new())
            }
        }
    }

    fn is_complete(&self) -> bool {
        match self {
            Self::CloseDelimited { finished } => *finished,
            Self::Chunked(decoder) => decoder.is_complete(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChunkState {
    Size,
    Data(usize),
    DataCr,
    DataLf,
    Trailers,
    Done,
}

#[derive(Debug)]
struct ChunkedDecoder {
    state: ChunkState,
    line: Vec<u8>,
    trailer_bytes: usize,
}

impl ChunkedDecoder {
    fn new() -> Self {
        Self {
            state: ChunkState::Size,
            line: Vec::with_capacity(64),
            trailer_bytes: 0,
        }
    }

    fn push(&mut self, mut bytes: &[u8]) -> Result<Vec<u8>, LocalClientError> {
        let mut decoded = Vec::with_capacity(bytes.len());
        while !bytes.is_empty() {
            match self.state {
                ChunkState::Size => {
                    let byte = bytes[0];
                    bytes = &bytes[1..];
                    if let Some(line) = self.push_line_byte(byte, MAX_CHUNK_LINE_BYTES)? {
                        let size = parse_chunk_size(&line)?;
                        self.state = if size == 0 {
                            ChunkState::Trailers
                        } else {
                            ChunkState::Data(size)
                        };
                    }
                }
                ChunkState::Data(remaining) => {
                    let count = remaining.min(bytes.len());
                    decoded.extend_from_slice(&bytes[..count]);
                    bytes = &bytes[count..];
                    self.state = if count == remaining {
                        ChunkState::DataCr
                    } else {
                        ChunkState::Data(remaining - count)
                    };
                }
                ChunkState::DataCr => {
                    if bytes[0] != b'\r' {
                        return Err(http_framing_error("missing CR after chunk data"));
                    }
                    bytes = &bytes[1..];
                    self.state = ChunkState::DataLf;
                }
                ChunkState::DataLf => {
                    if bytes[0] != b'\n' {
                        return Err(http_framing_error("missing LF after chunk data"));
                    }
                    bytes = &bytes[1..];
                    self.state = ChunkState::Size;
                }
                ChunkState::Trailers => {
                    let byte = bytes[0];
                    bytes = &bytes[1..];
                    self.trailer_bytes = self
                        .trailer_bytes
                        .checked_add(1)
                        .ok_or_else(|| http_framing_error("chunk trailers too large"))?;
                    if self.trailer_bytes > MAX_CHUNK_TRAILER_BYTES {
                        return Err(http_framing_error("chunk trailers too large"));
                    }
                    if let Some(line) = self.push_line_byte(byte, MAX_TRAILER_LINE_BYTES)? {
                        if line.is_empty() {
                            self.state = ChunkState::Done;
                        } else {
                            validate_trailer(&line)?;
                        }
                    }
                }
                ChunkState::Done => {
                    return Err(http_framing_error("bytes after chunked response body"));
                }
            }
        }
        Ok(decoded)
    }

    fn push_line_byte(
        &mut self,
        byte: u8,
        limit: usize,
    ) -> Result<Option<Vec<u8>>, LocalClientError> {
        if self.line.last() == Some(&b'\r') && byte != b'\n' {
            return Err(http_framing_error("bare CR in chunk framing"));
        }
        self.line.push(byte);
        if self.line.len() > limit {
            return Err(http_framing_error("chunk framing line too large"));
        }
        if byte != b'\n' {
            return Ok(None);
        }
        if self.line.len() < 2 || self.line[self.line.len() - 2] != b'\r' {
            return Err(http_framing_error("bare LF in chunk framing"));
        }
        self.line.truncate(self.line.len() - 2);
        Ok(Some(std::mem::take(&mut self.line)))
    }

    fn finish(&self) -> Result<(), LocalClientError> {
        if self.state == ChunkState::Done {
            Ok(())
        } else {
            Err(http_framing_error("truncated chunked response body"))
        }
    }

    fn is_complete(&self) -> bool {
        self.state == ChunkState::Done
    }
}

fn parse_chunk_size(line: &[u8]) -> Result<usize, LocalClientError> {
    let (hex, extension) = line
        .iter()
        .position(|byte| *byte == b';')
        .map_or((line, None), |position| {
            (&line[..position], Some(&line[position + 1..]))
        });
    if hex.is_empty() || !hex.iter().all(u8::is_ascii_hexdigit) {
        return Err(http_framing_error("invalid chunk size"));
    }
    if let Some(extension) = extension {
        validate_chunk_extensions(extension)?;
    }

    let mut size = 0usize;
    for byte in hex {
        let digit = (*byte as char).to_digit(16).expect("hex digit") as usize;
        size = size
            .checked_mul(16)
            .and_then(|value| value.checked_add(digit))
            .ok_or_else(|| http_framing_error("chunk size overflow"))?;
        if size > MAX_HTTP_CHUNK_BYTES {
            return Err(http_framing_error("chunk too large"));
        }
    }
    Ok(size)
}

fn validate_chunk_extensions(extension: &[u8]) -> Result<(), LocalClientError> {
    // Extensions are ignored semantically, but their syntax is validated to
    // avoid accepting ambiguous framing. Bound the aggregate extension text
    // and support RFC token or quoted-string values without obs-text.
    if extension.is_empty() || extension.len() > MAX_CHUNK_EXTENSION_BYTES {
        return Err(http_framing_error("invalid chunk extension"));
    }

    let mut offset = 0;
    while offset < extension.len() {
        let name_start = offset;
        while offset < extension.len() && is_http_token(extension[offset]) {
            offset += 1;
        }
        if offset == name_start {
            return Err(http_framing_error("invalid chunk extension name"));
        }
        if offset < extension.len() && extension[offset] == b'=' {
            offset += 1;
            if offset == extension.len() {
                return Err(http_framing_error("missing chunk extension value"));
            }
            if extension[offset] == b'"' {
                offset += 1;
                let mut closed = false;
                while offset < extension.len() {
                    match extension[offset] {
                        b'"' => {
                            offset += 1;
                            closed = true;
                            break;
                        }
                        b'\\' => {
                            offset += 1;
                            if offset == extension.len()
                                || !(extension[offset] == b'\t'
                                    || (0x20..=0x7e).contains(&extension[offset]))
                            {
                                return Err(http_framing_error("invalid quoted chunk extension"));
                            }
                            offset += 1;
                        }
                        byte if byte == b'\t' || byte == b' ' || (0x21..=0x7e).contains(&byte) => {
                            offset += 1;
                        }
                        _ => return Err(http_framing_error("invalid quoted chunk extension")),
                    }
                }
                if !closed {
                    return Err(http_framing_error("unterminated chunk extension quote"));
                }
            } else {
                let value_start = offset;
                while offset < extension.len() && is_http_token(extension[offset]) {
                    offset += 1;
                }
                if offset == value_start {
                    return Err(http_framing_error("invalid chunk extension value"));
                }
            }
        }
        if offset == extension.len() {
            break;
        }
        if extension[offset] != b';' {
            return Err(http_framing_error("invalid chunk extension separator"));
        }
        offset += 1;
        if offset == extension.len() {
            return Err(http_framing_error("empty chunk extension"));
        }
    }
    Ok(())
}

fn validate_trailer(line: &[u8]) -> Result<(), LocalClientError> {
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return Err(http_framing_error("malformed chunk trailer"));
    };
    let name = &line[..colon];
    let value = &line[colon + 1..];
    if name.is_empty() || !name.iter().all(|byte| is_http_token(*byte)) {
        return Err(http_framing_error("malformed chunk trailer name"));
    }
    if !value
        .iter()
        .all(|byte| *byte == b'\t' || (0x20..=0x7e).contains(byte))
    {
        return Err(http_framing_error("malformed chunk trailer value"));
    }
    if name.eq_ignore_ascii_case(b"content-length")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
    {
        return Err(http_framing_error("forbidden chunk trailer"));
    }
    Ok(())
}

fn is_http_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn parse_watch_header(header: &[u8]) -> Result<WatchBodyDecoder, LocalClientError> {
    let text = std::str::from_utf8(header)
        .map_err(|_| LocalClientError::Io("non-UTF-8 watch response header".into()))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| LocalClientError::Io("missing watch response status".into()))?;
    if !status_line
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
    {
        return Err(http_framing_error("malformed watch response status"));
    }
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| LocalClientError::Io("invalid watch response status".into()))?;
    if version != "HTTP/1.1" {
        return Err(LocalClientError::Io(
            "watch response is not HTTP/1.1".into(),
        ));
    }
    if !(200..300).contains(&status) {
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

    let mut transfer_encoding = None;
    let mut has_content_length = false;
    for line in lines {
        if line.is_empty() || line.starts_with([' ', '\t']) {
            return Err(http_framing_error("malformed watch response header"));
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(http_framing_error("malformed watch response header"));
        };
        if name.is_empty() || !name.bytes().all(is_http_token) {
            return Err(http_framing_error("malformed watch response header name"));
        }
        if !value
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
        {
            return Err(http_framing_error("malformed watch response header value"));
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.replace(value.trim()).is_some() {
                return Err(http_framing_error("duplicate Transfer-Encoding"));
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
    }

    if let Some(encoding) = transfer_encoding {
        if has_content_length {
            return Err(http_framing_error(
                "both Transfer-Encoding and Content-Length present",
            ));
        }
        let encodings = encoding.split(',').map(str::trim).collect::<Vec<_>>();
        if encodings.len() != 1 || !encodings[0].eq_ignore_ascii_case("chunked") {
            return Err(http_framing_error("unsupported Transfer-Encoding"));
        }
        Ok(WatchBodyDecoder::Chunked(ChunkedDecoder::new()))
    } else if has_content_length {
        Err(http_framing_error(
            "Content-Length is not valid for a watch stream",
        ))
    } else {
        Ok(WatchBodyDecoder::CloseDelimited { finished: false })
    }
}

fn http_framing_error(message: &str) -> LocalClientError {
    LocalClientError::Io(format!("invalid watch HTTP framing: {message}"))
}

fn decode_notify(line: &[u8]) -> Result<Notify, LocalClientError> {
    serde_json::from_slice(line)
        .map_err(|error| LocalClientError::Json(format!("invalid watch notification: {error}")))
}
#[cfg(test)]
mod tests {
    use super::*;

    fn decode_chunk_fragments<'a>(fragments: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
        let mut decoder = ChunkedDecoder::new();
        let mut decoded = Vec::new();
        for fragment in fragments {
            decoded.extend(decoder.push(fragment).unwrap());
        }
        decoder.finish().unwrap();
        decoded
    }

    #[test]
    fn watch_header_selects_strict_chunked_or_close_framing() {
        assert!(matches!(
            parse_watch_header(b"HTTP/1.1 200 OK\r\nConnection: close").unwrap(),
            WatchBodyDecoder::CloseDelimited { .. }
        ));
        assert!(matches!(
            parse_watch_header(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive"
            )
            .unwrap(),
            WatchBodyDecoder::Chunked(_)
        ));
        assert!(matches!(
            parse_watch_header(b"HTTP/1.1 403 Forbidden"),
            Err(LocalClientError::AccessDenied(_))
        ));
        for header in [
            b"HTTP/1.0 200 OK".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1".as_slice(),
            b"HTTP/1.1 200 OK\r\n bad: folded".as_slice(),
            b"HTTP/1.1 200 OK\r\nX-Test: bad\0value".as_slice(),
        ] {
            assert!(parse_watch_header(header).is_err(), "accepted {header:?}");
        }
    }

    #[test]
    fn chunk_decoder_handles_every_byte_fragmented_with_extensions_and_trailers() {
        let wire = b"3;source=\"te;st\"\r\nhel\r\n3\r\nlo\n\r\n0\r\nX-Test: yes\r\n\r\n";
        assert_eq!(
            decode_chunk_fragments(wire.iter().map(std::slice::from_ref)),
            b"hello\n"
        );
    }

    #[test]
    fn chunk_decoder_handles_fragmented_size_data_and_crlf() {
        let fragments = [
            b"1".as_slice(),
            b"0\r".as_slice(),
            b"\n0123".as_slice(),
            b"456789ab".as_slice(),
            b"cdef\r".as_slice(),
            b"\n0\r\n".as_slice(),
            b"\r".as_slice(),
            b"\n".as_slice(),
        ];
        assert_eq!(decode_chunk_fragments(fragments), b"0123456789abcdef");
    }

    #[test]
    fn chunk_decoder_rejects_malformed_oversized_and_truncated_bodies() {
        for wire in [
            b"z\r\n".as_slice(),
            b"1000001\r\n".as_slice(),
            b"1\r\naX".as_slice(),
            b"0\n\n".as_slice(),
            b"0\r\nnot-a-trailer\r\n\r\n".as_slice(),
            b"0\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"0\r\n\r\nextra".as_slice(),
            b"1;;empty\r\n".as_slice(),
            b"1;name=\r\n".as_slice(),
            b"1;name=\"unterminated\r\n".as_slice(),
        ] {
            let mut decoder = ChunkedDecoder::new();
            assert!(decoder.push(wire).is_err(), "accepted {wire:?}");
        }

        let mut long_extension = b"1;".to_vec();
        long_extension.extend(std::iter::repeat_n(b'x', MAX_CHUNK_EXTENSION_BYTES + 1));
        long_extension.extend_from_slice(b"\r\n");
        assert!(ChunkedDecoder::new().push(&long_extension).is_err());

        let mut excessive_trailers = b"0\r\n".to_vec();
        while excessive_trailers.len() <= MAX_CHUNK_TRAILER_BYTES + 16 {
            excessive_trailers.extend_from_slice(b"X: value\r\n");
        }
        assert!(ChunkedDecoder::new().push(&excessive_trailers).is_err());

        for truncated in [
            b"1".as_slice(),
            b"1\r\n".as_slice(),
            b"1\r\na".as_slice(),
            b"1\r\na\r".as_slice(),
            b"0\r\n".as_slice(),
            b"0\r\nX: y\r\n".as_slice(),
        ] {
            let mut decoder = ChunkedDecoder::new();
            decoder.push(truncated).unwrap();
            assert!(
                decoder.finish().is_err(),
                "accepted truncation {truncated:?}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn watch_decodes_a_byte_fragmented_real_chunked_stream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chunked-watch.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            assert!(request.starts_with(b"GET /localapi/v0/watch-ipn-bus?mask=2 "));

            let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"Sta\r\n7;part=two\r\nte\":5}\n\r\n0\r\nTrailer-Test: done\r\n\r\n";
            for byte in response {
                stream.write_all(std::slice::from_ref(byte)).await.unwrap();
                tokio::task::yield_now().await;
            }
        });

        let mut watch = crate::LocalClient::new(&path)
            .watch_ipn_bus(rustscale_ipn::NOTIFY_INITIAL_STATE)
            .await
            .unwrap();
        let notify = watch.next().await.unwrap().unwrap();
        assert_eq!(notify.State, Some(rustscale_ipn::State::Starting));
        assert!(watch.next().await.unwrap().is_none());
        server.await.unwrap();
    }

    #[test]
    fn notify_decoder_rejects_malformed_and_invalid_states() {
        assert!(decode_notify(br#"{"State":6}"#).is_ok());
        assert!(decode_notify(b"not-json").is_err());
        assert!(decode_notify(br#"{"State":99}"#).is_err());
    }
}
