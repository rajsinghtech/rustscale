//! Bounded streaming transports for tsrecorder nodes.
//!
//! Recorder addresses come from the matched SSH policy. The injected dialer
//! must route them over the authenticated tailnet; this module never resolves
//! names or falls back to the host network. A different recorder is attempted
//! only before a recording writer is returned, so bytes are never replayed.

use bytes::Bytes;
use h2::client;
use http::{Method, Request, StatusCode};
use rustscale_tailcfg::SSHRecordingAttempt;
use std::future::Future;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot, watch};

const PER_DIAL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const H2_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const ALL_DIAL_ATTEMPTS_TIMEOUT: Duration = Duration::from_secs(30);
const FINAL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const UPLOAD_QUEUE_FRAMES: usize = 64;
const MAX_HTTP_LINE: usize = 8 * 1024;
const MAX_HTTP_HEADERS: usize = 64 * 1024;
const MAX_ACK_BUFFER: usize = 64 * 1024;
#[cfg(not(test))]
const ACK_WINDOW: Duration = Duration::from_secs(30);
#[cfg(test)]
const ACK_WINDOW: Duration = Duration::from_secs(1);

pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for T {}
pub type BoxedIo = Box<dyn AsyncIo>;
pub type DialFuture = Pin<Box<dyn Future<Output = io::Result<BoxedIo>> + Send>>;
/// Injectable authenticated tailnet transport.
pub type DialFn = Arc<dyn Fn(SocketAddr) -> DialFuture + Send + Sync>;

/// Handle used to abort an upload that did not drain before session teardown.
#[derive(Clone)]
pub struct UploadAbort {
    cancel: watch::Sender<bool>,
}

impl UploadAbort {
    pub fn abort(&self) {
        self.cancel.send_replace(true);
    }

    #[cfg(test)]
    pub(crate) fn test_handle() -> Self {
        let (cancel, _) = watch::channel(false);
        Self { cancel }
    }

    #[cfg(test)]
    pub(crate) fn is_aborted(&self) -> bool {
        *self.cancel.borrow()
    }
}

pub struct RecordingConnection {
    pub writer: Box<dyn Write + Send>,
    pub result_rx: oneshot::Receiver<io::Result<()>>,
    pub attempts: Vec<SSHRecordingAttempt>,
    pub abort: UploadAbort,
}

struct ChannelWriter {
    tx: Option<mpsc::Sender<Vec<u8>>>,
    cancel: watch::Receiver<bool>,
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if *self.cancel.borrow() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "recorder upload closed",
            ));
        }
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "recorder stream closed"))?;
        tx.try_send(buf.to_vec()).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => {
                io::Error::new(io::ErrorKind::WouldBlock, "recorder upload queue is full")
            }
            mpsc::error::TrySendError::Closed(_) => {
                io::Error::new(io::ErrorKind::BrokenPipe, "recorder upload closed")
            }
        })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if *self.cancel.borrow() {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "recorder upload closed",
            ))
        } else {
            Ok(())
        }
    }
}

impl Drop for ChannelWriter {
    fn drop(&mut self) {
        self.tx.take();
    }
}

/// Connect to recorders in policy order, using h2c V2 when supported and
/// falling back to the legacy HTTP/1.1 protocol otherwise.
///
/// Retries stop as soon as a writer is returned. Upload failures are reported
/// through `result_rx` and are never retried, preventing duplicated or
/// reordered recording bytes.
pub async fn connect_to_recorder(
    recorders: &[SocketAddr],
    dial: DialFn,
) -> Result<RecordingConnection, (Vec<SSHRecordingAttempt>, io::Error)> {
    if recorders.is_empty() {
        return Err((Vec::new(), io::Error::other("no recorder addresses")));
    }

    let deadline = tokio::time::Instant::now() + ALL_DIAL_ATTEMPTS_TIMEOUT;
    let mut attempts = Vec::new();
    for &recorder in recorders {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        match tokio::time::timeout_at(deadline, connect_one(recorder, dial.clone())).await {
            Ok(Ok((writer, result_rx, abort))) => {
                attempts.push(SSHRecordingAttempt {
                    Recorder: recorder,
                    FailureMessage: String::new(),
                });
                return Ok(RecordingConnection {
                    writer,
                    result_rx,
                    attempts,
                    abort,
                });
            }
            Ok(Err(error)) => attempts.push(SSHRecordingAttempt {
                Recorder: recorder,
                FailureMessage: error.to_string(),
            }),
            Err(_) => attempts.push(SSHRecordingAttempt {
                Recorder: recorder,
                FailureMessage: "recorder connection timed out".into(),
            }),
        }
    }

    let message = if attempts.is_empty() {
        "no recorder addresses were attempted".to_string()
    } else {
        attempts
            .iter()
            .map(|attempt| format!("{}: {}", attempt.Recorder, attempt.FailureMessage))
            .collect::<Vec<_>>()
            .join("; ")
    };
    Err((attempts, io::Error::other(message)))
}

async fn connect_one(
    recorder: SocketAddr,
    dial: DialFn,
) -> io::Result<(
    Box<dyn Write + Send>,
    oneshot::Receiver<io::Result<()>>,
    UploadAbort,
)> {
    if supports_v2(recorder, &dial).await {
        connect_v2(recorder, &dial).await
    } else {
        connect_v1(recorder, &dial).await
    }
}

async fn dial_with_timeout(recorder: SocketAddr, dial: &DialFn) -> io::Result<BoxedIo> {
    tokio::time::timeout(PER_DIAL_ATTEMPT_TIMEOUT, dial(recorder))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "recorder dial timed out"))?
}

async fn supports_v2(recorder: SocketAddr, dial: &DialFn) -> bool {
    let probe = async {
        let stream = dial_with_timeout(recorder, dial).await?;
        let (mut sender, connection) = client::handshake(stream).await.map_err(h2_error)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .method(Method::HEAD)
            .uri(format!("http://{recorder}/v2/record"))
            .body(())
            .map_err(io::Error::other)?;
        let (response, _) = sender.send_request(request, true).map_err(h2_error)?;
        let response = response.await.map_err(h2_error)?;
        Ok::<bool, io::Error>(response.status() == StatusCode::OK)
    };
    tokio::time::timeout(H2_PROBE_TIMEOUT, probe)
        .await
        .unwrap_or(Ok(false))
        .unwrap_or(false)
}

async fn connect_v1(
    recorder: SocketAddr,
    dial: &DialFn,
) -> io::Result<(
    Box<dyn Write + Send>,
    oneshot::Receiver<io::Result<()>>,
    UploadAbort,
)> {
    let stream = dial_with_timeout(recorder, dial).await?;
    let (read, mut write) = tokio::io::split(stream);
    let request = format!(
        "POST /record HTTP/1.1\r\nHost: {recorder}\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    );
    write.write_all(request.as_bytes()).await?;
    write.flush().await?;

    let mut reader = BufReader::new(read);
    let status = read_http_status(&mut reader).await?;
    if status != 100 {
        return Err(io::Error::other(format!(
            "recorder rejected upload: HTTP {status}"
        )));
    }

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(UPLOAD_QUEUE_FRAMES);
    let (result_tx, result_rx) = oneshot::channel();
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let writer_cancel = cancel_rx.clone();
    let task_cancel = cancel_tx.clone();

    tokio::spawn(async move {
        let upload = async {
            while let Some(data) = rx.recv().await {
                write
                    .write_all(format!("{:X}\r\n", data.len()).as_bytes())
                    .await?;
                write.write_all(&data).await?;
                write.write_all(b"\r\n").await?;
            }
            write.write_all(b"0\r\n\r\n").await?;
            write.flush().await
        };
        let response = async {
            let status = read_http_status(&mut reader).await?;
            if (200..300).contains(&status) {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "recorder upload failed: HTTP {status}"
                )))
            }
        };
        tokio::pin!(upload);
        tokio::pin!(response);

        let mut upload_done = false;
        let mut response_deadline = None;
        let result = loop {
            tokio::select! {
                biased;
                upload_result = &mut upload, if !upload_done => {
                    match upload_result {
                        Ok(()) => {
                            upload_done = true;
                            response_deadline = Some(tokio::time::Instant::now() + FINAL_RESPONSE_TIMEOUT);
                        }
                        Err(error) => break Err(error),
                    }
                }
                response_result = &mut response => {
                    break match response_result {
                        Ok(()) if upload_done => Ok(()),
                        Ok(()) => Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "recorder returned a final response before upload drain",
                        )),
                        Err(error) => Err(error),
                    };
                }
                changed = cancel_rx.changed() => {
                    if changed.is_err() || *cancel_rx.borrow() {
                        break Err(io::Error::new(io::ErrorKind::Interrupted, "recorder upload aborted"));
                    }
                }
                () = wait_for_optional_deadline(response_deadline), if response_deadline.is_some() => {
                    break Err(io::Error::new(io::ErrorKind::TimedOut, "recorder final response timed out"));
                }
            }
        };
        task_cancel.send_replace(true);
        let _ = result_tx.send(result);
    });

    Ok((
        Box::new(ChannelWriter {
            tx: Some(tx),
            cancel: writer_cancel,
        }),
        result_rx,
        UploadAbort { cancel: cancel_tx },
    ))
}

async fn wait_for_optional_deadline(deadline: Option<tokio::time::Instant>) {
    if let Some(deadline) = deadline {
        tokio::time::sleep_until(deadline).await;
    } else {
        std::future::pending::<()>().await;
    }
}

async fn read_http_status<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<u16> {
    let line = read_bounded_line(reader, MAX_HTTP_LINE).await?;
    let line = std::str::from_utf8(&line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP response"))?;
    let mut parts = line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP response"))?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTP response version",
        ));
    }
    let status = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP response"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP status"))?;

    let mut header_bytes = 0;
    loop {
        let line = read_bounded_line(reader, MAX_HTTP_LINE).await?;
        header_bytes += line.len();
        if header_bytes > MAX_HTTP_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recorder HTTP headers too large",
            ));
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
    }
    Ok(status)
}

async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "recorder closed HTTP response",
            ));
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len() + take > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recorder HTTP line too large",
            ));
        }
        let complete = available[take - 1] == b'\n';
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if complete {
            return Ok(line);
        }
    }
}

async fn connect_v2(
    recorder: SocketAddr,
    dial: &DialFn,
) -> io::Result<(
    Box<dyn Write + Send>,
    oneshot::Receiver<io::Result<()>>,
    UploadAbort,
)> {
    let stream = dial_with_timeout(recorder, dial).await?;
    let (mut sender, connection) = client::handshake(stream).await.map_err(h2_error)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{recorder}/v2/record"))
        .body(())
        .map_err(io::Error::other)?;
    let (response, mut send_body) = sender.send_request(request, false).map_err(h2_error)?;
    // Like Go's HTTP/2 client, do not expose the writer until the recorder has
    // accepted the POST. No recording bytes have been supplied at this point,
    // so another policy recorder can still be tried safely on failure.
    let response = response.await.map_err(h2_error)?;
    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "recorder rejected upload: {}",
            response.status()
        )));
    }
    let mut ack_body = response.into_body();

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(UPLOAD_QUEUE_FRAMES);
    let (result_tx, result_rx) = oneshot::channel();
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let writer_cancel = cancel_rx.clone();
    let task_cancel = cancel_tx.clone();

    tokio::spawn(async move {
        let upload = async {
            while let Some(data) = rx.recv().await {
                send_h2_data(&mut send_body, Bytes::from(data)).await?;
            }
            send_body.send_data(Bytes::new(), true).map_err(h2_error)
        };
        tokio::pin!(upload);

        let mut upload_done = false;
        let mut ack_buffer = Vec::new();
        let mut ack_deadline = tokio::time::Instant::now() + ACK_WINDOW;
        let result = 'monitor: loop {
            tokio::select! {
                biased;
                upload_result = &mut upload, if !upload_done => {
                    match upload_result {
                        Ok(()) => upload_done = true,
                        Err(error) => break Err(error),
                    }
                }
                maybe_data = ack_body.data() => match maybe_data {
                    Some(Ok(data)) => {
                        let received = data.len();
                        if let Err(error) = ack_body.flow_control().release_capacity(received) {
                            break 'monitor Err(h2_error(error));
                        }
                        if ack_buffer.len() + received > MAX_ACK_BUFFER {
                            break Err(io::Error::new(io::ErrorKind::InvalidData, "recorder acknowledgement too large"));
                        }
                        ack_buffer.extend_from_slice(&data);
                        match drain_ack_frames(&mut ack_buffer) {
                            Ok(frames) => {
                                for frame in frames {
                                    if !frame.error.is_empty() {
                                        // Recorder-provided text is deliberately not
                                        // propagated into logs or user-facing errors.
                                        break 'monitor Err(io::Error::other("recorder reported an upload error"));
                                    }
                                    let _ = frame.ack;
                                    ack_deadline = tokio::time::Instant::now() + ACK_WINDOW;
                                }
                            }
                            Err(error) => break Err(error),
                        }
                    }
                    Some(Err(error)) => break Err(h2_error(error)),
                    None => {
                        if ack_buffer.iter().any(|byte| !byte.is_ascii_whitespace()) {
                            break Err(io::Error::new(io::ErrorKind::InvalidData, "truncated recorder acknowledgement"));
                        }
                        if upload_done {
                            break Ok(());
                        }
                        break Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "recorder closed acknowledgements before upload drain",
                        ));
                    }
                },
                changed = cancel_rx.changed() => {
                    if changed.is_err() || *cancel_rx.borrow() {
                        break Err(io::Error::new(io::ErrorKind::Interrupted, "recorder upload aborted"));
                    }
                }
                () = tokio::time::sleep_until(ack_deadline) => {
                    break Err(io::Error::new(io::ErrorKind::TimedOut, "no acknowledgements from recorder"));
                }
            }
        };
        task_cancel.send_replace(true);
        let _ = result_tx.send(result);
    });

    Ok((
        Box::new(ChannelWriter {
            tx: Some(tx),
            cancel: writer_cancel,
        }),
        result_rx,
        UploadAbort { cancel: cancel_tx },
    ))
}

async fn send_h2_data(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "recorder upload closed"))?
            .map_err(h2_error)?;
        if capacity == 0 {
            continue;
        }
        let count = capacity.min(data.len());
        send.send_data(data.split_to(count), false)
            .map_err(h2_error)?;
    }
    Ok(())
}

#[derive(Default, serde::Deserialize)]
#[serde(default)]
struct AckFrame {
    ack: u64,
    error: String,
}

fn drain_ack_frames(buffer: &mut Vec<u8>) -> io::Result<Vec<AckFrame>> {
    let mut frames = Vec::new();
    let mut consumed = 0;
    loop {
        let mut stream =
            serde_json::Deserializer::from_slice(&buffer[consumed..]).into_iter::<AckFrame>();
        match stream.next() {
            Some(Ok(frame)) => {
                let used = stream.byte_offset();
                if used == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid recorder acknowledgement",
                    ));
                }
                consumed += used;
                frames.push(frame);
            }
            Some(Err(error)) if error.is_eof() => break,
            Some(Err(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid recorder acknowledgement",
                ));
            }
            None => {
                consumed = buffer.len();
                break;
            }
        }
    }
    if consumed > 0 {
        buffer.drain(..consumed);
    }
    Ok(frames)
}

fn h2_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recording::CastHeader;
    use crate::session_handler::init_recording;
    use h2::server;
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn addr(last: u8, port: u16) -> SocketAddr {
        format!("100.64.0.{last}:{port}").parse().unwrap()
    }

    fn duplex_dial(streams: Vec<tokio::io::DuplexStream>) -> DialFn {
        let streams = Arc::new(Mutex::new(VecDeque::from(streams)));
        Arc::new(move |_| {
            let stream = streams
                .lock()
                .map_err(|_| io::Error::other("dial stream lock poisoned"))
                .and_then(|mut streams| {
                    streams
                        .pop_front()
                        .ok_or_else(|| io::Error::other("no mock dial stream"))
                });
            Box::pin(async move { stream.map(|stream| Box::new(stream) as BoxedIo) })
        })
    }

    fn header() -> CastHeader {
        CastHeader::new(
            (80, 24),
            String::new(),
            HashMap::new(),
            "alice".into(),
            "root".into(),
            "id".into(),
        )
    }

    #[tokio::test]
    async fn v1_recorder_accepts_exact_chunked_stream() {
        let (client, stream) = tokio::io::duplex(2 * 1024 * 1024);
        let server = tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);
            let mut headers = Vec::new();
            loop {
                let mut line = Vec::new();
                read.read_until(b'\n', &mut line).await.unwrap();
                headers.extend_from_slice(&line);
                if line == b"\r\n" {
                    break;
                }
            }
            let headers = String::from_utf8(headers).unwrap();
            assert!(headers.starts_with("POST /record HTTP/1.1\r\n"));
            assert!(headers.contains("Host: 100.64.0.1:80\r\n"));
            assert!(headers.contains("Expect: 100-continue\r\n"));
            assert!(headers.contains("Transfer-Encoding: chunked\r\n"));
            write
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .unwrap();
            let mut received = Vec::new();
            loop {
                let mut line = String::new();
                read.read_line(&mut line).await.unwrap();
                let length = usize::from_str_radix(line.trim(), 16).unwrap();
                if length == 0 {
                    break;
                }
                let mut data = vec![0; length];
                read.read_exact(&mut data).await.unwrap();
                received.extend_from_slice(&data);
                let mut crlf = [0; 2];
                read.read_exact(&mut crlf).await.unwrap();
                assert_eq!(&crlf, b"\r\n");
            }
            write
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            received
        });
        let (mut writer, result_rx, _) = connect_v1(addr(1, 80), &duplex_dial(vec![client]))
            .await
            .unwrap();
        let payload = vec![b'x'; 1024 * 1024];
        for chunk in payload.chunks(16 * 1024) {
            loop {
                match writer.write_all(chunk) {
                    Ok(()) => break,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("unexpected upload error: {error}"),
                }
            }
        }
        drop(writer);
        result_rx.await.unwrap().unwrap();
        assert_eq!(server.await.unwrap(), payload);
    }

    #[tokio::test]
    async fn v1_early_success_before_queued_frames_drain_is_failure() {
        let (client, stream) = tokio::io::duplex(512);
        let (respond_tx, respond_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);
            loop {
                let mut line = String::new();
                read.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            write
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .unwrap();
            let _ = respond_rx.await;
            write
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let (mut writer, result_rx, _) = connect_v1(addr(20, 80), &duplex_dial(vec![client]))
            .await
            .unwrap();
        for _ in 0..32 {
            writer.write_all(&[b'z'; 128]).unwrap();
        }
        respond_tx.send(()).unwrap();
        let error = result_rx.await.unwrap().unwrap_err();
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe
            ),
            "{error}"
        );
    }

    #[tokio::test]
    async fn v2_recorder_accepts_stream_and_exact_path() {
        let (client, stream) = tokio::io::duplex(2 * 1024 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = server::handshake(stream).await.unwrap();
            let (received_tx, received_rx) = oneshot::channel();
            let mut received_tx = Some(received_tx);
            while let Some(request) = connection.accept().await {
                let (request, mut respond) = request.unwrap();
                let Some(received_tx) = received_tx.take() else {
                    continue;
                };
                tokio::spawn(async move {
                    assert_eq!(request.method(), Method::POST);
                    assert_eq!(request.uri().path(), "/v2/record");
                    assert_eq!(request.uri().authority().unwrap().as_str(), "100.64.0.2:80");
                    let mut body = request.into_body();
                    let mut send = respond
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    let mut received = Vec::new();
                    while let Some(data) = body.data().await {
                        let data = data.unwrap();
                        body.flow_control().release_capacity(data.len()).unwrap();
                        received.extend_from_slice(&data);
                        send.send_data(
                            Bytes::from(format!("{{\"ack\":{}}}", received.len())),
                            false,
                        )
                        .unwrap();
                    }
                    send.send_data(Bytes::new(), true).unwrap();
                    let _ = received_tx.send(received);
                });
            }
            received_rx.await.unwrap()
        });
        let (mut writer, result_rx, _) = connect_v2(addr(2, 80), &duplex_dial(vec![client]))
            .await
            .unwrap();
        let payload = vec![b'y'; 1024 * 1024];
        writer.write_all(&payload).unwrap();
        drop(writer);
        result_rx.await.unwrap().unwrap();
        assert_eq!(server.await.unwrap(), payload);
    }

    #[tokio::test]
    async fn v2_early_ack_eof_before_queued_frames_drain_is_failure() {
        let (client, stream) = tokio::io::duplex(2 * 1024 * 1024);
        let (close_tx, close_rx) = oneshot::channel();
        tokio::spawn(async move {
            let mut connection = server::handshake(stream).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            tokio::spawn(async move {
                let _body = request.into_body();
                let mut send = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let _ = close_rx.await;
                send.send_data(Bytes::new(), true).unwrap();
            });
            while connection.accept().await.is_some() {}
        });

        let (mut writer, result_rx, _) = connect_v2(addr(21, 80), &duplex_dial(vec![client]))
            .await
            .unwrap();
        let frame = [b'q'; 16 * 1024];
        let mut queued = 0;
        while queued < 8 {
            match writer.write_all(&frame) {
                Ok(()) => queued += 1,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("unexpected upload error: {error}"),
            }
        }
        close_tx.send(()).unwrap();
        let error = result_rx.await.unwrap().unwrap_err();
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe
            ),
            "{error}"
        );
    }

    #[tokio::test]
    async fn v2_recorder_no_acks_times_out() {
        let (client, stream) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut connection = server::handshake(stream).await.unwrap();
            while let Some(request) = connection.accept().await {
                let (request, mut respond) = request.unwrap();
                tokio::spawn(async move {
                    let _body = request.into_body();
                    let _send = respond
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    tokio::time::sleep(ACK_WINDOW * 3).await;
                });
            }
        });
        let (mut writer, result_rx, _) = connect_v2(addr(3, 80), &duplex_dial(vec![client]))
            .await
            .unwrap();
        writer.write_all(b"test").unwrap();
        let error = result_rx.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("no acknowledgements"), "{error}");
    }

    #[tokio::test]
    async fn bounded_queue_applies_backpressure() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(1);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let mut writer = ChannelWriter {
            tx: Some(tx),
            cancel: cancel_rx,
        };
        writer.write_all(b"one").unwrap();
        let error = writer.write_all(b"two").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        cancel_tx.send_replace(true);
        assert_eq!(
            writer.flush().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[tokio::test]
    async fn connect_to_recorder_tries_addresses_only_before_streaming() {
        let (probe, probe_server) = tokio::io::duplex(64 * 1024);
        let (client, stream) = tokio::io::duplex(64 * 1024);
        drop(probe_server);
        tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);
            let mut line = String::new();
            loop {
                line.clear();
                read.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            write
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .unwrap();
            loop {
                line.clear();
                read.read_line(&mut line).await.unwrap();
                let length = usize::from_str_radix(line.trim(), 16).unwrap();
                if length == 0 {
                    break;
                }
                let mut data = vec![0; length + 2];
                read.read_exact(&mut data).await.unwrap();
            }
            write
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let good = addr(5, 80);
        let bad = addr(4, 1);
        let good_dial = duplex_dial(vec![probe, client]);
        let dial: DialFn = Arc::new(move |recorder| {
            if recorder == bad {
                return Box::pin(async { Err(io::Error::other("unreachable recorder")) });
            }
            good_dial(recorder)
        });
        let mut connection = connect_to_recorder(&[bad, good], dial).await.unwrap();
        assert_eq!(connection.attempts.len(), 2);
        connection.writer.write_all(b"test").unwrap();
        drop(connection.writer);
        connection.result_rx.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn disconnect_after_stream_start_is_never_retried() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (probe, probe_server) = tokio::io::duplex(64 * 1024);
        drop(probe_server);
        let (upload, upload_server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(upload_server);
            let mut read = BufReader::new(read);
            loop {
                let mut line = String::new();
                read.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            write
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .unwrap();
            let mut length = String::new();
            read.read_line(&mut length).await.unwrap();
            let length = usize::from_str_radix(length.trim(), 16).unwrap();
            let mut first_chunk = vec![0; length + 2];
            read.read_exact(&mut first_chunk).await.unwrap();
            // Dropping both halves simulates a recorder disconnect after it
            // may have consumed recording bytes.
        });

        let streams = Arc::new(Mutex::new(VecDeque::from([probe, upload])));
        let dials = Arc::new(AtomicUsize::new(0));
        let dial: DialFn = {
            let streams = streams.clone();
            let dials = dials.clone();
            Arc::new(move |_| {
                dials.fetch_add(1, Ordering::SeqCst);
                let stream = streams
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or_else(|| io::Error::other("unexpected retry"));
                Box::pin(async move { stream.map(|stream| Box::new(stream) as BoxedIo) })
            })
        };

        let first = addr(10, 80);
        let second = addr(11, 80);
        let mut connection = connect_to_recorder(&[first, second], dial).await.unwrap();
        connection.writer.write_all(b"recording bytes").unwrap();
        let result = connection.result_rx.await.unwrap();
        assert!(result.is_err());
        assert_eq!(dials.load(Ordering::SeqCst), 2);
        assert_eq!(connection.attempts.len(), 1);
    }

    #[tokio::test]
    async fn connect_to_recorder_all_fail() {
        match connect_to_recorder(&[addr(6, 1), addr(7, 2)], duplex_dial(vec![])).await {
            Err(error) => {
                assert_eq!(error.0.len(), 2);
                assert!(error.1.to_string().contains("no mock dial stream"));
            }
            Ok(_) => panic!("all recorders should fail"),
        }
    }

    #[tokio::test]
    async fn fail_open_and_fail_closed_on_connect_failure() {
        let config = crate::recording::RecordingConfig {
            recorders: vec![addr(8, 1)],
            fail_open: true,
            ..Default::default()
        };
        assert!(init_recording(&config, header(), Some(duplex_dial(vec![])))
            .await
            .unwrap()
            .is_none());
        let config = crate::recording::RecordingConfig {
            recorders: vec![addr(9, 1)],
            on_failure: Some(rustscale_tailcfg::SSHRecorderFailureAction {
                RejectSessionWithMessage: "no recorders".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        match init_recording(&config, header(), Some(duplex_dial(vec![]))).await {
            Err(message) => assert_eq!(message, "no recorders"),
            Ok(_) => panic!("expected recording failure to reject the session"),
        }
    }

    #[test]
    fn ack_decoder_accepts_unframed_json_stream() {
        let mut input = b"{\"ack\":1}{\"ack\":2}\n".to_vec();
        let frames = drain_ack_frames(&mut input).unwrap();
        assert_eq!(frames.len(), 2);
        assert!(input.is_empty());
    }
}
