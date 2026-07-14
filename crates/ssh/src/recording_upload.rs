//! Streaming transports for tsrecorder nodes.

use bytes::Bytes;
use h2::client;
use http::{Method, Request, StatusCode};
use rustscale_tailcfg::SSHRecordingAttempt;
use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

const PER_DIAL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const H2_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const ALL_DIAL_ATTEMPTS_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(not(test))]
const ACK_WINDOW: Duration = Duration::from_secs(30);
#[cfg(test)]
const ACK_WINDOW: Duration = Duration::from_secs(1);

pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for T {}
pub type BoxedIo = Box<dyn AsyncIo>;
pub type DialFuture = Pin<Box<dyn Future<Output = io::Result<BoxedIo>> + Send>>;
pub type DialFn = Arc<dyn Fn(&str, u16) -> DialFuture + Send + Sync>;

pub struct RecordingConnection {
    pub writer: Box<dyn Write + Send>,
    pub result_rx: oneshot::Receiver<io::Result<()>>,
    pub attempts: Vec<SSHRecordingAttempt>,
}

struct ChannelWriter {
    tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "recorder stream closed"))?;
        tx.send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "recorder upload closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for ChannelWriter {
    fn drop(&mut self) {
        self.tx.take();
    }
}

/// Connect to recorders in order, using h2c V2 when supported and falling
/// back to the legacy HTTP/1.1 protocol otherwise.
pub async fn connect_to_recorder(
    recorders: &[String],
    dial: DialFn,
) -> Result<RecordingConnection, (Vec<SSHRecordingAttempt>, io::Error)> {
    let deadline = tokio::time::Instant::now() + ALL_DIAL_ATTEMPTS_TIMEOUT;
    let mut attempts = Vec::new();
    for recorder in recorders {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        let result = tokio::time::timeout_at(
            deadline,
            tokio::time::timeout(
                PER_DIAL_ATTEMPT_TIMEOUT,
                connect_one(recorder, dial.clone()),
            ),
        )
        .await;
        match result {
            Ok(Ok(Ok((writer, result_rx)))) => {
                attempts.push(SSHRecordingAttempt {
                    Recorder: recorder.clone(),
                    FailureMessage: String::new(),
                });
                return Ok(RecordingConnection {
                    writer,
                    result_rx,
                    attempts,
                });
            }
            Ok(Ok(Err(error))) => attempts.push(SSHRecordingAttempt {
                Recorder: recorder.clone(),
                FailureMessage: error.to_string(),
            }),
            Ok(Err(_)) | Err(_) => attempts.push(SSHRecordingAttempt {
                Recorder: recorder.clone(),
                FailureMessage: "recorder connection timed out".into(),
            }),
        }
    }
    let message = attempts
        .iter()
        .map(|attempt| format!("{}: {}", attempt.Recorder, attempt.FailureMessage))
        .collect::<Vec<_>>()
        .join("; ");
    Err((
        attempts,
        io::Error::other(if message.is_empty() {
            "no recorder addresses"
        } else {
            &message
        }),
    ))
}

async fn connect_one(
    recorder: &str,
    dial: DialFn,
) -> io::Result<(Box<dyn Write + Send>, oneshot::Receiver<io::Result<()>>)> {
    let (host, port) = split_recorder_addr(recorder)?;
    if supports_v2(host, port, &dial).await {
        connect_v2(host, port, &dial).await
    } else {
        connect_v1(host, port, &dial).await
    }
}

fn split_recorder_addr(addr: &str) -> io::Result<(&str, u16)> {
    let (host, port) = addr.rsplit_once(':').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "recorder address needs a port")
    })?;
    let host = host.trim_matches(['[', ']']);
    let port = port
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid recorder port"))?;
    Ok((host, port))
}

async fn supports_v2(host: &str, port: u16, dial: &DialFn) -> bool {
    let probe = async {
        let stream = dial(host, port).await?;
        let (mut sender, connection) = client::handshake(stream).await.map_err(h2_error)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .method(Method::HEAD)
            .uri("http://recorder/v2/record")
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
    host: &str,
    port: u16,
    dial: &DialFn,
) -> io::Result<(Box<dyn Write + Send>, oneshot::Receiver<io::Result<()>>)> {
    let stream = dial(host, port).await?;
    let (read, mut write) = tokio::io::split(stream);
    let request = format!(
        "POST /record HTTP/1.1\r\nHost: {host}:{port}\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
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
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (result_tx, result_rx) = oneshot::channel();
    tokio::spawn(async move {
        let result = async {
            while let Some(data) = rx.recv().await {
                write
                    .write_all(format!("{:X}\r\n", data.len()).as_bytes())
                    .await?;
                write.write_all(&data).await?;
                write.write_all(b"\r\n").await?;
            }
            write.write_all(b"0\r\n\r\n").await?;
            write.flush().await?;
            let status = read_http_status(&mut reader).await?;
            if !(200..300).contains(&status) {
                return Err(io::Error::other(format!(
                    "recorder upload failed: HTTP {status}"
                )));
            }
            Ok(())
        }
        .await;
        let _ = result_tx.send(result);
    });
    Ok((Box::new(ChannelWriter { tx: Some(tx) }), result_rx))
}

async fn read_http_status<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> io::Result<u16> {
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let status = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::other("invalid HTTP response"))?
        .parse()
        .map_err(|_| io::Error::other("invalid HTTP status"))?;
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 || line == "\r\n" {
            break;
        }
    }
    Ok(status)
}

async fn connect_v2(
    host: &str,
    port: u16,
    dial: &DialFn,
) -> io::Result<(Box<dyn Write + Send>, oneshot::Receiver<io::Result<()>>)> {
    let stream = dial(host, port).await?;
    let (mut sender, connection) = client::handshake(stream).await.map_err(h2_error)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://recorder/v2/record")
        .body(())
        .map_err(io::Error::other)?;
    let (response, mut send_body) = sender.send_request(request, false).map_err(h2_error)?;
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (result_tx, result_rx) = oneshot::channel();
    let (writer_done_tx, mut writer_done_rx) = oneshot::channel();
    tokio::spawn(async move {
        let result = async {
            while let Some(data) = rx.recv().await {
                send_body
                    .send_data(Bytes::from(data), false)
                    .map_err(h2_error)?;
            }
            send_body.send_data(Bytes::new(), true).map_err(h2_error)
        }
        .await;
        let _ = writer_done_tx.send(result);
    });
    tokio::spawn(async move {
        let result = async {
            let response = tokio::time::timeout(ACK_WINDOW, response)
                .await
                .map_err(|_| io::Error::other("no acks from recorder"))?
                .map_err(h2_error)?;
            if !response.status().is_success() {
                return Err(io::Error::other(format!("recorder rejected upload: {}", response.status())));
            }
            let mut ack_body = response.into_body();
            let mut ack_buffer = Vec::new();
            let mut writer_finished = false;
            let mut saw_ack = false;
            loop {
                tokio::select! {
                    maybe_data = ack_body.data() => match maybe_data {
                        Some(Ok(data)) => {
                            ack_buffer.extend_from_slice(&data);
                            while let Some(index) = ack_buffer.iter().position(|byte| *byte == b'\n') {
                                let frame: AckFrame = serde_json::from_slice(&ack_buffer[..index]).map_err(io::Error::other)?;
                                ack_buffer.drain(..=index);
                                if let Some(error) = frame.error { return Err(io::Error::other(error)); }
                                if frame.ack.is_none() { return Err(io::Error::other("invalid recorder ack")); }
                                saw_ack = true;
                            }
                        }
                        Some(Err(error)) => return Err(h2_error(error)),
                        None => {
                            if writer_finished || saw_ack { return Ok(()); }
                            return Err(io::Error::other("recorder closed acknowledgements"));
                        }
                    },
                    writer_result = &mut writer_done_rx, if !writer_finished => match writer_result {
                        Ok(Ok(())) => writer_finished = true,
                        Ok(Err(error)) => return Err(error),
                        Err(_) => return Err(io::Error::other("recorder upload writer stopped")),
                    },
                    () = tokio::time::sleep(ACK_WINDOW) => return Err(io::Error::other("no acks from recorder")),
                }
            }
        }.await;
        let _ = result_tx.send(result);
    });
    Ok((Box::new(ChannelWriter { tx: Some(tx) }), result_rx))
}

#[derive(serde::Deserialize)]
struct AckFrame {
    ack: Option<u64>,
    error: Option<String>,
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

    fn duplex_dial(streams: Vec<tokio::io::DuplexStream>) -> DialFn {
        let streams = Arc::new(Mutex::new(VecDeque::from(streams)));
        Arc::new(move |_, _| {
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

    #[test]
    fn cast_header_serializes_correctly() {
        let header = CastHeader::new(
            (80, 24),
            "ls".into(),
            HashMap::new(),
            "alice".into(),
            "root".into(),
            "id".into(),
        );
        let value = serde_json::to_value(header).unwrap();
        assert_eq!(value["version"], 2);
        assert_eq!(value["width"], 80);
        assert_eq!(value["command"], "ls");
        assert!(value.get("src_node_tags").is_none());
    }

    #[tokio::test]
    async fn v1_recorder_accepts_stream() {
        let (client, stream) = tokio::io::duplex(2 * 1024 * 1024);
        let server = tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(stream);
            let mut read = BufReader::new(read);
            let mut headers = Vec::new();
            read.read_until(b'\n', &mut headers).await.unwrap();
            assert!(String::from_utf8_lossy(&headers).starts_with("POST /record"));
            loop {
                headers.clear();
                read.read_until(b'\n', &mut headers).await.unwrap();
                if headers == b"\r\n" {
                    break;
                }
            }
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
            }
            write
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            received
        });
        let (mut writer, result_rx) = connect_v1("recorder", 80, &duplex_dial(vec![client]))
            .await
            .unwrap();
        let payload = vec![b'x'; 1024 * 1024];
        writer.write_all(&payload).unwrap();
        drop(writer);
        result_rx.await.unwrap().unwrap();
        assert_eq!(server.await.unwrap(), payload);
    }

    #[tokio::test]
    async fn v2_recorder_accepts_stream() {
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
                    let mut body = request.into_body();
                    let first = body.data().await.unwrap().unwrap();
                    let mut send = respond
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    send.send_data(Bytes::from_static(b"{\"ack\":1}\n"), false)
                        .unwrap();
                    let mut received = first.to_vec();
                    while let Some(data) = body.data().await {
                        received.extend_from_slice(&data.unwrap());
                    }
                    send.send_data(Bytes::new(), true).unwrap();
                    let _ = received_tx.send(received);
                });
            }
            received_rx.await.unwrap()
        });
        let (mut writer, result_rx) = connect_v2("recorder", 80, &duplex_dial(vec![client]))
            .await
            .unwrap();
        let payload = vec![b'y'; 1024];
        writer.write_all(&payload).unwrap();
        drop(writer);
        result_rx.await.unwrap().unwrap();
        assert_eq!(server.await.unwrap(), payload);
    }

    #[tokio::test]
    async fn v2_recorder_no_acks_times_out() {
        let (client, stream) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut connection = server::handshake(stream).await.unwrap();
            while let Some(request) = connection.accept().await {
                let (_request, mut respond) = request.unwrap();
                tokio::spawn(async move {
                    let _send = respond
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    tokio::time::sleep(ACK_WINDOW * 2).await;
                });
            }
        });
        let (mut writer, result_rx) = connect_v2("recorder", 80, &duplex_dial(vec![client]))
            .await
            .unwrap();
        writer.write_all(b"test").unwrap();
        let error = result_rx.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("no acks"), "{error}");
    }

    #[tokio::test]
    async fn connect_to_recorder_tries_all_addrs() {
        let (probe, probe_server) = tokio::io::duplex(64 * 1024);
        let (client, stream) = tokio::io::duplex(64 * 1024);
        // The first connection is the h2c probe (which this legacy recorder
        // rejects); the second is the V1 upload connection.
        tokio::spawn(async move {
            drop(probe_server);
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
        let good = "good:80".to_string();
        let good_dial = duplex_dial(vec![probe, client]);
        let dial: DialFn = Arc::new(move |host, port| {
            if host == "bad" {
                return Box::pin(async { Err(io::Error::other("unreachable recorder")) });
            }
            good_dial(host, port)
        });
        let mut connection = connect_to_recorder(&["bad:1".into(), good], dial)
            .await
            .unwrap();
        assert_eq!(connection.attempts.len(), 2);
        connection.writer.write_all(b"test").unwrap();
        drop(connection.writer);
        connection.result_rx.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connect_to_recorder_all_fail() {
        match connect_to_recorder(&["one:1".into(), "two:2".into()], duplex_dial(vec![])).await {
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
            recorders: vec!["127.0.0.1:1".into()],
            ..Default::default()
        };
        assert!(init_recording(&config, header(), Some(duplex_dial(vec![])))
            .await
            .unwrap()
            .is_none());
        let config = crate::recording::RecordingConfig {
            recorders: vec!["127.0.0.1:1".into()],
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
}
