use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream, ReadBuf,
};

use super::*;

struct PartialWriteStream {
    inner: DuplexStream,
    max_write: usize,
}

impl AsyncRead for PartialWriteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PartialWriteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let limit = buf.len().min(self.max_write);
        Pin::new(&mut self.inner).poll_write(cx, &buf[..limit])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn queued_connector(streams: Vec<BoxedStream>) -> Arc<dyn Connector> {
    let streams = Arc::new(Mutex::new(VecDeque::from(streams)));
    Arc::new(move || -> ConnectFuture {
        let streams = Arc::clone(&streams);
        Box::pin(async move {
            streams.lock().unwrap().pop_front().ok_or_else(|| {
                io::Error::new(io::ErrorKind::ConnectionRefused, "no fake stream available")
            })
        })
    })
}

async fn write_in_chunks(stream: &mut DuplexStream, response: &str) {
    for chunk in response.as_bytes().chunks(2) {
        stream.write_all(chunk).await.unwrap();
        tokio::task::yield_now().await;
    }
}

async fn expect_command(reader: &mut BufReader<DuplexStream>, expected: &str, response: &str) {
    let mut command = String::new();
    reader.read_line(&mut command).await.unwrap();
    assert_eq!(command, format!("{expected}\n"));
    write_in_chunks(reader.get_mut(), response).await;
}

#[tokio::test]
async fn protocol_and_route_commands_have_exact_wire_format() {
    let (client, mut server) = tokio::io::duplex(32);
    let server_task = tokio::spawn(async move {
        write_in_chunks(&mut server, "0001 BIRD 2.0.8 ready.\n").await;
        let mut server = BufReader::new(server);
        expect_command(
            &mut server,
            "enable tailscale",
            "0011-tailscale: enabled\n0000 \n",
        )
        .await;
        expect_command(
            &mut server,
            "enable tailscale",
            "0010-tailscale: already enabled\n0000 \n",
        )
        .await;
        expect_command(
            &mut server,
            "disable tailscale",
            "0009-tailscale: disabled\n0000 \n",
        )
        .await;
        expect_command(
            &mut server,
            "disable tailscale",
            "0008-tailscale: already disabled\n0000 \n",
        )
        .await;
        expect_command(
            &mut server,
            "add route 192.0.2.0/24 via 192.0.2.1",
            "0000 Route added\n",
        )
        .await;
        // A successful repeated add is accepted, making daemon-side idempotent
        // route configuration safe for callers.
        expect_command(
            &mut server,
            "add route 192.0.2.0/24 via 192.0.2.1",
            "0000 Route already present\n",
        )
        .await;
        expect_command(
            &mut server,
            "replace route 2001:db8:1::/64 via 2001:db8:1::1",
            "0000 Route replaced\n",
        )
        .await;
        expect_command(
            &mut server,
            "delete route 192.0.2.0/24",
            "0000 Route removed\n",
        )
        .await;
    });

    let client = PartialWriteStream {
        inner: client,
        max_write: 2,
    };
    let connector = queued_connector(vec![Box::new(client)]);
    let mut client = BirdClient::with_connector(connector, Duration::from_secs(1))
        .await
        .unwrap();

    client.enable_protocol("tailscale").await.unwrap();
    client.enable_protocol("tailscale").await.unwrap();
    client.disable_protocol("tailscale").await.unwrap();
    client.disable_protocol("tailscale").await.unwrap();

    let v4 = Route::new(
        "192.0.2.0/24".parse().unwrap(),
        "192.0.2.1".parse().unwrap(),
    )
    .unwrap();
    client.add_route(v4).await.unwrap();
    client.add_route(v4).await.unwrap();
    let v6 = Route::new(
        "2001:db8:1::/64".parse().unwrap(),
        "2001:db8:1::1".parse().unwrap(),
    )
    .unwrap();
    client.replace_route(v6).await.unwrap();
    client.remove_route(v4.prefix).await.unwrap();

    server_task.await.unwrap();
}

#[tokio::test]
async fn parses_multiline_and_abbreviated_response_lines() {
    let (client, mut server) = tokio::io::duplex(128);
    tokio::spawn(async move {
        server.write_all(b"0001 ready\n").await.unwrap();
        let mut server = BufReader::new(server);
        expect_command(
            &mut server,
            "show protocols",
            "1002-first\n same-code continuation\n1002-another\n0000 done\n",
        )
        .await;
    });
    let mut client = BirdClient::with_connector(
        queued_connector(vec![Box::new(client)]),
        Duration::from_secs(1),
    )
    .await
    .unwrap();

    let response = client.execute("show protocols").await.unwrap();
    assert_eq!(response.final_code().get(), 0);
    assert_eq!(response.lines().len(), 4);
    assert_eq!(response.lines()[1].code, None);
    assert_eq!(response.lines()[1].text, "same-code continuation");
    assert_eq!(
        response.raw(),
        "1002-first\n same-code continuation\n1002-another\n0000 done"
    );
}

#[tokio::test]
async fn reports_error_codes_even_before_success_terminator() {
    let (client, mut server) = tokio::io::duplex(128);
    tokio::spawn(async move {
        server.write_all(b"0001 ready\n").await.unwrap();
        let mut command = String::new();
        let mut server = BufReader::new(server);
        server.read_line(&mut command).await.unwrap();
        server
            .get_mut()
            .write_all(b"9001-syntax error\n0000 \n")
            .await
            .unwrap();
    });
    let mut client = BirdClient::with_connector(
        queued_connector(vec![Box::new(client)]),
        Duration::from_secs(1),
    )
    .await
    .unwrap();

    let error = client.enable_protocol("unknown").await.unwrap_err();
    assert!(matches!(
        error,
        Error::CommandRejected { code, .. } if code.get() == 9001
    ));
}

#[tokio::test]
async fn malformed_reply_disconnects_and_reconnect_consumes_new_greeting() {
    let (client_one, mut server_one) = tokio::io::duplex(128);
    let (client_two, mut server_two) = tokio::io::duplex(128);
    let first = tokio::spawn(async move {
        server_one.write_all(b"0001 first\n").await.unwrap();
        let mut command = String::new();
        let mut server_one = BufReader::new(server_one);
        server_one.read_line(&mut command).await.unwrap();
        server_one
            .get_mut()
            .write_all(b"00x0 malformed\n")
            .await
            .unwrap();
    });
    let second = tokio::spawn(async move {
        server_two.write_all(b"0001 second\n").await.unwrap();
        let mut server_two = BufReader::new(server_two);
        expect_command(
            &mut server_two,
            "enable tailscale",
            "0011 tailscale: enabled\n",
        )
        .await;
    });
    let mut client = BirdClient::with_connector(
        queued_connector(vec![Box::new(client_one), Box::new(client_two)]),
        Duration::from_secs(1),
    )
    .await
    .unwrap();

    assert!(matches!(
        client.execute("show status").await,
        Err(Error::MalformedResponse { .. })
    ));
    assert!(matches!(
        client.execute("show status").await,
        Err(Error::NotConnected)
    ));
    client.reconnect().await.unwrap();
    client.enable_protocol("tailscale").await.unwrap();
    first.await.unwrap();
    second.await.unwrap();
}

#[tokio::test]
async fn timeout_and_eof_are_typed_and_disconnect() {
    let (timeout_client, mut timeout_server) = tokio::io::duplex(128);
    let timeout_task = tokio::spawn(async move {
        timeout_server.write_all(b"0001 ready\n").await.unwrap();
        let mut command = String::new();
        let mut timeout_server = BufReader::new(timeout_server);
        timeout_server.read_line(&mut command).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let mut client = BirdClient::with_connector(
        queued_connector(vec![Box::new(timeout_client)]),
        Duration::from_millis(20),
    )
    .await
    .unwrap();
    assert!(matches!(
        client.execute("show status").await,
        Err(Error::Timeout {
            operation: "reading a BIRD response",
            ..
        })
    ));
    timeout_task.abort();

    let (eof_client, mut eof_server) = tokio::io::duplex(128);
    tokio::spawn(async move {
        eof_server.write_all(b"0001 ready\n").await.unwrap();
        let mut command = String::new();
        let mut eof_server = BufReader::new(eof_server);
        eof_server.read_line(&mut command).await.unwrap();
        eof_server
            .get_mut()
            .write_all(b"0011-partial\n")
            .await
            .unwrap();
    });
    let mut client = BirdClient::with_connector(
        queued_connector(vec![Box::new(eof_client)]),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(matches!(
        client.execute("show status").await,
        Err(Error::UnexpectedEof { partial }) if partial == "0011-partial"
    ));
}

#[test]
fn validates_and_formats_ip_prefixes() {
    let vectors = [
        ("0.0.0.0/0", IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        ("192.0.2.0/24", "192.0.2.0".parse().unwrap(), 24),
        ("2001:db8::/32", "2001:db8::".parse().unwrap(), 32),
        ("::/0", IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    ];
    for (wire, address, length) in vectors {
        let prefix: IpPrefix = wire.parse().unwrap();
        assert_eq!(prefix.addr(), address);
        assert_eq!(prefix.length(), length);
        assert_eq!(prefix.to_string(), wire);
    }

    assert!(matches!(
        "192.0.2.1/24".parse::<IpPrefix>(),
        Err(PrefixError::HostBitsSet(_))
    ));
    assert!(matches!(
        "2001:db8::/129".parse::<IpPrefix>(),
        Err(PrefixError::LengthOutOfRange { .. })
    ));
    assert!(matches!(
        "192.0.2.0".parse::<IpPrefix>(),
        Err(PrefixError::MissingLength)
    ));
    assert!(matches!(
        Route::new(
            "192.0.2.0/24".parse().unwrap(),
            "2001:db8::1".parse().unwrap()
        ),
        Err(Error::AddressFamilyMismatch { .. })
    ));
}

#[tokio::test]
async fn validates_command_and_protocol_before_writing() {
    let (client, mut server) = tokio::io::duplex(128);
    tokio::spawn(async move {
        server.write_all(b"0001 ready\n").await.unwrap();
        // Keep the stream alive while the client performs local validation.
        tokio::time::sleep(Duration::from_millis(100)).await;
    });
    let mut client = BirdClient::with_connector(
        queued_connector(vec![Box::new(client)]),
        Duration::from_secs(1),
    )
    .await
    .unwrap();

    assert!(matches!(
        client.enable_protocol("tailscale\ndisable all").await,
        Err(Error::InvalidProtocol(_))
    ));
    assert!(matches!(
        client.execute("show status\r\nquit").await,
        Err(Error::InvalidCommand)
    ));
    client.close().await.unwrap();
    client.close().await.unwrap();
}
