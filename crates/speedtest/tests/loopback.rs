use std::time::Duration;

use rustscale_speedtest::{
    handle_connection, run, CancellationToken, Config, ConfigResponse, Direction, Server,
    SpeedtestError, MAX_CONTROL_FRAME_SIZE, MIN_DURATION, PROTOCOL_VERSION,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn read_line(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut line = Vec::new();
    loop {
        let byte = stream.read_u8().await.unwrap();
        line.push(byte);
        if byte == b'\n' {
            return line;
        }
    }
}

async fn write_config(stream: &mut (impl AsyncWrite + Unpin), direction: Direction) {
    let config = Config {
        version: PROTOCOL_VERSION,
        test_duration_ns: i64::try_from(MIN_DURATION.as_nanos()).unwrap(),
        direction,
    };
    let mut line = serde_json::to_vec(&config).unwrap();
    line.push(b'\n');
    stream.write_all(&line).await.unwrap();
}

async fn read_response(stream: &mut (impl AsyncRead + Unpin)) -> ConfigResponse {
    serde_json::from_slice(&read_line(stream).await).unwrap()
}

#[test]
fn upstream_control_vectors() {
    let config = Config {
        version: PROTOCOL_VERSION,
        test_duration_ns: 5_000_000_000,
        direction: Direction::Upload,
    };
    assert_eq!(
        serde_json::to_string(&config).unwrap(),
        r#"{"version":2,"time":5000000000,"direction":1}"#
    );
    assert_eq!(
        serde_json::to_string(&ConfigResponse::default()).unwrap(),
        "{}"
    );
}

#[tokio::test]
async fn invalid_local_duration_writes_nothing() {
    let (mut client, mut peer) = tokio::io::duplex(64);
    assert!(matches!(
        run(&mut client, Direction::Download, Duration::from_secs(1)).await,
        Err(SpeedtestError::InvalidDuration)
    ));
    client.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty());
}

#[tokio::test]
async fn bounded_server_queues_connections_isolates_errors_and_drains() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let cancellation = CancellationToken::new();
    let child_cancellation = cancellation.clone();
    let server_task = tokio::spawn(async move {
        Server::new(1)
            .unwrap()
            .serve(listener, child_cancellation)
            .await
    });

    // The first valid upload request makes the server reverse to Download and
    // block reading test data while retaining its sole concurrency permit.
    let mut first = TcpStream::connect(address).await.unwrap();
    write_config(&mut first, Direction::Upload).await;
    assert_eq!(read_response(&mut first).await, ConfigResponse::default());

    let mut second = TcpStream::connect(address).await.unwrap();
    write_config(&mut second, Direction::Upload).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(250), second.read_u8())
            .await
            .is_err(),
        "second connection was handshaken while the sole permit was held"
    );

    // Releasing the first worker admits and handshakes the queued connection.
    first.shutdown().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), read_response(&mut second))
            .await
            .unwrap(),
        ConfigResponse::default()
    );
    second.shutdown().await.unwrap();

    // A malformed worker returns an error response but does not terminate the
    // listener or consume its permit permanently.
    let mut malformed = TcpStream::connect(address).await.unwrap();
    malformed.write_all(b"not-json\n").await.unwrap();
    let malformed_response =
        tokio::time::timeout(Duration::from_secs(2), read_response(&mut malformed))
            .await
            .unwrap();
    assert!(malformed_response.error.is_some());
    drop(malformed);

    // A subsequent valid worker proves malformed-client isolation, then stays
    // blocked so shutdown must cancel and drain an active worker.
    let mut final_client = TcpStream::connect(address).await.unwrap();
    write_config(&mut final_client, Direction::Upload).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), read_response(&mut final_client))
            .await
            .unwrap(),
        ConfigResponse::default()
    );

    cancellation.cancel();
    let server_result = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("server cancellation did not drain workers")
        .unwrap();
    assert!(server_result.is_ok());

    let mut remaining = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        final_client.read_to_end(&mut remaining),
    )
    .await
    .expect("active worker stream remained open after cancellation")
    .unwrap();
    assert!(remaining.is_empty());
}

#[tokio::test]
async fn malformed_peer_is_connection_local() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move { handle_connection(&mut server).await });
    client
        .write_all(&vec![b'x'; MAX_CONTROL_FRAME_SIZE + 1])
        .await
        .unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(SpeedtestError::ControlFrameTooLarge { .. })
    ));
    let response = read_line(&mut client).await;
    let parsed: ConfigResponse = serde_json::from_slice(&response).unwrap();
    assert!(parsed.error.is_some());
}
