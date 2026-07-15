use std::time::Duration;

use rustscale_speedtest::{
    handle_connection, run, Config, ConfigResponse, Direction, SpeedtestError,
    MAX_CONTROL_FRAME_SIZE, PROTOCOL_VERSION,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn read_line(stream: &mut tokio::io::DuplexStream) -> Vec<u8> {
    let mut line = Vec::new();
    loop {
        let byte = stream.read_u8().await.unwrap();
        line.push(byte);
        if byte == b'\n' {
            return line;
        }
    }
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
