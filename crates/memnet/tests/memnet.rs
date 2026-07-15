use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};

use rustscale_memnet::{MemConn, MemListener, MemPipe, Network, NETWORK_NAME};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TEST_TIMEOUT: Duration = Duration::from_secs(2);

#[tokio::test]
async fn pipe_is_fifo_and_applies_byte_backpressure() {
    let pipe = Arc::new(MemPipe::new("bounded", 1));
    let writer_pipe = Arc::clone(&pipe);
    let writer = tokio::spawn(async move { writer_pipe.write(b"abc").await });

    tokio::task::yield_now().await;
    assert!(!writer.is_finished(), "write completed despite full buffer");

    let mut got = [0; 3];
    for byte in &mut got {
        let mut one = [0];
        assert_eq!(pipe.read(&mut one).await.unwrap(), 1);
        *byte = one[0];
    }
    assert_eq!(&got, b"abc");
    assert_eq!(writer.await.unwrap().unwrap(), 3);
}

#[tokio::test]
async fn pipe_close_drains_then_eof_and_wakes_writer() {
    let pipe = Arc::new(MemPipe::new("close", 2));
    assert_eq!(pipe.write(b"ok").await.unwrap(), 2);

    let writer_pipe = Arc::clone(&pipe);
    let blocked = tokio::spawn(async move { writer_pipe.write(b"blocked").await });
    tokio::task::yield_now().await;
    assert!(!blocked.is_finished());

    pipe.close();
    let error = blocked.await.unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::BrokenPipe);

    let mut output = [0; 8];
    assert_eq!(pipe.read(&mut output).await.unwrap(), 2);
    assert_eq!(&output[..2], b"ok");
    assert_eq!(pipe.read(&mut output).await.unwrap(), 0);
    assert_eq!(
        pipe.write(b"x").await.unwrap_err().kind(),
        ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn pipe_block_deadline_and_unblock_are_ordered() {
    let pipe = Arc::new(MemPipe::new("fault", 8));
    pipe.write(b"queued").await.unwrap();
    pipe.block().unwrap();
    assert_eq!(pipe.block().unwrap_err().kind(), ErrorKind::AlreadyExists);

    pipe.set_read_deadline(Some(Instant::now() + Duration::from_millis(25)));
    let mut output = [0; 8];
    assert_eq!(
        pipe.read(&mut output).await.unwrap_err().kind(),
        ErrorKind::TimedOut
    );

    pipe.set_read_deadline(None);
    pipe.unblock().unwrap();
    assert_eq!(pipe.unblock().unwrap_err().kind(), ErrorKind::InvalidInput);
    assert_eq!(pipe.read(&mut output).await.unwrap(), 6);
    assert_eq!(&output[..6], b"queued");

    pipe.close();
    assert_eq!(pipe.block().unwrap_err().kind(), ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn shared_pipe_wakes_all_concurrent_deadline_waiters() {
    let pipe = Arc::new(MemPipe::new("concurrent-deadline", 1));
    pipe.set_read_deadline(Some(Instant::now() + Duration::from_millis(25)));
    let mut readers = Vec::new();
    for _ in 0..8 {
        let pipe = Arc::clone(&pipe);
        readers.push(tokio::spawn(async move {
            let mut byte = [0];
            pipe.read(&mut byte).await
        }));
    }

    for reader in readers {
        let error = tokio::time::timeout(TEST_TIMEOUT, reader)
            .await
            .expect("a concurrent reader was not woken")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }
}

#[tokio::test]
async fn resetting_deadline_wakes_and_retimes_pending_operation() {
    let pipe = Arc::new(MemPipe::new("deadline", 1));
    let reader_pipe = Arc::clone(&pipe);
    pipe.set_read_deadline(Some(Instant::now() + Duration::from_secs(30)));
    let reader = tokio::spawn(async move {
        let mut byte = [0];
        reader_pipe.read(&mut byte).await
    });
    tokio::task::yield_now().await;

    pipe.set_read_deadline(Some(
        Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("one millisecond before now is representable"),
    ));
    let error = tokio::time::timeout(TEST_TIMEOUT, reader)
        .await
        .expect("deadline did not wake reader")
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TimedOut);
}

#[tokio::test]
async fn connection_addresses_and_bidirectional_order_match_upstream() {
    let (mut first, mut second) = MemConn::new_pair("noise", 16);
    assert_eq!(first.local_addr().as_str(), "noise|0");
    assert_eq!(first.remote_addr().as_str(), "noise|1");
    assert_eq!(second.local_addr(), first.remote_addr());
    assert_eq!(second.remote_addr(), first.local_addr());
    assert_eq!(first.local_addr().network(), NETWORK_NAME);

    let first_task = tokio::spawn(async move {
        first.write_all(b"first").await.unwrap();
        let mut response = [0; 6];
        first.read_exact(&mut response).await.unwrap();
        response
    });
    let second_task = tokio::spawn(async move {
        second.write_all(b"second").await.unwrap();
        let mut response = [0; 5];
        second.read_exact(&mut response).await.unwrap();
        response
    });
    assert_eq!(&first_task.await.unwrap(), b"second");
    assert_eq!(&second_task.await.unwrap(), b"first");
}

#[test]
fn tcp_pair_reports_real_endpoint_addresses() {
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), 1234);
    let destination = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
    let (first, second) = MemConn::new_tcp_pair(source, destination, 8);
    assert_eq!(first.local_addr().as_socket_addr(), Some(source));
    assert_eq!(first.remote_addr().as_socket_addr(), Some(destination));
    assert_eq!(first.local_addr().network(), "tcp");
    assert_eq!(second.local_addr().as_socket_addr(), Some(destination));
    assert_eq!(second.remote_addr().as_socket_addr(), Some(source));
}

#[tokio::test]
async fn connection_block_affects_peer_and_close_wakes_both_sides() {
    let (mut first, mut second) = MemConn::new_pair("blocked", 1);
    first.set_read_block(true).unwrap();

    let write = tokio::time::timeout(Duration::from_millis(20), second.write_all(b"x")).await;
    assert!(write.is_err(), "peer write ignored read-side block");

    first.set_read_block(false).unwrap();
    second.write_all(b"x").await.unwrap();
    let mut byte = [0];
    first.read_exact(&mut byte).await.unwrap();
    assert_eq!(&byte, b"x");

    first.set_write_block(true).unwrap();
    let pending_read = tokio::spawn(async move {
        let mut byte = [0];
        second.read(&mut byte).await
    });
    tokio::task::yield_now().await;
    first.close();
    assert_eq!(
        tokio::time::timeout(TEST_TIMEOUT, pending_read)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn connection_close_drains_bytes_and_shutdown_is_half_close() {
    let (mut first, mut second) = MemConn::new_pair("close", 8);
    first.write_all(b"bye").await.unwrap();
    first.shutdown().await.unwrap();

    let mut bytes = [0; 3];
    second.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"bye");
    assert_eq!(second.read(&mut [0]).await.unwrap(), 0);

    second.write_all(b"reply").await.unwrap();
    let mut reply = [0; 5];
    first.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"reply");

    first.close();
    assert_eq!(
        second.write_all(b"x").await.unwrap_err().kind(),
        ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn connection_read_and_write_deadlines_cover_block_and_backpressure() {
    let (mut first, mut second) = MemConn::new_pair("deadlines", 1);
    first.set_read_deadline(Some(Instant::now() + Duration::from_millis(25)));
    assert_eq!(
        first.read(&mut [0]).await.unwrap_err().kind(),
        ErrorKind::TimedOut
    );

    first.set_read_deadline(None);
    first.write_all(b"a").await.unwrap();
    first.set_write_deadline(Some(Instant::now() + Duration::from_millis(25)));
    assert_eq!(
        first.write_all(b"b").await.unwrap_err().kind(),
        ErrorKind::TimedOut
    );

    let mut byte = [0];
    second.read_exact(&mut byte).await.unwrap();
    assert_eq!(&byte, b"a");
}

#[tokio::test]
async fn dial_is_a_rendezvous_and_reports_connection_addresses() {
    let listener = Arc::new(MemListener::listen("srv.local:80"));
    let dialing = Arc::clone(&listener);
    let dial = tokio::spawn(async move { dialing.dial("tcp", "srv.local:80").await });
    tokio::task::yield_now().await;
    assert!(!dial.is_finished(), "dial completed before accept");

    let server = listener.accept().await.unwrap();
    let client = dial.await.unwrap().unwrap();
    assert_eq!(client.local_addr().as_str(), "srv.local:80|0");
    assert_eq!(server.local_addr().as_str(), "srv.local:80|1");
    assert_eq!(client.remote_addr(), server.local_addr());
}

#[tokio::test]
async fn canceled_dial_is_never_returned_by_accept() {
    let listener = Arc::new(MemListener::listen("cancel"));
    let first_listener = Arc::clone(&listener);
    let first = tokio::spawn(async move { first_listener.dial("tcp", "cancel").await });
    tokio::task::yield_now().await;
    first.abort();
    let _ = first.await;

    let accept_listener = Arc::clone(&listener);
    let accept = tokio::spawn(async move { accept_listener.accept().await });
    let second_listener = Arc::clone(&listener);
    let second = tokio::spawn(async move { second_listener.dial("tcp", "cancel").await });

    let server = tokio::time::timeout(TEST_TIMEOUT, accept)
        .await
        .expect("accept remained stuck on canceled dial")
        .unwrap()
        .unwrap();
    let _client = second.await.unwrap().unwrap();
    assert_eq!(server.local_addr().as_str(), "cancel|1");
}

#[tokio::test]
async fn listener_close_wakes_pending_accept_and_dial() {
    let accept_listener = Arc::new(MemListener::listen("accept-close"));
    let accepting = Arc::clone(&accept_listener);
    let accept = tokio::spawn(async move { accepting.accept().await });
    tokio::task::yield_now().await;
    accept_listener.close();
    assert_eq!(
        accept.await.unwrap().unwrap_err().kind(),
        ErrorKind::ConnectionAborted
    );

    let dial_listener = Arc::new(MemListener::listen("dial-close"));
    let dialing = Arc::clone(&dial_listener);
    let dial = tokio::spawn(async move { dialing.dial("tcp", "dial-close").await });
    tokio::task::yield_now().await;
    dial_listener.close();
    assert_eq!(
        dial.await.unwrap().unwrap_err().kind(),
        ErrorKind::ConnectionAborted
    );
    assert_eq!(
        dial_listener.accept().await.unwrap_err().kind(),
        ErrorKind::ConnectionAborted
    );
}

#[tokio::test]
async fn close_racing_many_dials_wakes_and_discards_every_connection() {
    let listener = Arc::new(MemListener::listen("close-race"));
    let mut dials = Vec::new();
    for _ in 0..128 {
        let listener = Arc::clone(&listener);
        dials.push(tokio::spawn(async move {
            listener.dial("tcp", "close-race").await
        }));
    }
    tokio::task::yield_now().await;
    listener.close();

    for dial in dials {
        let error = tokio::time::timeout(TEST_TIMEOUT, dial)
            .await
            .expect("dial leaked after listener close")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ConnectionAborted);
    }
    assert_eq!(
        listener.accept().await.unwrap_err().kind(),
        ErrorKind::ConnectionAborted
    );
}

#[tokio::test]
async fn concurrent_dials_are_accepted_in_enqueue_order() {
    let listener = Arc::new(MemListener::listen("ordered"));
    let mut dials = Vec::new();
    for id in 0_u8..8 {
        let listener = Arc::clone(&listener);
        dials.push(tokio::spawn(async move {
            let mut connection = listener.dial("tcp", "ordered").await.unwrap();
            connection.write_all(&[id]).await.unwrap();
        }));
        tokio::task::yield_now().await;
    }

    for expected in 0_u8..8 {
        let mut connection = listener.accept().await.unwrap();
        let mut id = [0];
        connection.read_exact(&mut id).await.unwrap();
        assert_eq!(id[0], expected);
    }
    for dial in dials {
        dial.await.unwrap();
    }
}

#[test]
fn network_validates_addresses_allocates_deterministically_and_reuses() {
    let network = Network::new();
    assert_eq!(
        network.listen("udp", "127.0.0.1:1").unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        network.listen("tcp", "localhost:1").unwrap_err().kind(),
        ErrorKind::InvalidInput
    );

    let first = network.listen("tcp", "127.0.0.1:0").unwrap();
    let second = network.listen("tcp", "127.0.0.1:0").unwrap();
    assert_eq!(first.addr().as_str(), "127.0.0.1:33000");
    assert_eq!(second.addr().as_str(), "127.0.0.1:33001");
    assert_eq!(network.listener_count(), 2);

    first.close();
    assert_eq!(network.listener_count(), 1);
    let reused = network.listen("tcp", "127.0.0.1:0").unwrap();
    assert_eq!(reused.addr().as_str(), "127.0.0.1:33000");
    assert_eq!(
        network.listen("tcp", "127.0.0.1:33000").unwrap_err().kind(),
        ErrorKind::AddrInUse
    );
}

#[tokio::test]
async fn network_dial_and_close_relisten_are_race_safe() {
    let network = Network::new();
    let listener = network.listen("tcp4", "127.0.0.1:12345").unwrap();
    let accepting = Arc::clone(&listener);
    let accept = tokio::spawn(async move { accepting.accept().await.unwrap() });
    let client = network.dial("tcp4", "127.0.0.1:12345").await.unwrap();
    let server = accept.await.unwrap();
    drop((client, server));

    listener.close();
    let replacement = network.listen("tcp6", "127.0.0.1:12345").unwrap();
    assert_eq!(replacement.addr().as_str(), "127.0.0.1:12345");
}

#[test]
fn only_one_concurrent_listener_claims_an_address() {
    let network = Network::new();
    let barrier = Arc::new(Barrier::new(9));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let network = network.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            network.listen("tcp", "127.0.0.1:23456")
        }));
    }
    barrier.wait();

    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results
        .iter()
        .filter_map(|result| result.as_ref().err())
        .all(|error| error.kind() == ErrorKind::AddrInUse));
}

#[tokio::test]
async fn dropping_last_network_closes_registered_listeners() {
    let network = Network::new();
    let listener = network.listen("tcp", "127.0.0.1:34567").unwrap();
    let waiting = Arc::clone(&listener);
    let accept = tokio::spawn(async move { waiting.accept().await });
    tokio::task::yield_now().await;

    drop(network);
    assert!(listener.is_closed());
    assert_eq!(
        accept.await.unwrap().unwrap_err().kind(),
        ErrorKind::ConnectionAborted
    );
}
