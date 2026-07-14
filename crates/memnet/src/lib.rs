//! A name-addressed, in-memory TCP-like network for tests.

mod addr;
mod conn;
mod listener;
mod network;
mod pipe;

pub use addr::MemAddr;
pub use conn::MemConn;
pub use listener::MemListener;
pub use network::Network;
pub use pipe::MemBuf;

#[cfg(test)]
mod tests {
    use std::{
        io::ErrorKind,
        time::{Duration, Instant},
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{MemBuf, MemConn, MemListener, Network};

    #[test]
    fn test_pipe_read_write() {
        let pipe = MemBuf::new("pipe", 16);
        assert_eq!(pipe.write(b"hello").unwrap(), 5);
        let mut output = [0; 5];
        assert_eq!(pipe.read(&mut output).unwrap(), 5);
        assert_eq!(&output, b"hello");
    }

    #[test]
    fn test_pipe_capacity() {
        let pipe = MemBuf::new("pipe", 2);
        assert_eq!(pipe.write(b"abc").unwrap(), 2);
        assert_eq!(pipe.write(b"c").unwrap_err().kind(), ErrorKind::WouldBlock);
        let mut output = [0; 1];
        assert_eq!(pipe.read(&mut output).unwrap(), 1);
        assert_eq!(pipe.write(b"c").unwrap(), 1);
    }

    #[test]
    fn test_pipe_close_drain() {
        let pipe = MemBuf::new("pipe", 8);
        pipe.write(b"hello").unwrap();
        pipe.close();
        let mut first = [0; 3];
        assert_eq!(pipe.read(&mut first).unwrap(), 3);
        assert_eq!(&first, b"hel");
        let mut second = [0; 3];
        assert_eq!(pipe.read(&mut second).unwrap(), 2);
        assert_eq!(&second[..2], b"lo");
        assert_eq!(pipe.read(&mut second).unwrap(), 0);
    }

    #[tokio::test]
    async fn test_conn_pair_echo() {
        let (mut client, mut server) = MemConn::new_pair("pair", 16);
        client.write_all(b"ping").await.unwrap();
        let mut request = [0; 4];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        server.write_all(b"pong").await.unwrap();
        let mut response = [0; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        assert_eq!(client.local_addr().as_str(), "pair");
        assert_eq!(client.remote_addr().as_str(), "pair");
    }

    #[tokio::test]
    async fn test_conn_concurrent() {
        let (mut one, mut two) = MemConn::new_pair("pair", 16);
        let first = tokio::spawn(async move {
            one.write_all(b"one").await.unwrap();
            let mut response = [0; 3];
            one.read_exact(&mut response).await.unwrap();
            response
        });
        let second = tokio::spawn(async move {
            two.write_all(b"two").await.unwrap();
            let mut response = [0; 3];
            two.read_exact(&mut response).await.unwrap();
            response
        });
        assert_eq!(&first.await.unwrap(), b"two");
        assert_eq!(&second.await.unwrap(), b"one");
    }

    #[tokio::test]
    async fn test_conn_deadline() {
        let (_client, mut server) = MemConn::new_pair("pair", 16);
        let mut byte = [0; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(10), server.read(&mut byte))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_listener_accept_dial() {
        let listener = std::sync::Arc::new(MemListener::listen("srv.local"));
        let accepted_by = std::sync::Arc::clone(&listener);
        let server = tokio::spawn(async move { accepted_by.accept().await.unwrap() });
        let mut client = listener.dial("srv.local").await.unwrap();
        let mut server = server.await.unwrap();
        client.write_all(b"x").await.unwrap();
        let mut byte = [0; 1];
        server.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"x");
        listener.close();
    }

    #[tokio::test]
    async fn test_listener_wrong_addr() {
        let listener = MemListener::listen("srv.local");
        let error = listener
            .dial("other.local")
            .await
            .err()
            .expect("dial should fail");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn test_listener_closed_rejects() {
        let listener = MemListener::listen("srv.local");
        listener.close();
        let accept_error = listener.accept().await.err().expect("accept should fail");
        assert_eq!(accept_error.kind(), ErrorKind::ConnectionAborted);
        let dial_error = listener
            .dial("srv.local")
            .await
            .err()
            .expect("dial should fail");
        assert_eq!(dial_error.kind(), ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn test_network_listen_dial() {
        let network = Network::new();
        let listener = network.listen("srv.local").await.unwrap();
        let server_listener = std::sync::Arc::clone(&listener);
        let server = tokio::spawn(async move {
            let mut connection = server_listener.accept().await.unwrap();
            let mut request = [0; 4];
            connection.read_exact(&mut request).await.unwrap();
            connection.write_all(&request).await.unwrap();
        });
        let mut client = network.dial("srv.local").await.unwrap();
        client.write_all(b"echo").await.unwrap();
        let mut response = [0; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"echo");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_network_port_zero() {
        let network = Network::new();
        let listener = network.listen("127.0.0.1:0").await.unwrap();
        assert!(listener.addr().as_str().starts_with("127.0.0.1:33"));
    }

    #[tokio::test]
    async fn test_network_addr_in_use() {
        let network = Network::new();
        network.listen("srv.local").await.unwrap();
        let error = network
            .listen("srv.local")
            .await
            .err()
            .expect("listen should fail");
        assert_eq!(error.kind(), ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn test_network_relisten_after_close() {
        let network = Network::new();
        let listener = network.listen("srv.local").await.unwrap();
        listener.close();
        network.listen("srv.local").await.unwrap();
    }

    #[test]
    fn test_network_new_local_tcp_listener() {
        let network = Network::new();
        let listener = network.new_local_tcp_listener();
        assert!(listener.addr().as_str().starts_with("127.0.0.1:"));
    }

    #[test]
    fn test_pipe_deadline() {
        let pipe = MemBuf::new("pipe", 1);
        let expired = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("one millisecond before now is representable");
        pipe.set_write_deadline(Some(expired));
        assert_eq!(pipe.write(b"x").unwrap_err().kind(), ErrorKind::TimedOut);
    }
}
