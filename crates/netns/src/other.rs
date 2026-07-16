use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};
pub async fn control_and_connect(addr: SocketAddr) -> Result<TcpStream, std::io::Error> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

pub async fn system_control_and_connect(addr: SocketAddr) -> Result<TcpStream, std::io::Error> {
    control_and_connect(addr).await
}

pub fn create_tun_tcp_socket(
    _addr: SocketAddr,
    _tun_name: &str,
) -> Result<tokio::net::TcpSocket, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "protected TUN TCP binding is unsupported on this platform",
    ))
}

pub fn configure_udp_socket(_socket: &UdpSocket) -> Result<(), std::io::Error> {
    Ok(())
}

pub fn validate_underlay_bypass(_rustscale_tun_name: &str) -> Result<(), std::io::Error> {
    Ok(())
}
