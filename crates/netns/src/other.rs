use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};
pub async fn control_and_connect(addr: SocketAddr) -> Result<TcpStream, std::io::Error> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

pub fn configure_udp_socket(_socket: &UdpSocket) -> Result<(), std::io::Error> {
    Ok(())
}
