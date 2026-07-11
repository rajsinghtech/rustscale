use std::net::SocketAddr;
use tokio::net::TcpStream;

pub async fn control_and_connect(addr: SocketAddr) -> Result<TcpStream, std::io::Error> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}
