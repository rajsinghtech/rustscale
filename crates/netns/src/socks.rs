use std::net::{SocketAddr, ToSocketAddrs};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub fn all_proxy() -> Option<String> {
    let proxy = std::env::var("ALL_PROXY")
        .or_else(|_| std::env::var("all_proxy"))
        .ok()?;
    let proxy = proxy.trim();
    if proxy.is_empty() {
        return None;
    }
    let proxy = proxy
        .strip_prefix("socks5://")
        .or_else(|| proxy.strip_prefix("socks5h://"))
        .unwrap_or(proxy);
    Some(proxy.to_string())
}

pub async fn dial_sock5(
    proxy: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, std::io::Error> {
    let proxy_addr = if proxy.contains(':') {
        proxy.to_string()
    } else {
        format!("{proxy}:1080")
    };
    let sa: SocketAddr = proxy_addr
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid proxy"))?;
    let mut stream = TcpStream::connect(sa).await?;
    stream.set_nodelay(true).ok();
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "SOCKS5 auth negotiation failed",
        ));
    }
    let host_bytes = target_host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "host too long",
        ));
    }
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await?;
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "invalid SOCKS5 reply version",
        ));
    }
    if hdr[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 connect failed: rep={}", hdr[1]),
        ));
    }
    match hdr[3] {
        0x01 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let mut buf = vec![0u8; len_buf[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unknown SOCKS5 atyp",
            ))
        }
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::all_proxy;
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    #[test]
    fn test_all_proxy_parsing() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("ALL_PROXY");
        std::env::remove_var("all_proxy");
        assert!(all_proxy().is_none());
        std::env::set_var("ALL_PROXY", "socks5://127.0.0.1:1080");
        assert_eq!(all_proxy().as_deref(), Some("127.0.0.1:1080"));
        std::env::remove_var("ALL_PROXY");
        std::env::set_var("all_proxy", "127.0.0.1:9050");
        assert_eq!(all_proxy().as_deref(), Some("127.0.0.1:9050"));
        std::env::remove_var("all_proxy");
    }
}
