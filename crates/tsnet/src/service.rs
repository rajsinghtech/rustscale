//! Tailscale VIP Service listener — `Server::listen_service`.
//!
//! Ports Go's `tsnet.Server.ListenService` to Rust. A service host advertises
//! a named service (`svc:dns-label`) and listens on the service's VIP
//! addresses. Connections addressed to the VIP IP on the specified port are
//! accepted via the userspace netstack and surface as normal tsnet streams.
//!
//! # PROXY protocol v2
//!
//! When [`ServiceMode::proxy_protocol`] is `true`, a PROXY protocol v2 binary
//! header is prepended to each accepted stream so the backend can learn the
//! real client address (the peer's tailnet IP) and the service VIP address.
//!
//! # Architecture
//!
//! Unlike Go's tsnet (which creates a local TCP listener and uses serve-config
//! TCP forwarding to relay connections from the VIP IPs), the Rust
//! implementation listens directly on the VIP IPs via the userspace netstack.
//! The service VIP addresses are:
//! 1. Extracted from the self node's `CapMap` under the `service-host` key
//!    (as `ServiceIPMappings`).
//! 2. Added to the smoltcp interface via `Netstack::add_addr`.
//! 3. Listened on via `Netstack::listen_on(vip_ip, port)`.
//!
//! Multiple VIP listeners (one per v4 VIP) are merged into a single accept
//! channel via forwarder tasks. Each accepted stream is tagged with the VIP
//! address it arrived on, so the PROXY v2 header can carry both the real
//! client address (src) and the service VIP (dst).
//!
//! # Current limitations
//!
//! - Only IPv4 VIPs are supported (smoltcp is configured for `proto-ipv4`
//!   only). IPv6 VIPs are skipped with a warning.
//! - TLS termination is not implemented for service listeners.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use rustscale_netstack::{Listener, NetstackError, NetstackStream};
use rustscale_tailcfg::{service_vip_addrs, ServiceName};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::proxyproto;

/// Configuration for a [`ServiceListener`].
///
/// Mirrors the relevant fields of Go's `tsnet.ServiceModeTCP` /
/// `tsnet.ServiceModeHTTP`. Currently only the TCP mode is implemented.
#[derive(Clone, Debug)]
pub struct ServiceMode {
    /// TCP port to listen on for the service VIP.
    pub port: u16,
    /// If `true`, prepend a PROXY protocol v2 binary header to each accepted
    /// stream so the backend learns the real client address.
    pub proxy_protocol: bool,
}

impl ServiceMode {
    /// Create a TCP service mode on `port` without PROXY protocol.
    pub fn tcp(port: u16) -> Self {
        Self {
            port,
            proxy_protocol: false,
        }
    }

    /// Enable PROXY protocol v2 header injection on accepted connections.
    pub fn with_proxy_protocol(mut self, on: bool) -> Self {
        self.proxy_protocol = on;
        self
    }
}

/// Depth of the merged accept channel for multi-VIP service listeners.
const MERGED_ACCEPT_DEPTH: usize = 64;

/// A network listener for a Tailscale VIP Service.
///
/// Accepts connections addressed to the service's VIP addresses on the
/// configured port. Connections surface as normal tsnet streams. When PROXY
/// protocol v2 is enabled, each stream begins with the PROXY header.
///
/// Created by [`Server::listen_service`](crate::Server::listen_service).
pub struct ServiceListener {
    /// Merged accept channel: (vip_addr, stream) from all VIP listeners.
    accept_rx: mpsc::Receiver<Result<(IpAddr, NetstackStream), NetstackError>>,
    /// The service's FQDN (`<bare-name>.<magicdns-suffix>`).
    pub fqdn: String,
    /// Whether PROXY protocol v2 headers are prepended to accepted streams.
    proxy_protocol: bool,
    /// The service name (for diagnostics).
    svc_name: ServiceName,
    /// The port being listened on.
    port: u16,
}

impl ServiceListener {
    /// Accept the next incoming connection addressed to a service VIP.
    ///
    /// If PROXY protocol v2 is enabled, the returned stream begins with the
    /// PROXY v2 header carrying the real client address (src) and the
    /// service VIP address (dst).
    pub async fn accept(&mut self) -> Result<ServiceStream, NetstackError> {
        let (vip_addr, stream) = self
            .accept_rx
            .recv()
            .await
            .ok_or(NetstackError::ShuttingDown)??;
        Ok(self.wrap_stream(stream, vip_addr))
    }

    /// Wrap a [`NetstackStream`] with a PROXY protocol v2 header if enabled.
    fn wrap_stream(&self, stream: NetstackStream, vip_addr: IpAddr) -> ServiceStream {
        if !self.proxy_protocol {
            return ServiceStream::Plain(stream);
        }

        let dst = SocketAddr::new(vip_addr, self.port);
        let header = match stream.peer_addr() {
            Some(src) => proxyproto::proxy_v2_header(src, dst),
            None => proxyproto::proxy_v2_local_header(),
        };

        ServiceStream::WithProxy {
            prefix: header,
            prefix_pos: 0,
            inner: stream,
        }
    }

    /// The service's fully-qualified domain name.
    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }

    /// The service name.
    pub fn service_name(&self) -> &ServiceName {
        &self.svc_name
    }
}

/// A stream from a [`ServiceListener`], optionally prefixed with a PROXY
/// protocol v2 header.
pub enum ServiceStream {
    /// Plain netstack stream (no PROXY protocol).
    Plain(NetstackStream),
    /// Stream with a PROXY protocol v2 header prepended.
    WithProxy {
        /// The PROXY v2 header bytes, drained before the inner stream.
        prefix: Vec<u8>,
        /// Current read position in `prefix`.
        prefix_pos: usize,
        /// The underlying netstack stream.
        inner: NetstackStream,
    },
}

impl ServiceStream {
    /// The remote peer's socket address, if known.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Plain(s) => s.peer_addr(),
            Self::WithProxy { inner, .. } => inner.peer_addr(),
        }
    }
}

impl AsyncRead for ServiceStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::WithProxy {
                prefix,
                prefix_pos,
                inner,
            } => {
                // Drain the PROXY header first.
                if *prefix_pos < prefix.len() {
                    let remaining = &prefix[*prefix_pos..];
                    let n = remaining.len().min(buf.remaining());
                    buf.put_slice(&remaining[..n]);
                    *prefix_pos += n;
                    return Poll::Ready(Ok(()));
                }
                // Header fully drained — delegate to the inner stream.
                Pin::new(inner).poll_read(cx, buf)
            }
        }
    }
}

impl AsyncWrite for ServiceStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::WithProxy { inner, .. } => Pin::new(inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::WithProxy { inner, .. } => Pin::new(inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::WithProxy { inner, .. } => Pin::new(inner).poll_shutdown(cx),
        }
    }
}

/// Errors specific to service listeners.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("invalid service name: {0}")]
    InvalidServiceName(String),
    #[error("service {0} has no VIP addresses assigned in the netmap")]
    NoVipAddrs(String),
    #[error("service {0} has no IPv4 VIP addresses (IPv6 not yet supported)")]
    NoV4VipAddrs(String),
    #[error("netstack error: {0}")]
    Netstack(#[from] NetstackError),
}

/// Resolve the VIP addresses for a service from the current netmap and create
/// a [`ServiceListener`] that accepts connections on those VIPs.
///
/// This is the internal implementation behind `Server::listen_service`. It:
/// 1. Validates the service name.
/// 2. Looks up the service's VIP addresses from the self node's `CapMap`.
/// 3. Adds each v4 VIP to the netstack interface.
/// 4. Creates a netstack listener on each (vip, port).
/// 5. Merges all listeners into a single accept channel via forwarder tasks,
///    tagging each accepted stream with the VIP address it arrived on.
pub(crate) async fn create_service_listener(
    netstack: &rustscale_netstack::Netstack,
    self_node: &rustscale_tailcfg::Node,
    magicdns_suffix: &str,
    svc_name: &str,
    mode: ServiceMode,
) -> Result<ServiceListener, ServiceError> {
    // 1. Validate the service name.
    let svc =
        ServiceName::new(svc_name).map_err(|e| ServiceError::InvalidServiceName(e.to_string()))?;

    // 2. Resolve VIP addresses from the netmap.
    let vip_addrs = service_vip_addrs(&self_node.CapMap, &svc);
    if vip_addrs.is_empty() {
        return Err(ServiceError::NoVipAddrs(svc.to_string()));
    }

    // 3. Filter to v4 addresses (v6 not yet supported by the netstack).
    let v4_addrs: Vec<IpAddr> = vip_addrs
        .iter()
        .filter(|ip| matches!(ip, IpAddr::V4(_)))
        .copied()
        .collect();
    if v4_addrs.is_empty() {
        eprintln!("tsnet: service {svc} has only IPv6 VIPs (not yet supported)");
        return Err(ServiceError::NoV4VipAddrs(svc.to_string()));
    }

    // Log any v6 addresses we're skipping.
    for ip in &vip_addrs {
        if ip.is_ipv6() {
            eprintln!("tsnet: skipping IPv6 VIP {ip} for service {svc} (not yet supported)");
        }
    }

    // 4. Add each v4 VIP to the netstack interface and listen on it.
    let mut listeners: Vec<(IpAddr, Listener)> = Vec::with_capacity(v4_addrs.len());
    for ip in &v4_addrs {
        netstack.add_addr(*ip).await?;
        match netstack.listen_on(*ip, mode.port).await {
            Ok(ln) => listeners.push((*ip, ln)),
            Err(NetstackError::ListenFailed(msg)) if msg.contains("already in use") => {
                eprintln!(
                    "tsnet: service listener on {ip}:{} already exists, reusing",
                    mode.port
                );
            }
            Err(e) => return Err(e.into()),
        }
    }

    // 5. Merge all listeners into a single accept channel, tagging each
    //    accepted stream with the VIP address it arrived on.
    let (merged_tx, merged_rx) = mpsc::channel(MERGED_ACCEPT_DEPTH);
    for (vip_addr, listener) in listeners {
        let tx = merged_tx.clone();
        tokio::spawn(async move {
            let mut rx = listener.into_receiver();
            while let Some(result) = rx.recv().await {
                let tagged = result.map(|stream| (vip_addr, stream));
                if tx.send(tagged).await.is_err() {
                    break;
                }
            }
        });
    }
    // Drop the last clone so the merged channel closes when all forwarders exit.
    drop(merged_tx);

    // 6. Compute the FQDN.
    let fqdn = format!("{}.{}", svc.without_prefix(), magicdns_suffix);

    eprintln!(
        "tsnet: service listener for {svc} on v4 VIPs {:?} port {} (FQDN: {fqdn})",
        v4_addrs, mode.port
    );

    Ok(ServiceListener {
        accept_rx: merged_rx,
        fqdn,
        proxy_protocol: mode.proxy_protocol,
        svc_name: svc,
        port: mode.port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_mode_tcp() {
        let m = ServiceMode::tcp(8080);
        assert_eq!(m.port, 8080);
        assert!(!m.proxy_protocol);
    }

    #[test]
    fn service_mode_with_proxy() {
        let m = ServiceMode::tcp(443).with_proxy_protocol(true);
        assert_eq!(m.port, 443);
        assert!(m.proxy_protocol);
    }

    #[tokio::test]
    async fn service_listener_accept_empty() {
        let (tx, rx) =
            mpsc::channel::<Result<(IpAddr, NetstackStream), NetstackError>>(MERGED_ACCEPT_DEPTH);
        drop(tx);
        let mut sl = ServiceListener {
            accept_rx: rx,
            fqdn: "test.tailnet.ts.net".into(),
            proxy_protocol: false,
            svc_name: ServiceName::new_unchecked("svc:test"),
            port: 8080,
        };
        let result = sl.accept().await;
        assert!(result.is_err());
    }

    #[test]
    fn service_error_display() {
        let e = ServiceError::InvalidServiceName("bad name".into());
        assert!(e.to_string().contains("bad name"));

        let e = ServiceError::NoVipAddrs("svc:web".into());
        assert!(e.to_string().contains("svc:web"));

        let e = ServiceError::NoV4VipAddrs("svc:web".into());
        assert!(e.to_string().contains("IPv4"));
    }
}
