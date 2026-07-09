//! TLS listener support for tsnet.
//!
//! At this stage (phase 10a) the certificate is **self-signed per node** —
//! generated in-process with [`rcgen`]. Real Let's Encrypt certificates
//! provisioned via the control plane come in a later phase (roadmap item 11).
//! The [`CertProvider`] trait abstracts certificate provisioning so the LE
//! implementation can drop in behind the same `listen_tls` API.
//!
//! # C-representable API
//!
//! [`CertProvider`] is an object-safe trait (`Send + Sync`) usable behind an
//! opaque FFI handle. [`TlsListener`] is a concrete struct (no generics) whose
//! `accept` returns a concrete [`TlsStream`] — both map cleanly to the C handle
//! model used by the FFI layer.

#![allow(clippy::needless_pass_by_value)]

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustscale_netstack::{Listener, NetstackStream};
use tokio_rustls::server::TlsStream as RustlsTlsStream;
use tokio_rustls::TlsAcceptor;

/// A provider of TLS certificate material for [`Server::listen_tls`].
///
/// Implementations supply the certificate chain and private key used to
/// terminate TLS. The current implementation ([`SelfSignedCertProvider`])
/// generates a self-signed certificate per node; a future implementation will
/// fetch Let's Encrypt certificates via the control plane.
///
/// Object-safe (`Send + Sync`) so it can be stored as `Arc<dyn CertProvider>`
/// and used behind an opaque FFI handle.
pub trait CertProvider: Send + Sync {
    /// The leaf + intermediate certificate chain in DER, leaf first.
    fn cert_chain(&self) -> Vec<CertificateDer<'static>>;
    /// The private key matching the leaf certificate, in PKCS#8 DER.
    fn private_key(&self) -> PrivateKeyDer<'static>;
}

/// A [`CertProvider`] that generates a self-signed certificate in-process using
/// [`rcgen`].
///
/// The certificate is valid for `localhost` and the node's tailnet IPs (passed
/// in as SAN names). **Clients must skip certificate verification** when
/// connecting (or pin the node's public key) — the cert is not trusted by any
/// CA. This is sufficient for the benchmarking/serve scenarios in phase 10a.
pub struct SelfSignedCertProvider {
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl SelfSignedCertProvider {
    /// Generate a new self-signed certificate valid for the given subject-alt
    /// names (typically `["localhost"]` plus the node's tailnet IPs).
    pub fn new(san_names: Vec<String>) -> Result<Self, TlsError> {
        let CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(san_names).map_err(TlsError::CertGen)?;
        let cert_chain = vec![cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        Ok(Self { cert_chain, key })
    }
}

impl CertProvider for SelfSignedCertProvider {
    fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        self.cert_chain.clone()
    }
    fn private_key(&self) -> PrivateKeyDer<'static> {
        self.key.clone_key()
    }
}

/// A TLS listener wrapping a netstack [`Listener`].
///
/// Created by [`Server::listen_tls`]. Each call to [`accept`](Self::accept)
/// performs a TLS handshake over an accepted netstack TCP connection and
/// returns a [`TlsStream`].
pub struct TlsListener {
    inner: Listener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    pub(crate) fn new(inner: Listener, provider: Arc<dyn CertProvider>) -> Result<Self, TlsError> {
        let cert_chain = provider.cert_chain();
        let key = provider.private_key();
        let server_config = rustls::server::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| TlsError::Rustls(e.to_string()))?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        Ok(Self { inner, acceptor })
    }

    /// Accept the next incoming TCP connection and perform a TLS handshake.
    pub async fn accept(&mut self) -> Result<TlsStream, TlsError> {
        let stream = self.inner.accept().await?;
        let tls = self.acceptor.accept(stream).await?;
        Ok(TlsStream(tls))
    }
}

/// A TLS-over-netstack stream implementing [`AsyncRead`] + [`AsyncWrite`].
#[allow(dead_code)]
pub struct TlsStream(RustlsTlsStream<NetstackStream>);

impl tokio::io::AsyncRead for TlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TlsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Errors from TLS listener operations.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("certificate generation error: {0}")]
    CertGen(#[from] rcgen::Error),
    #[error("rustls configuration error: {0}")]
    Rustls(String),
    #[error("netstack error: {0}")]
    Netstack(#[from] rustscale_netstack::NetstackError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

use rcgen::CertifiedKey;

/// Build a default [`CertProvider`] (self-signed) for a node with the given
/// tailnet IPs. The SAN list includes `localhost` and each tailnet IP so the
/// cert is valid for both loopback and tailnet-address connections.
pub(crate) fn default_cert_provider(tailscale_ips: &[std::net::IpAddr]) -> Arc<dyn CertProvider> {
    let mut sans = vec!["localhost".to_string()];
    for ip in tailscale_ips {
        sans.push(ip.to_string());
    }
    match SelfSignedCertProvider::new(sans) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!("tsnet: self-signed cert generation failed ({e}); using fallback");
            // Fallback: localhost-only cert. If this also fails we panic —
            // TLS is unavailable, which is a hard error for listen_tls.
            Arc::new(
                SelfSignedCertProvider::new(vec!["localhost".into()])
                    .expect("tsnet: fallback self-signed cert generation failed — TLS unavailable"),
            )
        }
    }
}
