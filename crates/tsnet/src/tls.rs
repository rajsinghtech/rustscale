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

// ---------------------------------------------------------------------------
// Let's Encrypt certs via the control plane (ControlCertProvider)
// ---------------------------------------------------------------------------

use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};

/// A fetched certificate: PEM-encoded cert chain + key, plus the leaf's
/// not-after time (for cache/refresh decisions).
#[derive(Clone, Debug)]
pub struct CertMaterial {
    /// PEM cert chain (leaf first), `-----BEGIN CERTIFICATE-----` blocks.
    pub cert_pem: Vec<u8>,
    /// PEM private key (PKCS#8).
    pub key_pem: Vec<u8>,
    /// Leaf certificate not-after time.
    pub not_after: DateTime<Utc>,
}

/// Errors from certificate provisioning.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// The tailnet does not have HTTPS/certs enabled — `DNSConfig.CertDomains`
    /// does not contain our node's FQDN. A clean, typed signal that LE certs
    /// are unavailable for this tailnet.
    #[error("HTTPS certs not enabled for this tailnet (FQDN {0} not in CertDomains)")]
    NotEnabled(String),
    /// HTTPS is enabled but the ACME-to-Let's-Encrypt client is not yet
    /// implemented in rustscale. The control-plane `SetDNS` path is wired;
    /// the ACME order/finalize step is a follow-up phase.
    #[error("ACME client not yet implemented (HTTPS enabled for {0}); using self-signed")]
    AcmeClientUnavailable(String),
    /// A protocol error during the ACME order flow (directory, authorization,
    /// challenge, finalize, or cert download). The message includes the
    /// underlying ACME error detail.
    #[error("ACME protocol error: {0}")]
    Acme(String),
    /// A cached cert exists but is unreadable/invalid.
    #[error("cached cert for {0} is invalid: {1}")]
    CacheInvalid(String, String),
    /// I/O error reading/writing the cert cache.
    #[error("cert cache io: {0}")]
    Io(#[from] std::io::Error),
}

/// How certificate material is fetched. Implementations:
/// - [`AcmeCertFetcher`] — the real (control-plane-assisted) LE flow.
/// - test mocks — for cache/refresh unit tests.
///
/// Object-safe (`Send + Sync`) so it can be stored as `Arc<dyn CertFetcher>`.
/// The `fetch` method is async (via `async_trait`); `CertProvider` itself
/// stays synchronous — only the refresh/fetch path is async.
#[async_trait::async_trait]
pub trait CertFetcher: Send + Sync {
    /// Fetch cert material for `domain` (the node FQDN without trailing dot).
    async fn fetch(&self, domain: &str) -> Result<CertMaterial, CertError>;
}

/// A [`CertFetcher`] implementing the control-plane-assisted LE flow.
///
/// **Flow found in Go** (`ipn/ipnlocal/cert.go`): the client speaks ACME
/// *directly* to Let's Encrypt; control's role is only to publish the ACME
/// DNS-01 challenge TXT record via `POST /machine/set-dns` (control owns the
/// `ts.net` DNS zone). A non-empty `MapResponse.DNSConfig.CertDomains` means
/// the tailnet has HTTPS enabled.
///
/// **What rustscale implements**: the full ACME RFC 8555 flow — directory,
/// newAccount, newOrder, dns-01 challenge (with TXT published via control
/// `set-dns`), poll, finalize, download cert chain. The account key (P-256,
/// ES256) is persisted in `state_dir`; issued certs are cached by
/// [`ControlCertProvider`].
///
/// The directory URL defaults to LE production; set the `RUSTSCALE_ACME_URL`
/// env var to override (e.g. LE staging for e2e tests).
pub struct AcmeCertFetcher {
    cert_domains: Vec<String>,
    state_dir: PathBuf,
    control_url: String,
    machine_key: rustscale_key::MachinePrivate,
    server_pub_key: rustscale_key::MachinePublic,
    node_key: rustscale_key::NodePrivate,
    capability_version: i32,
    protocol_version: u16,
}

impl AcmeCertFetcher {
    /// Build from the netmap's `DNSConfig.CertDomains` plus the control-plane
    /// credentials needed for `set-dns` (publishing the DNS-01 TXT record).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cert_domains: Vec<String>,
        state_dir: PathBuf,
        control_url: String,
        machine_key: rustscale_key::MachinePrivate,
        server_pub_key: rustscale_key::MachinePublic,
        node_key: rustscale_key::NodePrivate,
        capability_version: i32,
        protocol_version: u16,
    ) -> Self {
        Self {
            cert_domains,
            state_dir,
            control_url,
            machine_key,
            server_pub_key,
            node_key,
            capability_version,
            protocol_version,
        }
    }

    fn enabled_for(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.').to_lowercase();
        self.cert_domains
            .iter()
            .any(|c| c.trim_end_matches('.').eq_ignore_ascii_case(&d))
    }
}

/// Publishes a DNS-01 TXT record via the control plane's `set-dns`.
///
/// This is the glue between the ACME protocol client ([`crate::acme`]) and
/// the control plane ([`ControlClient::set_dns`]). It holds the credentials
/// needed to dial the control server and post a `SetDNSRequest`.
struct ControlDnsPublisher {
    control_url: String,
    machine_key: rustscale_key::MachinePrivate,
    server_pub_key: rustscale_key::MachinePublic,
    node_key: rustscale_key::NodePrivate,
    capability_version: i32,
    protocol_version: u16,
}

#[async_trait::async_trait]
impl crate::acme::DnsPublisher for ControlDnsPublisher {
    async fn publish_txt(&self, name: &str, value: &str) -> Result<(), crate::acme::AcmeError> {
        use rustscale_controlclient::client::ControlClient;
        use rustscale_tailcfg::SetDNSRequest;

        let cc = ControlClient::new(
            &self.control_url,
            self.machine_key.clone(),
            self.server_pub_key.clone(),
            self.protocol_version,
        );
        let req = SetDNSRequest {
            Version: self.capability_version,
            NodeKey: self.node_key.public(),
            Name: name.to_string(),
            Type: "TXT".to_string(),
            Value: value.to_string(),
        };
        cc.set_dns(&req)
            .await
            .map(|_| ())
            .map_err(|e| crate::acme::AcmeError::SetDns(e.to_string()))
    }
}

#[async_trait::async_trait]
impl CertFetcher for AcmeCertFetcher {
    async fn fetch(&self, domain: &str) -> Result<CertMaterial, CertError> {
        if !self.enabled_for(domain) {
            return Err(CertError::NotEnabled(domain.to_string()));
        }

        let directory_url = std::env::var("RUSTSCALE_ACME_URL")
            .unwrap_or_else(|_| crate::acme::LE_DIRECTORY_URL.to_string());

        let publisher: std::sync::Arc<dyn crate::acme::DnsPublisher> =
            std::sync::Arc::new(ControlDnsPublisher {
                control_url: self.control_url.clone(),
                machine_key: self.machine_key.clone(),
                server_pub_key: self.server_pub_key.clone(),
                node_key: self.node_key.clone(),
                capability_version: self.capability_version,
                protocol_version: self.protocol_version,
            });

        crate::acme::issue_cert(domain, &self.state_dir, &directory_url, publisher)
            .await
            .map_err(|e| CertError::Acme(e.to_string()))
    }
}

/// Refresh threshold: refresh when the cached cert expires within this many
/// days (matches Go's `domainRenewalTimeByExpiry` ~2/3 lifetime, simplified).
const CERT_REFRESH_THRESHOLD: Duration = Duration::days(14);

/// A [`CertProvider`] backed by Let's Encrypt certs fetched via the control
/// plane (through a [`CertFetcher`]). Caches cert+key PEM in `state_dir`
/// (mirroring Go's `certFileStore`: `<domain>.crt.pem` / `<domain>.key.pem`
/// plus a `<domain>.expiry` sidecar for the cache-validity check) and
/// refreshes when the cached cert is missing or within
/// [`CERT_REFRESH_THRESHOLD`] of expiry.
///
/// [`CertProvider::cert_chain`] / [`CertProvider::private_key`] return the
/// cached material; call [`ControlCertProvider::refresh`] (async) first to
/// populate/refresh it. Both methods are synchronous per the trait, so
/// refresh is decoupled.
pub struct ControlCertProvider {
    state_dir: PathBuf,
    domain: String,
    fetcher: Arc<dyn CertFetcher>,
    material: Mutex<Option<CertMaterial>>,
    /// Optional health tracker for reporting stale-cache fallback.
    health: Option<rustscale_health::Tracker>,
}

impl ControlCertProvider {
    /// Create a new provider. `domain` is the node FQDN (trailing dot
    /// stripped). Call [`refresh`](Self::refresh) before use.
    pub fn new(
        state_dir: PathBuf,
        domain: impl Into<String>,
        fetcher: Arc<dyn CertFetcher>,
    ) -> Self {
        Self {
            state_dir,
            domain: domain.into().trim_end_matches('.').to_string(),
            fetcher,
            material: Mutex::new(None),
            health: None,
        }
    }

    /// Attach a health tracker so the provider can report when it serves a
    /// stale cached cert (fetch failure but cache still valid).
    pub fn with_health(mut self, health: rustscale_health::Tracker) -> Self {
        self.health = Some(health);
        self
    }

    /// Load from cache or fetch fresh material. Refreshes when the cached
    /// cert is missing or expires within [`CERT_REFRESH_THRESHOLD`].
    pub async fn refresh(&self) -> Result<(), CertError> {
        // Try the cache first.
        if let Some(cached) = self.load_cached()? {
            let now = Utc::now();
            if cached.not_after > now + CERT_REFRESH_THRESHOLD {
                *self.material.lock().expect("cert material mutex") = Some(cached);
                return Ok(());
            }
            // Cached but near expiry — fall through to a fresh fetch.
        }

        match self.fetcher.fetch(&self.domain).await {
            Ok(mat) => {
                self.write_cached(&mat)?;
                *self.material.lock().expect("cert material mutex") = Some(mat);
                Ok(())
            }
            Err(e) => {
                // On fetch failure, serve a still-valid cached cert if we
                // have one (stale-but-usable); otherwise propagate the error.
                if let Some(cached) = self.load_cached()? {
                    if cached.not_after > Utc::now() {
                        eprintln!(
                            "tsnet: cert fetch failed ({e}); serving stale cache for {}",
                            self.domain
                        );
                        if let Some(ref health) = self.health {
                            health.set_unhealthy(
                                rustscale_health::WARN_CERT_FALLBACK,
                                format!("serving stale cached cert: {e}"),
                            );
                        }
                        *self.material.lock().expect("cert material mutex") = Some(cached);
                        return Ok(());
                    }
                }
                Err(e)
            }
        }
    }

    fn crt_path(&self) -> PathBuf {
        self.state_dir.join(format!("{}.crt.pem", self.domain))
    }
    fn key_path(&self) -> PathBuf {
        self.state_dir.join(format!("{}.key.pem", self.domain))
    }
    fn expiry_path(&self) -> PathBuf {
        self.state_dir.join(format!("{}.expiry", self.domain))
    }

    fn load_cached(&self) -> Result<Option<CertMaterial>, CertError> {
        let crt = std::fs::read(self.crt_path());
        let key = std::fs::read(self.key_path());
        let (crt, key) = match (crt, key) {
            (Ok(c), Ok(k)) => (c, k),
            (Err(e), _) | (_, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            (Err(e), _) | (_, Err(e)) => return Err(CertError::Io(e)),
        };
        let expiry = std::fs::read_to_string(self.expiry_path())
            .map_err(|e| CertError::CacheInvalid(self.domain.clone(), e.to_string()))?;
        let not_after = DateTime::parse_from_rfc3339(expiry.trim())
            .map_err(|e| CertError::CacheInvalid(self.domain.clone(), e.to_string()))?
            .with_timezone(&Utc);
        Ok(Some(CertMaterial {
            cert_pem: crt,
            key_pem: key,
            not_after,
        }))
    }

    fn write_cached(&self, mat: &CertMaterial) -> Result<(), CertError> {
        std::fs::write(self.crt_path(), &mat.cert_pem)?;
        std::fs::write(self.key_path(), &mat.key_pem)?;
        std::fs::write(self.expiry_path(), mat.not_after.to_rfc3339())?;
        Ok(())
    }

    fn with_material<R>(&self, f: impl Fn(&CertMaterial) -> R) -> R {
        let guard = self.material.lock().expect("cert material mutex");
        let mat = guard
            .as_ref()
            .expect("ControlCertProvider used before refresh() — call refresh() first");
        f(mat)
    }
}

impl CertProvider for ControlCertProvider {
    fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        self.with_material(|mat| pem_cert_chain_to_der(&mat.cert_pem))
    }
    fn private_key(&self) -> PrivateKeyDer<'static> {
        self.with_material(|mat| {
            let der = pem_pkcs8_to_der(&mat.key_pem).unwrap_or_default();
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))
        })
    }
}

/// Decode all `CERTIFICATE` PEM blocks in `pem` to DER, leaf first.
fn pem_cert_chain_to_der(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    let Ok(text) = std::str::from_utf8(pem) else {
        return vec![];
    };
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after_begin = &rest[start + "-----BEGIN CERTIFICATE-----".len()..];
        let Some(end) = after_begin.find("-----END CERTIFICATE-----") else {
            break;
        };
        let b64: String = after_begin[..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b64) {
            out.push(CertificateDer::from(der));
        }
        rest = &after_begin[end + "-----END CERTIFICATE-----".len()..];
    }
    out
}

/// Decode a PKCS#8 (`PRIVATE KEY`) PEM block to DER.
fn pem_pkcs8_to_der(pem: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(pem).ok()?;
    let begin = "-----BEGIN PRIVATE KEY-----";
    let end = "-----END PRIVATE KEY-----";
    let start = text.find(begin)? + begin.len();
    let stop = text[start..].find(end)? + start;
    let b64: String = text[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

#[cfg(test)]
mod cert_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fetcher that returns canned material and counts calls.
    struct MockFetcher {
        not_after: DateTime<Utc>,
        calls: AtomicUsize,
    }
    impl MockFetcher {
        fn new(not_after: DateTime<Utc>) -> Self {
            Self {
                not_after,
                calls: AtomicUsize::new(0),
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }
    #[async_trait::async_trait]
    impl CertFetcher for MockFetcher {
        async fn fetch(&self, domain: &str) -> Result<CertMaterial, CertError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // Real PEM (self-signed via rcgen) so the DER parse paths work.
            let CertifiedKey { cert, key_pair } =
                rcgen::generate_simple_self_signed(vec![domain.to_string()]).unwrap();
            let mut cert_pem = String::new();
            use std::fmt::Write;
            let der = cert.der();
            let b64 = base64::engine::general_purpose::STANDARD.encode(der);
            writeln!(cert_pem, "-----BEGIN CERTIFICATE-----").unwrap();
            for chunk in b64.as_bytes().chunks(64) {
                writeln!(cert_pem, "{}", std::str::from_utf8(chunk).unwrap()).unwrap();
            }
            writeln!(cert_pem, "-----END CERTIFICATE-----").unwrap();
            let key_der = key_pair.serialize_der();
            let mut key_pem = String::new();
            writeln!(key_pem, "-----BEGIN PRIVATE KEY-----").unwrap();
            let kb64 = base64::engine::general_purpose::STANDARD.encode(&key_der);
            for chunk in kb64.as_bytes().chunks(64) {
                writeln!(key_pem, "{}", std::str::from_utf8(chunk).unwrap()).unwrap();
            }
            writeln!(key_pem, "-----END PRIVATE KEY-----").unwrap();
            Ok(CertMaterial {
                cert_pem: cert_pem.into_bytes(),
                key_pem: key_pem.into_bytes(),
                not_after: self.not_after,
            })
        }
    }

    fn temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!("rustscale-cert-test-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[tokio::test]
    async fn cache_miss_fetches_then_cache_hit_no_fetch() {
        let dir = temp_dir();
        let far_future = Utc::now() + Duration::days(90);
        let fetcher = Arc::new(MockFetcher::new(far_future));
        let prov = ControlCertProvider::new(dir.clone(), "node.ts.net", fetcher.clone());
        // No cache → fetch.
        prov.refresh().await.expect("refresh");
        assert_eq!(fetcher.calls(), 1, "should fetch on cache miss");
        // Cached + far from expiry → no refetch.
        prov.refresh().await.expect("refresh 2");
        assert_eq!(fetcher.calls(), 1, "should NOT refetch on cache hit");
        // Material parses to a cert chain.
        assert!(!prov.cert_chain().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn refreshes_when_within_threshold() {
        let dir = temp_dir();
        let soon = Utc::now() + Duration::days(5); // < 14 day threshold
        let fetcher = Arc::new(MockFetcher::new(soon));
        let prov = ControlCertProvider::new(dir.clone(), "node.ts.net", fetcher.clone());
        prov.refresh().await.expect("refresh");
        assert_eq!(fetcher.calls(), 1);
        // Within threshold → refetch.
        prov.refresh().await.expect("refresh 2");
        assert_eq!(fetcher.calls(), 2, "should refetch within threshold");
        std::fs::remove_dir_all(dir).ok();
    }

    /// Build a dummy AcmeCertFetcher with generated keys (the control info
    /// is never used when cert_domains is empty — `enabled_for` returns
    /// false before touching it).
    fn dummy_acme_fetcher(cert_domains: Vec<String>) -> AcmeCertFetcher {
        let mk = rustscale_key::MachinePrivate::generate();
        let mk_pub = mk.public();
        let nk = rustscale_key::NodePrivate::generate();
        AcmeCertFetcher::new(
            cert_domains,
            temp_dir(),
            "control.example.invalid".into(),
            mk,
            mk_pub,
            nk,
            141,
            141,
        )
    }

    #[tokio::test]
    async fn not_enabled_propagates() {
        let fetcher = Arc::new(dummy_acme_fetcher(vec![])); // no cert domains
        let prov = ControlCertProvider::new(temp_dir(), "node.ts.net", fetcher);
        let err = prov.refresh().await.expect_err("should be NotEnabled");
        assert!(matches!(err, CertError::NotEnabled(_)), "got {err:?}");
    }

    #[test]
    fn acme_fetcher_enabled_for() {
        let f = dummy_acme_fetcher(vec!["node.ts.net".into()]);
        assert!(f.enabled_for("node.ts.net"));
        assert!(f.enabled_for("node.ts.net.")); // trailing dot ok
        assert!(f.enabled_for("NODE.ts.net")); // case-insensitive
        assert!(!f.enabled_for("other.ts.net"));
    }

    #[tokio::test]
    async fn stale_cache_served_on_fetch_failure() {
        let dir = temp_dir();
        // First: a valid cached cert written directly.
        let far_future = Utc::now() + Duration::days(90);
        let good = MockFetcher::new(far_future);
        let mat = good.fetch("node.ts.net").await.unwrap();
        std::fs::write(dir.join("node.ts.net.crt.pem"), &mat.cert_pem).unwrap();
        std::fs::write(dir.join("node.ts.net.key.pem"), &mat.key_pem).unwrap();
        std::fs::write(dir.join("node.ts.net.expiry"), mat.not_after.to_rfc3339()).unwrap();
        // Now a fetcher that always fails — refresh should serve the stale cache.
        struct Fail;
        #[async_trait::async_trait]
        impl CertFetcher for Fail {
            async fn fetch(&self, _d: &str) -> Result<CertMaterial, CertError> {
                Err(CertError::NotEnabled("x".into()))
            }
        }
        let prov = ControlCertProvider::new(dir.clone(), "node.ts.net", Arc::new(Fail));
        prov.refresh().await.expect("should serve stale cache");
        assert!(!prov.cert_chain().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn pem_cert_chain_to_der_roundtrip() {
        let CertifiedKey { cert, .. } =
            rcgen::generate_simple_self_signed(vec!["x".into()]).unwrap();
        let der = cert.der();
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
        let parsed = pem_cert_chain_to_der(pem.as_bytes());
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].as_ref(), der.as_ref());
    }
}
