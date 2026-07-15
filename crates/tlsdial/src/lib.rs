//! Unified outbound TLS policy for rustscale control and DERP clients.
//!
//! This crate is the single place that combines platform, Mozilla, optional
//! caller-provided, and baked ISRG roots; constructs rustls client configs;
//! applies SNI and certificate-name policy; enforces handshake timeouts; and
//! reports certificate diagnostics. TCP dialing remains selectable between
//! [`rustscale_tsdial`] and a caller-provided [`rustscale_dnscache::Resolver`].

#![forbid(unsafe_code)]

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Default maximum duration of a TLS handshake.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A stable, coarse classification suitable for retry and health decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorClass {
    /// The SNI name could not be represented as a TLS server name.
    InvalidServerName,
    /// A caller-provided trust anchor was malformed.
    InvalidRoot,
    /// An ALPN protocol identifier was empty or too long.
    InvalidAlpn,
    /// A pinned certificate hash was malformed.
    InvalidCertificatePin,
    /// DNS resolution failed before TLS started.
    Dns,
    /// The TCP or TLS transport failed for a non-certificate reason.
    Io,
    /// The TLS handshake exceeded its configured deadline.
    Timeout,
    /// The peer certificate was rejected.
    Certificate(CertificateFailure),
    /// TLS failed for a reason not covered above.
    Handshake,
}

/// Certificate verification failure categories used by diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateFailure {
    BadEncoding,
    Expired,
    NotValidYet,
    UnknownIssuer,
    NameMismatch,
    Revoked,
    BadSignature,
    InvalidPurpose,
    PinMismatch,
    Other,
}

/// Clock direction suggested by a certificate validity failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockSkew {
    /// The local clock may be ahead (the certificate appears expired).
    Ahead,
    /// The local clock may be behind (the certificate is not valid yet).
    Behind,
}

/// Information emitted after each certificate verification attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationDiagnostic {
    /// SNI name used on the wire.
    pub server_name: String,
    /// Name against which the certificate was checked.
    pub certificate_name: String,
    /// `None` when verification succeeded.
    pub failure: Option<CertificateFailure>,
    /// Clock-skew hint for time validity failures.
    pub clock_skew: Option<ClockSkew>,
    /// Issuer of a self-issued leaf, useful for interception diagnostics.
    pub self_signed_issuer: Option<String>,
    /// Known network appliance manufacturer found in a rejected leaf.
    pub block_blame: Option<&'static str>,
}

/// Certificate verification diagnostic callback.
pub type DiagnosticHook = Arc<dyn Fn(VerificationDiagnostic) + Send + Sync>;

/// Shared TLS client policy.
#[derive(Clone)]
pub struct Config {
    extra_roots: Vec<Vec<u8>>,
    alpn_protocols: Vec<Vec<u8>>,
    expected_certificate_name: Option<String>,
    expected_certificate_sha256: Option<[u8; 32]>,
    handshake_timeout: Duration,
    diagnostic_hook: Option<DiagnosticHook>,
    dangerous_insecure_for_tests: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("extra_root_count", &self.extra_roots.len())
            .field("alpn_protocols", &self.alpn_protocols)
            .field("expected_certificate_name", &self.expected_certificate_name)
            .field(
                "has_expected_certificate_sha256",
                &self.expected_certificate_sha256.is_some(),
            )
            .field("handshake_timeout", &self.handshake_timeout)
            .field("has_diagnostic_hook", &self.diagnostic_hook.is_some())
            .field(
                "dangerous_insecure_for_tests",
                &self.dangerous_insecure_for_tests,
            )
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            extra_roots: Vec::new(),
            alpn_protocols: Vec::new(),
            expected_certificate_name: None,
            expected_certificate_sha256: None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            diagnostic_hook: None,
            dangerous_insecure_for_tests: false,
        }
    }
}

impl Config {
    /// Add DER-encoded caller-provided trust anchors.
    pub fn with_extra_roots(mut self, roots: &[Vec<u8>]) -> Self {
        self.extra_roots = roots.to_vec();
        self
    }

    /// Set ALPN protocol identifiers in client preference order.
    pub fn with_alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Validate the certificate against `name` while retaining the dialed name
    /// for SNI. This supports explicit domain-fronting configurations without
    /// disabling chain, validity, or hostname verification.
    pub fn with_expected_certificate_name(mut self, name: impl Into<String>) -> Self {
        self.expected_certificate_name = Some(name.into());
        self
    }

    /// Require the verified leaf certificate to have this full-DER SHA-256
    /// digest. Normal chain, validity, and hostname verification still apply.
    pub fn with_expected_certificate_sha256(mut self, digest: [u8; 32]) -> Self {
        self.expected_certificate_sha256 = Some(digest);
        self
    }

    /// Parse and require a 64-character hexadecimal full-certificate digest.
    pub fn with_expected_certificate_sha256_hex(mut self, digest: &str) -> Result<Self, Error> {
        if digest.len() != 64 {
            return Err(Error::InvalidCertificatePin);
        }
        let mut decoded = [0u8; 32];
        for (index, chunk) in digest.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_nibble(chunk[0]).ok_or(Error::InvalidCertificatePin)?;
            let low = hex_nibble(chunk[1]).ok_or(Error::InvalidCertificatePin)?;
            decoded[index] = (high << 4) | low;
        }
        self.expected_certificate_sha256 = Some(decoded);
        Ok(self)
    }

    /// Set the TLS handshake deadline.
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Observe deterministic certificate verification diagnostics.
    pub fn with_diagnostic_hook(mut self, hook: DiagnosticHook) -> Self {
        self.diagnostic_hook = Some(hook);
        self
    }

    /// Disable certificate-chain and hostname verification for an explicitly
    /// marked test endpoint. TLS handshake signatures are still verified.
    ///
    /// This exists only to preserve `InsecureForTests` and local interop
    /// behavior. Production callers must not enable it.
    #[doc(hidden)]
    pub fn dangerous_insecure_for_tests(mut self, enabled: bool) -> Self {
        self.dangerous_insecure_for_tests = enabled;
        self
    }
}

/// Errors from TLS configuration, dialing, and handshaking.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid TLS server name {name:?}: {reason}")]
    InvalidServerName { name: String, reason: String },
    #[error("invalid extra root certificate at index {index}: {source}")]
    InvalidRoot { index: usize, source: rustls::Error },
    #[error("invalid ALPN protocol at index {index}: identifiers must contain 1..=255 bytes")]
    InvalidAlpn { index: usize },
    #[error("expected certificate SHA-256 must be exactly 64 hexadecimal characters")]
    InvalidCertificatePin,
    #[error("DNS dial failed: {0}")]
    Dns(String),
    #[error("TCP dial failed: {0}")]
    Dial(#[source] io::Error),
    #[error("TLS handshake timed out after {0:?}")]
    Timeout(Duration),
    #[error("TLS handshake failed: {0}")]
    Handshake(#[source] io::Error),
    #[error("TLS verifier configuration failed: {0}")]
    Verifier(String),
}

impl Error {
    /// Return the stable error classification.
    pub fn class(&self) -> ErrorClass {
        match self {
            Self::InvalidServerName { .. } => ErrorClass::InvalidServerName,
            Self::InvalidRoot { .. } => ErrorClass::InvalidRoot,
            Self::InvalidAlpn { .. } => ErrorClass::InvalidAlpn,
            Self::InvalidCertificatePin => ErrorClass::InvalidCertificatePin,
            Self::Dns(_) => ErrorClass::Dns,
            Self::Dial(_) => ErrorClass::Io,
            Self::Timeout(_) => ErrorClass::Timeout,
            Self::Verifier(_) => ErrorClass::Handshake,
            Self::Handshake(error) => rustls_error_from_io(error)
                .and_then(certificate_failure)
                .map_or(ErrorClass::Handshake, ErrorClass::Certificate),
        }
    }
}

/// Parse an owned TLS server name for SNI.
pub fn server_name(name: &str) -> Result<ServerName<'static>, Error> {
    ServerName::try_from(name.to_owned()).map_err(|error| Error::InvalidServerName {
        name: name.to_owned(),
        reason: error.to_string(),
    })
}

/// Build a rustls client config from the shared policy.
pub fn client_config(options: &Config) -> Result<rustls::ClientConfig, Error> {
    ensure_ring_provider();
    for (index, protocol) in options.alpn_protocols.iter().enumerate() {
        if protocol.is_empty() || protocol.len() > u8::MAX as usize {
            return Err(Error::InvalidAlpn { index });
        }
    }

    let roots = root_store(&options.extra_roots)?;
    let provider = rustls::crypto::ring::default_provider();
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(provider.clone()),
    )
    .build()
    .map_err(|error| Error::Verifier(error.to_string()))?;

    let verifier: Arc<dyn ServerCertVerifier> = if options.dangerous_insecure_for_tests {
        Arc::new(InsecureForTestsVerifier {
            signatures: verifier,
        })
    } else {
        let expected_name = options
            .expected_certificate_name
            .as_deref()
            .map(server_name)
            .transpose()?;
        Arc::new(DiagnosticVerifier {
            inner: verifier,
            expected_name,
            expected_sha256: options.expected_certificate_sha256,
            hook: options.diagnostic_hook.clone(),
        })
    };

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| Error::Verifier(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols.clone_from(&options.alpn_protocols);
    Ok(config)
}

/// Complete a TLS handshake over an already-connected stream.
///
/// `tls_server_name` is sent as SNI. Use
/// [`Config::with_expected_certificate_name`] only when the certificate must be
/// validated against a different explicit name.
pub async fn connect<S>(
    stream: S,
    tls_server_name: &str,
    options: &Config,
) -> Result<tokio_rustls::client::TlsStream<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name = server_name(tls_server_name)?;
    let config = client_config(options)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    tokio::time::timeout(options.handshake_timeout, connector.connect(name, stream))
        .await
        .map_err(|_| Error::Timeout(options.handshake_timeout))?
        .map_err(Error::Handshake)
}

/// Dial `host:port`, optionally through a DNS cache, then complete TLS.
///
/// Proxy tunnels should be established by the caller and passed to [`connect`]
/// so proxy selection remains protocol-specific.
pub async fn dial(
    host: &str,
    port: u16,
    options: &Config,
    resolver: Option<&rustscale_dnscache::Resolver>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Error> {
    let tcp = if let Some(resolver) = resolver {
        resolver
            .dial_tcp(host, port)
            .await
            .map_err(|error| Error::Dns(error.to_string()))?
    } else {
        rustscale_tsdial::system_dial("tcp", &format!("{host}:{port}"))
            .await
            .map_err(Error::Dial)?
    };
    connect(tcp, host, options).await
}

fn ensure_ring_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn root_store(extra_roots: &[Vec<u8>]) -> Result<rustls::RootCertStore, Error> {
    // Validate extras before passing them to bakedroots' combined store, whose
    // historical API expects valid DER and panics on malformed caller input.
    for (index, der) in extra_roots.iter().enumerate() {
        let mut validation = rustls::RootCertStore::empty();
        validation
            .add(CertificateDer::from(der.clone()))
            .map_err(|source| Error::InvalidRoot { index, source })?;
    }

    // Reuse bakedroots for Mozilla + caller-provided + baked ISRG roots, then
    // add platform roots that are not represented by the Mozilla bundle.
    let mut roots = rustscale_bakedroots::combined_root_store(Some(extra_roots));
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }
    Ok(roots)
}

struct DiagnosticVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    expected_name: Option<ServerName<'static>>,
    expected_sha256: Option<[u8; 32]>,
    hook: Option<DiagnosticHook>,
}

impl fmt::Debug for DiagnosticVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiagnosticVerifier")
            .field("expected_name", &self.expected_name)
            .field("has_expected_sha256", &self.expected_sha256.is_some())
            .field("has_hook", &self.hook.is_some())
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for DiagnosticVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        wire_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let certificate_name = self.expected_name.as_ref().unwrap_or(wire_name);
        let result = self
            .inner
            .verify_server_cert(
                end_entity,
                intermediates,
                certificate_name,
                ocsp_response,
                now,
            )
            .and_then(|verified| {
                if self.expected_sha256.is_some_and(|expected| {
                    let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
                    actual != expected
                }) {
                    Err(CertificateError::Other(rustls::OtherError(Arc::new(
                        CertificatePinMismatch,
                    )))
                    .into())
                } else {
                    Ok(verified)
                }
            });
        if let Some(hook) = &self.hook {
            let failure = result.as_ref().err().and_then(certificate_failure);
            let (self_signed_issuer, block_blame) = if failure.is_some() {
                certificate_diagnostics(end_entity)
            } else {
                (None, None)
            };
            hook(VerificationDiagnostic {
                server_name: wire_name.to_str().into_owned(),
                certificate_name: certificate_name.to_str().into_owned(),
                failure,
                clock_skew: match failure {
                    Some(CertificateFailure::Expired) => Some(ClockSkew::Ahead),
                    Some(CertificateFailure::NotValidYet) => Some(ClockSkew::Behind),
                    _ => None,
                },
                self_signed_issuer,
                block_blame,
            });
        }
        result
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct InsecureForTestsVerifier {
    signatures: Arc<rustls::client::WebPkiServerVerifier>,
}

impl ServerCertVerifier for InsecureForTestsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signatures.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signatures.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signatures.supported_verify_schemes()
    }
}

fn rustls_error_from_io(error: &io::Error) -> Option<&rustls::Error> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<rustls::Error>())
}

fn certificate_failure(error: &rustls::Error) -> Option<CertificateFailure> {
    let rustls::Error::InvalidCertificate(error) = error else {
        return None;
    };
    Some(match error {
        CertificateError::BadEncoding => CertificateFailure::BadEncoding,
        CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
            CertificateFailure::Expired
        }
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
            CertificateFailure::NotValidYet
        }
        CertificateError::UnknownIssuer => CertificateFailure::UnknownIssuer,
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
            CertificateFailure::NameMismatch
        }
        CertificateError::Revoked => CertificateFailure::Revoked,
        CertificateError::BadSignature => CertificateFailure::BadSignature,
        CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. } => {
            CertificateFailure::InvalidPurpose
        }
        CertificateError::Other(error) if error.0.is::<CertificatePinMismatch>() => {
            CertificateFailure::PinMismatch
        }
        _ => CertificateFailure::Other,
    })
}

#[derive(Debug, thiserror::Error)]
#[error("certificate hash does not match the expected SHA-256")]
struct CertificatePinMismatch;

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn certificate_diagnostics(cert: &CertificateDer<'_>) -> (Option<String>, Option<&'static str>) {
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(cert.as_ref()) else {
        return (None, None);
    };
    let issuer = parsed.issuer().to_string();
    let self_signed = (parsed.subject() == parsed.issuer()).then(|| issuer.clone());
    let manufacturer = manufacturer_for(&parsed, &issuer);
    (self_signed, manufacturer)
}

fn manufacturer_for(
    cert: &x509_parser::certificate::X509Certificate<'_>,
    issuer: &str,
) -> Option<&'static str> {
    let issuer = issuer.to_ascii_lowercase();
    let issuer_match = [
        ("aruba", "Aruba Networks"),
        ("cisco", "Cisco"),
        ("fortinet", "Fortinet"),
        ("palo alto networks", "Palo Alto Networks"),
        ("pan-fw", "Palo Alto Networks"),
        ("sophos", "Sophos"),
        ("unifi", "Ubiquiti"),
        ("ubiquiti", "Ubiquiti"),
    ];
    if let Some((_, manufacturer)) = issuer_match
        .iter()
        .find(|(needle, _)| issuer.contains(needle))
    {
        return Some(*manufacturer);
    }

    let emails = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .into_iter()
        .flat_map(|extension| extension.value.general_names.iter())
        .filter_map(|name| match name {
            x509_parser::extensions::GeneralName::RFC822Name(email) => {
                Some(email.to_ascii_lowercase())
            }
            _ => None,
        });
    for email in emails {
        if email.contains("support@fortinet.com") {
            return Some("Fortinet");
        }
        if email.contains("mobile@huawei.com") {
            return Some("Huawei");
        }
    }
    None
}

#[cfg(test)]
mod tests;
