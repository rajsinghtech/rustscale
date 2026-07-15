//! Unified outbound TLS policy for rustscale control and DERP clients.
//!
//! This crate is the single place that combines platform, optional caller-
//! provided, and baked ISRG fallback roots; constructs rustls client configs;
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
    /// Insecure test mode was combined with a certificate constraint.
    InsecurePolicyConflict,
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
    UnexpectedCertificate,
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

/// Certificate identity policy, independent of the SNI sent on the wire.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum CertificatePolicy {
    /// Verify the certificate against the SNI name and configured roots.
    #[default]
    ServerName,
    /// Keep the dialed SNI but verify the certificate against this name.
    ExpectedName(String),
    /// Require the exact leaf DER hash and verify its SNI hostname and validity.
    /// The exact pin is its trust anchor, matching upstream DERP pin semantics.
    /// Additional certificates are rejected except for DERP's metadata cert.
    PinnedLeafSha256([u8; 32]),
}

impl CertificatePolicy {
    /// Parse a DERP `CertName`: empty uses SNI, `sha256-raw:<hex>` pins the
    /// exact leaf, and any other value is an alternate certificate name.
    pub fn from_derp_cert_name(cert_name: &str) -> Result<Self, Error> {
        if cert_name.is_empty() {
            return Ok(Self::ServerName);
        }
        if let Some(digest) = cert_name.strip_prefix("sha256-raw:") {
            return parse_sha256(digest).map(Self::PinnedLeafSha256);
        }
        Ok(Self::ExpectedName(cert_name.to_owned()))
    }

    fn is_constrained(&self) -> bool {
        !matches!(self, Self::ServerName)
    }
}

/// Native-root loading diagnostic category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootDiagnosticKind {
    /// The platform root loader reported an error.
    NativeLoad,
    /// A certificate returned by the platform loader could not be added.
    NativeCertificate,
}

/// Non-fatal native-root loading diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootDiagnostic {
    /// Root loading or parsing stage that failed.
    pub kind: RootDiagnosticKind,
    /// Index of the native certificate, when parsing a loaded certificate.
    pub certificate_index: Option<usize>,
    /// Stable, path-free summary of the failure.
    pub message: String,
}

/// Native-root diagnostic callback.
pub type RootDiagnosticHook = Arc<dyn Fn(RootDiagnostic) + Send + Sync>;

/// Shared TLS client policy.
#[derive(Clone)]
pub struct Config {
    extra_roots: Vec<Vec<u8>>,
    alpn_protocols: Vec<Vec<u8>>,
    certificate_policy: CertificatePolicy,
    handshake_timeout: Duration,
    diagnostic_hook: Option<DiagnosticHook>,
    root_diagnostic_hook: Option<RootDiagnosticHook>,
    dangerous_insecure_for_tests: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("extra_root_count", &self.extra_roots.len())
            .field("alpn_protocols", &self.alpn_protocols)
            .field("certificate_policy", &self.certificate_policy)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("has_diagnostic_hook", &self.diagnostic_hook.is_some())
            .field(
                "has_root_diagnostic_hook",
                &self.root_diagnostic_hook.is_some(),
            )
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
            certificate_policy: CertificatePolicy::ServerName,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            diagnostic_hook: None,
            root_diagnostic_hook: None,
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
        self.certificate_policy = CertificatePolicy::ExpectedName(name.into());
        self
    }

    /// Require the exact leaf DER SHA-256 while still validating the SNI name
    /// and validity period. The pin itself is the trust anchor.
    pub fn with_expected_certificate_sha256(mut self, digest: [u8; 32]) -> Self {
        self.certificate_policy = CertificatePolicy::PinnedLeafSha256(digest);
        self
    }

    /// Parse and require a 64-character hexadecimal full-certificate digest.
    pub fn with_expected_certificate_sha256_hex(mut self, digest: &str) -> Result<Self, Error> {
        self.certificate_policy = CertificatePolicy::PinnedLeafSha256(parse_sha256(digest)?);
        Ok(self)
    }

    /// Set a typed certificate policy.
    pub fn with_certificate_policy(mut self, policy: CertificatePolicy) -> Self {
        self.certificate_policy = policy;
        self
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

    /// Observe non-fatal platform root loading and parsing failures.
    pub fn with_root_diagnostic_hook(mut self, hook: RootDiagnosticHook) -> Self {
        self.root_diagnostic_hook = Some(hook);
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
    #[error("insecure test mode cannot be combined with an expected certificate name or pin")]
    InsecurePolicyConflict,
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
            Self::InsecurePolicyConflict => ErrorClass::InsecurePolicyConflict,
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
    client_config_with_roots(options, &SystemRootSource)
}

fn client_config_with_roots(
    options: &Config,
    root_source: &dyn NativeRootSource,
) -> Result<rustls::ClientConfig, Error> {
    ensure_ring_provider();
    for (index, protocol) in options.alpn_protocols.iter().enumerate() {
        if protocol.is_empty() || protocol.len() > u8::MAX as usize {
            return Err(Error::InvalidAlpn { index });
        }
    }
    if options.dangerous_insecure_for_tests && options.certificate_policy.is_constrained() {
        return Err(Error::InsecurePolicyConflict);
    }

    let roots = root_store(options, root_source)?;
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
        let policy = match &options.certificate_policy {
            CertificatePolicy::ExpectedName(name) => {
                CertificatePolicy::ExpectedName(server_name(name)?.to_str().into_owned())
            }
            policy => policy.clone(),
        };
        Arc::new(DiagnosticVerifier {
            inner: verifier,
            policy,
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

struct NativeRoots {
    certs: Vec<CertificateDer<'static>>,
    errors: Vec<String>,
}

trait NativeRootSource {
    fn load(&self) -> NativeRoots;
}

struct SystemRootSource;

impl NativeRootSource for SystemRootSource {
    fn load(&self) -> NativeRoots {
        let loaded = rustls_native_certs::load_native_certs();
        NativeRoots {
            certs: loaded.certs,
            errors: loaded
                .errors
                .into_iter()
                .map(|error| error.to_string())
                .collect(),
        }
    }
}

fn root_store(
    options: &Config,
    source: &dyn NativeRootSource,
) -> Result<rustls::RootCertStore, Error> {
    let mut roots = rustls::RootCertStore::empty();
    let native = source.load();
    for _error in native.errors {
        emit_root_diagnostic(
            options,
            RootDiagnostic {
                kind: RootDiagnosticKind::NativeLoad,
                certificate_index: None,
                // Platform loader errors can contain certificate-store paths.
                // The classified stage is actionable without exposing them.
                message: "platform root loader reported an error".to_owned(),
            },
        );
    }
    for (index, cert) in native.certs.into_iter().enumerate() {
        if roots.add(cert).is_err() {
            emit_root_diagnostic(
                options,
                RootDiagnostic {
                    kind: RootDiagnosticKind::NativeCertificate,
                    certificate_index: Some(index),
                    // Keep diagnostics stable and free of platform details.
                    message: "platform root certificate was invalid".to_owned(),
                },
            );
        }
    }
    for (index, der) in options.extra_roots.iter().enumerate() {
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(|source| Error::InvalidRoot { index, source })?;
    }
    roots
        .roots
        .extend(rustscale_bakedroots::get().roots.iter().cloned());
    Ok(roots)
}

fn emit_root_diagnostic(options: &Config, diagnostic: RootDiagnostic) {
    if let Some(hook) = &options.root_diagnostic_hook {
        hook(diagnostic);
    }
}

struct DiagnosticVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    policy: CertificatePolicy,
    hook: Option<DiagnosticHook>,
}

impl fmt::Debug for DiagnosticVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiagnosticVerifier")
            .field("policy", &self.policy)
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
        let expected_name = match &self.policy {
            CertificatePolicy::ExpectedName(name) => {
                Some(ServerName::try_from(name.as_str()).expect("certificate policy was validated"))
            }
            _ => None,
        };
        let certificate_name = expected_name.as_ref().unwrap_or(wire_name);
        let result = match &self.policy {
            CertificatePolicy::ServerName | CertificatePolicy::ExpectedName(_) => {
                self.inner.verify_server_cert(
                    end_entity,
                    intermediates,
                    certificate_name,
                    ocsp_response,
                    now,
                )
            }
            CertificatePolicy::PinnedLeafSha256(expected) => verify_pinned_leaf(
                end_entity,
                intermediates,
                wire_name,
                ocsp_response,
                now,
                *expected,
            ),
        };
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
        CertificateError::Other(error) if error.0.is::<UnexpectedCertificate>() => {
            CertificateFailure::UnexpectedCertificate
        }
        _ => CertificateFailure::Other,
    })
}

fn verify_pinned_leaf(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    _ocsp_response: &[u8],
    now: UnixTime,
    expected: [u8; 32],
) -> Result<ServerCertVerified, rustls::Error> {
    if is_derp_meta_cert(end_entity) {
        return Err(
            CertificateError::Other(rustls::OtherError(Arc::new(UnexpectedCertificate))).into(),
        );
    }
    let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
    if actual != expected {
        return Err(
            CertificateError::Other(rustls::OtherError(Arc::new(CertificatePinMismatch))).into(),
        );
    }
    if intermediates.iter().any(|cert| !is_derp_meta_cert(cert)) {
        return Err(
            CertificateError::Other(rustls::OtherError(Arc::new(UnexpectedCertificate))).into(),
        );
    }

    // The exact pin replaces chain validation, but not certificate parsing,
    // SNI hostname/IP-SAN matching, validity checks, or TLS handshake
    // signature verification. DERP metadata certs are deliberately ignored.
    let parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;
    rustls::client::verify_server_name(&parsed, server_name)?;
    let (_, parsed) = x509_parser::parse_x509_certificate(end_entity.as_ref())
        .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
    let now = i64::try_from(now.as_secs())
        .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::Expired))?;
    if now < parsed.validity().not_before.timestamp() {
        return Err(CertificateError::NotValidYet.into());
    }
    if now > parsed.validity().not_after.timestamp() {
        return Err(CertificateError::Expired.into());
    }
    Ok(ServerCertVerified::assertion())
}

fn is_derp_meta_cert(cert: &CertificateDer<'_>) -> bool {
    const COMMON_NAME_PREFIX: &str = "derpkey";

    x509_parser::parse_x509_certificate(cert.as_ref())
        .ok()
        .is_some_and(|(_, cert)| {
            cert.subject().iter_common_name().any(|name| {
                name.as_str()
                    .is_ok_and(|name| name.starts_with(COMMON_NAME_PREFIX))
            })
        })
}

#[derive(Debug, thiserror::Error)]
#[error("certificate hash does not match the expected SHA-256")]
struct CertificatePinMismatch;

#[derive(Debug, thiserror::Error)]
#[error("unexpected additional certificate presented with an exact leaf pin")]
struct UnexpectedCertificate;

fn parse_sha256(digest: &str) -> Result<[u8; 32], Error> {
    if digest.len() != 64 {
        return Err(Error::InvalidCertificatePin);
    }
    let mut decoded = [0u8; 32];
    for (index, chunk) in digest.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0]).ok_or(Error::InvalidCertificatePin)?;
        let low = hex_nibble(chunk[1]).ok_or(Error::InvalidCertificatePin)?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

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
