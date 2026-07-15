use std::sync::{Arc, Mutex};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use super::*;

struct TestCertificate {
    root: Vec<u8>,
    leaf: CertificateDer<'static>,
    intermediates: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
}

fn certificate_for(name: &str, future: bool) -> TestCertificate {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "rustscale tlsdial test root");
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let mut leaf_params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, name);
    leaf_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    if future {
        leaf_params.not_before = rcgen::date_time_ymd(2100, 1, 1);
        leaf_params.not_after = rcgen::date_time_ymd(2101, 1, 1);
    }
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

    TestCertificate {
        root: ca.der().to_vec(),
        leaf: leaf.der().clone(),
        intermediates: Vec::new(),
        key: leaf_key.serialize_der(),
    }
}

fn server_config(certificate: &TestCertificate, alpn: Vec<Vec<u8>>) -> rustls::ServerConfig {
    ensure_ring_provider();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificate.key.clone()));
    let chain = std::iter::once(certificate.leaf.clone())
        .chain(certificate.intermediates.iter().cloned())
        .collect();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = alpn;
    config
}

async fn handshake(
    certificate: &TestCertificate,
    tls_name: &str,
    options: &Config,
    server_alpn: Vec<Vec<u8>>,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>, Option<String>), Error> {
    let config = client_config(options)?;
    handshake_with_client_config(certificate, tls_name, config, server_alpn).await
}

async fn handshake_with_client_config(
    certificate: &TestCertificate,
    tls_name: &str,
    config: rustls::ClientConfig,
    server_alpn: Vec<Vec<u8>>,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>, Option<String>), Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(certificate, server_alpn)));
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        acceptor.accept(tcp).await.ok().map(|tls| {
            let connection = &tls.get_ref().1;
            (
                connection.alpn_protocol().map(<[u8]>::to_vec),
                connection.server_name().map(str::to_owned),
            )
        })
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tls = connector
        .connect(server_name(tls_name)?, tcp)
        .await
        .map_err(Error::Handshake)?;
    let client_alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let (server_alpn, seen_sni) = server.await.unwrap().unwrap_or_default();
    Ok((client_alpn, server_alpn, seen_sni))
}

#[tokio::test]
async fn extra_root_and_hostname_verification() {
    let certificate = certificate_for("control.test", false);
    let options = Config::default().with_extra_roots(std::slice::from_ref(&certificate.root));

    handshake(&certificate, "control.test", &options, Vec::new())
        .await
        .unwrap();

    let error = handshake(&certificate, "other.test", &options, Vec::new())
        .await
        .unwrap_err();
    assert_eq!(
        error.class(),
        ErrorClass::Certificate(CertificateFailure::NameMismatch)
    );
}

#[tokio::test]
async fn untrusted_root_is_classified() {
    let certificate = certificate_for("derp.test", false);
    let error = handshake(&certificate, "derp.test", &Config::default(), Vec::new())
        .await
        .unwrap_err();
    assert_eq!(
        error.class(),
        ErrorClass::Certificate(CertificateFailure::UnknownIssuer)
    );
}

#[tokio::test]
async fn ip_literals_never_imply_insecure_verification() {
    for ip in ["127.0.0.1", "10.0.0.1", "203.0.113.1"] {
        let certificate = self_signed_certificate(ip, false);
        let error = handshake(&certificate, ip, &Config::default(), Vec::new())
            .await
            .unwrap_err();
        assert_eq!(
            error.class(),
            ErrorClass::Certificate(CertificateFailure::UnknownIssuer),
            "IP literal {ip} unexpectedly bypassed certificate verification"
        );
    }
}

#[tokio::test]
async fn insecure_test_mode_requires_an_explicit_option() {
    let certificate = self_signed_certificate("explicit-test.test", false);
    let result = handshake(
        &certificate,
        "explicit-test.test",
        &Config::default().dangerous_insecure_for_tests(true),
        Vec::new(),
    )
    .await
    .unwrap();
    assert_eq!(result.2.as_deref(), Some("explicit-test.test"));
}

#[tokio::test]
async fn separate_sni_and_expected_certificate_name() {
    let certificate = certificate_for("certificate.test", false);
    let diagnostics = Arc::new(Mutex::new(Vec::new()));
    let hook: DiagnosticHook = {
        let diagnostics = diagnostics.clone();
        Arc::new(move |diagnostic| diagnostics.lock().unwrap().push(diagnostic))
    };
    let options = Config::default()
        .with_extra_roots(std::slice::from_ref(&certificate.root))
        .with_expected_certificate_name("certificate.test")
        .with_diagnostic_hook(hook);

    let result = handshake(&certificate, "front.test", &options, Vec::new())
        .await
        .unwrap();
    assert_eq!(result.2.as_deref(), Some("front.test"));
    {
        let diagnostics = diagnostics.lock().unwrap();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].server_name, "front.test");
        assert_eq!(diagnostics[0].certificate_name, "certificate.test");
        assert_eq!(diagnostics[0].failure, None);
    }

    let wrong_name = Config::default()
        .with_extra_roots(std::slice::from_ref(&certificate.root))
        .with_expected_certificate_name("wrong.test");
    let error = handshake(&certificate, "front.test", &wrong_name, Vec::new())
        .await
        .unwrap_err();
    assert_eq!(
        error.class(),
        ErrorClass::Certificate(CertificateFailure::NameMismatch)
    );
}

#[test]
fn derp_cert_name_parses_typed_policies() {
    assert_eq!(
        CertificatePolicy::from_derp_cert_name("").unwrap(),
        CertificatePolicy::ServerName
    );
    assert_eq!(
        CertificatePolicy::from_derp_cert_name("certificate.test").unwrap(),
        CertificatePolicy::ExpectedName("certificate.test".to_owned())
    );
    assert_eq!(
        CertificatePolicy::from_derp_cert_name(&format!("sha256-raw:{}", "ab".repeat(32))).unwrap(),
        CertificatePolicy::PinnedLeafSha256([0xab; 32])
    );
}

fn self_signed_certificate(name: &str, future: bool) -> TestCertificate {
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    if future {
        params.not_before = rcgen::date_time_ymd(2100, 1, 1);
        params.not_after = rcgen::date_time_ymd(2101, 1, 1);
    }
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    TestCertificate {
        root: cert.der().to_vec(),
        leaf: cert.der().clone(),
        intermediates: Vec::new(),
        key: key.serialize_der(),
    }
}

fn expired_self_signed_certificate(name: &str) -> TestCertificate {
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params.not_before = rcgen::date_time_ymd(2000, 1, 1);
    params.not_after = rcgen::date_time_ymd(2001, 1, 1);
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    TestCertificate {
        root: cert.der().to_vec(),
        leaf: cert.der().clone(),
        intermediates: Vec::new(),
        key: key.serialize_der(),
    }
}

#[tokio::test]
async fn exact_leaf_pin_is_its_own_trust_anchor_and_retains_sni() {
    let certificate = certificate_for("pinned.test", false);
    let digest: [u8; 32] = Sha256::digest(certificate.leaf.as_ref()).into();
    let policy = Config::default().with_expected_certificate_sha256(digest);

    let result = handshake(&certificate, "pinned.test", &policy, Vec::new())
        .await
        .unwrap();
    assert_eq!(result.2.as_deref(), Some("pinned.test"));
}

#[tokio::test]
async fn exact_leaf_pin_checks_hash_hostname_and_validity() {
    let certificate = self_signed_certificate("pinned.test", false);
    let digest: [u8; 32] = Sha256::digest(certificate.leaf.as_ref()).into();
    let valid = Config::default().with_expected_certificate_sha256(digest);

    let mismatch = Config::default().with_expected_certificate_sha256([0; 32]);
    let error = handshake(&certificate, "pinned.test", &mismatch, Vec::new())
        .await
        .unwrap_err();
    assert_eq!(
        error.class(),
        ErrorClass::Certificate(CertificateFailure::PinMismatch)
    );

    let error = handshake(&certificate, "wrong.test", &valid, Vec::new())
        .await
        .unwrap_err();
    assert_eq!(
        error.class(),
        ErrorClass::Certificate(CertificateFailure::NameMismatch)
    );

    for (certificate, failure) in [
        (
            self_signed_certificate("time-pin.test", true),
            CertificateFailure::NotValidYet,
        ),
        (
            expired_self_signed_certificate("time-pin.test"),
            CertificateFailure::Expired,
        ),
    ] {
        let digest: [u8; 32] = Sha256::digest(certificate.leaf.as_ref()).into();
        let policy = Config::default().with_expected_certificate_sha256(digest);
        let error = handshake(&certificate, "time-pin.test", &policy, Vec::new())
            .await
            .unwrap_err();
        assert_eq!(error.class(), ErrorClass::Certificate(failure));
    }
}

#[tokio::test]
async fn exact_leaf_pin_allows_only_derp_metadata_after_leaf() {
    let metadata = self_signed_certificate("derpkey0123456789", false);
    let metadata_digest: [u8; 32] = Sha256::digest(metadata.leaf.as_ref()).into();
    let error = handshake(
        &metadata,
        "derpkey0123456789",
        &Config::default().with_expected_certificate_sha256(metadata_digest),
        Vec::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.class(),
        ErrorClass::Certificate(CertificateFailure::UnexpectedCertificate)
    );

    let mut certificate = self_signed_certificate("pinned.test", false);
    certificate.intermediates.push(metadata.leaf);
    let digest: [u8; 32] = Sha256::digest(certificate.leaf.as_ref()).into();
    let policy = Config::default().with_expected_certificate_sha256(digest);
    handshake(&certificate, "pinned.test", &policy, Vec::new())
        .await
        .unwrap();

    let extra = self_signed_certificate("not-metadata.test", false);
    certificate.intermediates.push(extra.leaf);
    let error = handshake(&certificate, "pinned.test", &policy, Vec::new())
        .await
        .unwrap_err();
    assert_eq!(
        error.class(),
        ErrorClass::Certificate(CertificateFailure::UnexpectedCertificate)
    );
}

#[tokio::test]
async fn alpn_is_negotiated() {
    let certificate = certificate_for("derp.test", false);
    let options = Config::default()
        .with_extra_roots(std::slice::from_ref(&certificate.root))
        .with_alpn_protocols(vec![b"h2".to_vec()]);
    let negotiated = handshake(&certificate, "derp.test", &options, vec![b"h2".to_vec()])
        .await
        .unwrap();
    assert_eq!(negotiated.0, Some(b"h2".to_vec()));
    assert_eq!(negotiated.1, Some(b"h2".to_vec()));
}

#[tokio::test]
async fn handshake_timeout_is_classified() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_tcp, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let options = Config::default().with_handshake_timeout(Duration::from_millis(20));
    let error = connect(tcp, "timeout.test", &options).await.unwrap_err();
    assert_eq!(error.class(), ErrorClass::Timeout);
    server.abort();
}

#[tokio::test]
async fn future_certificate_reports_clock_skew() {
    let certificate = certificate_for("future.test", true);
    let diagnostics = Arc::new(Mutex::new(Vec::new()));
    let hook: DiagnosticHook = {
        let diagnostics = diagnostics.clone();
        Arc::new(move |diagnostic| diagnostics.lock().unwrap().push(diagnostic))
    };
    let options = Config::default()
        .with_extra_roots(std::slice::from_ref(&certificate.root))
        .with_diagnostic_hook(hook);

    let error = handshake(&certificate, "future.test", &options, Vec::new())
        .await
        .unwrap_err();
    assert_eq!(
        error.class(),
        ErrorClass::Certificate(CertificateFailure::NotValidYet)
    );
    let diagnostics = diagnostics.lock().unwrap();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].clock_skew, Some(ClockSkew::Behind));
}

#[test]
fn block_blame_and_self_signed_diagnostics() {
    let mut params = CertificateParams::new(vec!["blocked.test".to_owned()]).unwrap();
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Fortinet TLS interception");
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();

    let (issuer, manufacturer) = certificate_diagnostics(cert.der());
    assert!(issuer.is_some());
    assert_eq!(manufacturer, Some("Fortinet"));
}

#[test]
fn malformed_inputs_have_stable_classes() {
    let invalid_name = server_name("not a server name").unwrap_err();
    assert_eq!(invalid_name.class(), ErrorClass::InvalidServerName);

    let invalid_root =
        client_config(&Config::default().with_extra_roots(&[vec![1, 2, 3]])).unwrap_err();
    assert_eq!(invalid_root.class(), ErrorClass::InvalidRoot);

    let invalid_alpn =
        client_config(&Config::default().with_alpn_protocols(vec![Vec::new()])).unwrap_err();
    assert_eq!(invalid_alpn.class(), ErrorClass::InvalidAlpn);

    let invalid_pin = Config::default()
        .with_expected_certificate_sha256_hex("not-a-hash")
        .unwrap_err();
    assert_eq!(invalid_pin.class(), ErrorClass::InvalidCertificatePin);
    for cert_name in [
        "sha256-raw:nope".to_owned(),
        format!("sha256-raw:{}g", "0".repeat(63)),
    ] {
        let error = CertificatePolicy::from_derp_cert_name(&cert_name).unwrap_err();
        assert_eq!(error.class(), ErrorClass::InvalidCertificatePin);
    }

    let invalid_expected_name =
        client_config(&Config::default().with_expected_certificate_name("not a server name"))
            .unwrap_err();
    assert_eq!(invalid_expected_name.class(), ErrorClass::InvalidServerName);

    for policy in [
        CertificatePolicy::ExpectedName("expected.test".to_owned()),
        CertificatePolicy::PinnedLeafSha256([0; 32]),
    ] {
        let conflict = client_config(
            &Config::default()
                .with_certificate_policy(policy)
                .dangerous_insecure_for_tests(true),
        )
        .unwrap_err();
        assert_eq!(conflict.class(), ErrorClass::InsecurePolicyConflict);
    }
    client_config(&Config::default().dangerous_insecure_for_tests(true)).unwrap();
}

#[derive(Clone)]
struct FakeRootSource {
    certs: Vec<CertificateDer<'static>>,
    errors: Vec<String>,
}

impl NativeRootSource for FakeRootSource {
    fn load(&self) -> NativeRoots {
        NativeRoots {
            certs: self.certs.clone(),
            errors: self.errors.clone(),
        }
    }
}

#[tokio::test]
async fn mocked_native_roots_exclude_mozilla_and_preserve_fallbacks() {
    let empty = FakeRootSource {
        certs: Vec::new(),
        errors: Vec::new(),
    };
    let roots = root_store(&Config::default(), &empty).unwrap();
    assert_eq!(roots.roots.len(), rustscale_bakedroots::get().roots.len());

    let native_certificate = certificate_for("native.test", false);
    let extra_certificate = certificate_for("extra.test", false);
    let native = FakeRootSource {
        certs: vec![CertificateDer::from(native_certificate.root.clone())],
        errors: Vec::new(),
    };
    let options = Config::default().with_extra_roots(std::slice::from_ref(&extra_certificate.root));
    let roots = root_store(&options, &native).unwrap();
    assert_eq!(
        roots.roots.len(),
        rustscale_bakedroots::get().roots.len() + 2
    );

    let native_config = client_config_with_roots(&Config::default(), &native).unwrap();
    handshake_with_client_config(
        &native_certificate,
        "native.test",
        native_config,
        Vec::new(),
    )
    .await
    .unwrap();
    let extra_config = client_config_with_roots(&options, &empty).unwrap();
    handshake_with_client_config(&extra_certificate, "extra.test", extra_config, Vec::new())
        .await
        .unwrap();

    let diagnostics = Arc::new(Mutex::new(Vec::new()));
    let hook: RootDiagnosticHook = {
        let diagnostics = diagnostics.clone();
        Arc::new(move |diagnostic| diagnostics.lock().unwrap().push(diagnostic))
    };
    let broken = FakeRootSource {
        certs: vec![CertificateDer::from(vec![1, 2, 3])],
        errors: vec!["failed to read /private/root-store.pem".to_owned()],
    };
    root_store(&Config::default().with_root_diagnostic_hook(hook), &broken).unwrap();
    let diagnostics = diagnostics.lock().unwrap();
    assert_eq!(diagnostics.len(), 2);
    assert_eq!(diagnostics[0].kind, RootDiagnosticKind::NativeLoad);
    assert_eq!(
        diagnostics[0].message,
        "platform root loader reported an error"
    );
    assert!(!diagnostics[0].message.contains("/private/"));
    assert_eq!(diagnostics[1].kind, RootDiagnosticKind::NativeCertificate);
    assert_eq!(diagnostics[1].certificate_index, Some(0));
    assert_eq!(
        diagnostics[1].message,
        "platform root certificate was invalid"
    );
}
