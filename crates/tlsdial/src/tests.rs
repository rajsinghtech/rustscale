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
        key: leaf_key.serialize_der(),
    }
}

fn server_config(certificate: &TestCertificate, alpn: Vec<Vec<u8>>) -> rustls::ServerConfig {
    ensure_ring_provider();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificate.key.clone()));
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.leaf.clone()], key)
        .unwrap();
    config.alpn_protocols = alpn;
    config
}

async fn handshake(
    certificate: &TestCertificate,
    tls_name: &str,
    options: &Config,
    server_alpn: Vec<Vec<u8>>,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config(certificate, server_alpn)));
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        acceptor
            .accept(tcp)
            .await
            .ok()
            .and_then(|tls| tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec))
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls = connect(tcp, tls_name, options).await?;
    let client_alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let server_alpn = server.await.unwrap();
    Ok((client_alpn, server_alpn))
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
async fn separate_sni_and_expected_certificate_name() {
    let certificate = certificate_for("certificate.test", false);
    let options = Config::default()
        .with_extra_roots(std::slice::from_ref(&certificate.root))
        .with_expected_certificate_name("certificate.test");

    handshake(&certificate, "front.test", &options, Vec::new())
        .await
        .unwrap();
}

#[tokio::test]
async fn full_certificate_hash_is_an_additional_constraint() {
    let certificate = certificate_for("pinned.test", false);
    let digest: [u8; 32] = Sha256::digest(certificate.leaf.as_ref()).into();
    let valid = Config::default()
        .with_extra_roots(std::slice::from_ref(&certificate.root))
        .with_expected_certificate_sha256(digest);
    handshake(&certificate, "pinned.test", &valid, Vec::new())
        .await
        .unwrap();

    let invalid = Config::default()
        .with_extra_roots(std::slice::from_ref(&certificate.root))
        .with_expected_certificate_sha256([0; 32]);
    let error = handshake(&certificate, "pinned.test", &invalid, Vec::new())
        .await
        .unwrap_err();
    assert_eq!(
        error.class(),
        ErrorClass::Certificate(CertificateFailure::PinMismatch)
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
    assert_eq!(negotiated, (Some(b"h2".to_vec()), Some(b"h2".to_vec())));
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
}

#[test]
fn trust_store_includes_baked_and_platform_policy() {
    let roots = root_store(&[]).unwrap();
    let baked_and_webpki = rustscale_bakedroots::combined_root_store(None);
    assert!(roots.roots.len() >= baked_and_webpki.roots.len());
}
