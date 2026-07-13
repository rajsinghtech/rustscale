//! Embedded ISRG Root X1 and X2 certificates — a fallback trust store for
//! environments where the system certificate pool is empty or missing these
//! roots (containers, minimal Linux, ancient devices).
//!
//! Mirrors Go's `net/bakedroots` package. The 3-tier verification waterfall
//! (system → extra → baked) cannot be implemented exactly in rustls 0.23 (no
//! `VerifyConnection` hook), so [`combined_root_store`] pre-constructs a single
//! `RootCertStore` concatenating webpki roots, optional extra roots, and the
//! baked ISRG roots.

use std::sync::OnceLock;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

/// Decode a PEM-encoded certificate to DER bytes.
fn pem_to_der(pem: &str) -> Vec<u8> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    BASE64
        .decode(b64.as_bytes())
        .expect("baked ISRG root PEMs are valid base64")
}

/// ISRG Root X1 PEM (RSA 4096-bit, SHA-256, valid 2015-06-04 to 2035-06-04).
/// Subject: C=US, O=Internet Security Research Group, CN=ISRG Root X1
#[cfg(feature = "bakedroots")]
const ISRG_ROOT_X1_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----";

/// ISRG Root X2 PEM (ECDSA P-384, valid 2020-09-04 to 2035-09-04).
/// Subject: O=Internet Security Research Group, CN=ISRG Root X2
#[cfg(feature = "bakedroots")]
const ISRG_ROOT_X2_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----";

/// Parse a PEM-encoded certificate and add it to a `RootCertStore`.
#[cfg(feature = "bakedroots")]
fn add_pem_to_store(store: &mut rustls::RootCertStore, pem: &str) {
    let der = pem_to_der(pem);
    store
        .add(rustls::pki_types::CertificateDer::from(der))
        .expect("baked ISRG root certs are valid");
}

/// Returns a `RootCertStore` containing the two baked-in ISRG roots (X1 and X2).
/// Lazily initialized on first call.
///
/// When the `bakedroots` Cargo feature is disabled, returns an empty store.
pub fn get() -> &'static rustls::RootCertStore {
    static STORE: OnceLock<rustls::RootCertStore> = OnceLock::new();
    STORE.get_or_init(|| {
        let mut store = rustls::RootCertStore::empty();
        #[cfg(feature = "bakedroots")]
        {
            add_pem_to_store(&mut store, ISRG_ROOT_X1_PEM);
            add_pem_to_store(&mut store, ISRG_ROOT_X2_PEM);
        }
        store
    })
}

/// Build a `RootCertStore` that concatenates webpki roots, optional extra
/// certs, and baked ISRG roots — the 3-tier strategy as a single store.
///
/// `extra_certs` are DER-encoded certificates (e.g. user-installed CAs from
/// `tsnet::ServerBuilder::extra_root_certs`).
pub fn combined_root_store(extra_certs: Option<&[Vec<u8>]>) -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    store
        .roots
        .extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(extras) = extra_certs {
        for der in extras {
            store
                .add(rustls::pki_types::CertificateDer::from(der.clone()))
                .expect("extra root cert should be valid DER");
        }
    }
    store.roots.extend(get().roots.iter().cloned());
    store
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_two_roots() {
        let store = get();
        assert_eq!(
            store.roots.len(),
            2,
            "baked store should have exactly 2 roots"
        );
    }

    #[test]
    fn combined_root_store_no_extras_includes_webpki_and_baked() {
        let store = combined_root_store(None);
        let webpki_count = webpki_roots::TLS_SERVER_ROOTS.len();
        let baked_count = get().roots.len();
        assert!(
            store.roots.len() >= webpki_count + baked_count,
            "combined store should have at least webpki ({webpki_count}) + baked ({baked_count}) roots, got {}",
            store.roots.len(),
        );
    }

    #[test]
    fn combined_root_store_with_extra_includes_all_three() {
        let test_der = pem_to_der(ISRG_ROOT_X1_PEM);
        let store = combined_root_store(Some(std::slice::from_ref(&test_der)));
        let webpki_count = webpki_roots::TLS_SERVER_ROOTS.len();
        let baked_count = get().roots.len();
        assert!(
            store.roots.len() > webpki_count + baked_count,
            "combined store with extra should have more than webpki ({webpki_count}) + baked ({baked_count}) roots, got {}",
            store.roots.len(),
        );
    }

    #[test]
    fn baked_roots_are_distinct_anchors() {
        let store = get();
        let subjects: Vec<_> = store.roots.iter().map(|a| a.subject.len()).collect();
        assert_eq!(subjects.len(), 2);
        assert_ne!(store.roots[0].subject, store.roots[1].subject);
    }
}
