//! UPnP IGD client: SSDP discovery, root-desc fetch, and SOAP
//! AddPortMapping / DeletePortMapping / GetExternalIPAddress.
//!
//! Discovery sends M-SEARCH packets to the gateway's unicast address and the
//! SSDP multicast address (239.255.255.250:1900). Responses are HTTP-over-UDP
//! with `LOCATION`, `SERVER`, and `USN` headers. We fetch the root-desc XML
//! from the LOCATION URL, find the best WAN connection service, and make SOAP
//! calls to create/delete mappings and get the external IP.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::http;
use crate::xml;

/// A parsed UPnP SSDP discovery response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpnpDiscoResponse {
    pub location: String,
    #[allow(dead_code)]
    pub server: String,
    #[allow(dead_code)]
    pub usn: String,
}

/// The M-SEARCH discovery packet (ST: ssdp:all).
pub(crate) fn ssdp_packet() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\n\
      HOST: 239.255.255.250:1900\r\n\
      ST: ssdp:all\r\n\
      MAN: \"ssdp:discover\"\r\n\
      MX: 2\r\n\r\n"
        .to_vec()
}

/// The M-SEARCH discovery packet targeting InternetGatewayDevice:1
/// specifically (some devices only respond to this, not ssdp:all).
pub(crate) fn ssdp_igd_packet() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\n\
      HOST: 239.255.255.250:1900\r\n\
      ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
      MAN: \"ssdp:discover\"\r\n\
      MX: 2\r\n\r\n"
        .to_vec()
}

/// Parse a single SSDP HTTP-over-UDP response.
pub(crate) fn parse_ssdp_response(body: &[u8]) -> Option<UpnpDiscoResponse> {
    let text = std::str::from_utf8(body).ok()?;
    let mut location = None;
    let mut server = String::new();
    let mut usn = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        // Case-insensitive header name match, but preserve the original
        // case of the value (URLs are case-sensitive).
        let lower = trimmed.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("location:") {
            // Extract the value from the original (non-lowercased) string.
            let value_start = trimmed.len() - rest.len();
            location = Some(trimmed[value_start..].trim().to_string());
        } else if let Some(rest) = lower.strip_prefix("server:") {
            let value_start = trimmed.len() - rest.len();
            server = trimmed[value_start..].trim().to_string();
        } else if let Some(rest) = lower.strip_prefix("usn:") {
            let value_start = trimmed.len() - rest.len();
            usn = trimmed[value_start..].trim().to_string();
        }
    }
    if !text.contains("InternetGatewayDevice") {
        return None;
    }
    Some(UpnpDiscoResponse {
        location: location?,
        server,
        usn,
    })
}

/// Whether a UDP packet looks like a UPnP IGD discovery response (contains
/// the `InternetGatewayDevice` substring). Used to accept responses from
/// non-standard ports (some devices reply from a different port than 1900).
pub(crate) fn looks_like_igd_response(pkt: &[u8]) -> bool {
    pkt.windows(23).any(|w| w == b"InternetGatewayDevice")
}

/// Deduplicate and sort UPnP discovery responses. Prefers
/// `InternetGatewayDevice:2` over `:1` (reverse USN sort), and compacts
/// responses with the same Location+Server (keeping the first/highest USN).
pub(crate) fn process_responses(mut responses: Vec<UpnpDiscoResponse>) -> Vec<UpnpDiscoResponse> {
    // Sort by USN in reverse so :2 sorts before :1.
    responses.sort_by_key(|r| std::cmp::Reverse(r.usn.clone()));
    // Compact by (location, server).
    responses.dedup_by(|a, b| a.location == b.location && a.server == b.server);
    responses
}

/// A selected UPnP IGD service ready for SOAP calls.
#[derive(Debug, Clone)]
pub(crate) struct UpnpService {
    /// The full control URL (absolute, e.g. http://192.168.1.1:5000/ctl/IPConn).
    pub control_url: String,
    /// The IGD service kind (0=WANIP2, 1=WANIP1, 2=WANPPP, 3=legacy).
    pub kind: u8,
}

/// Fetch the root-desc XML from a discovery response's LOCATION URL and
/// select the best WAN connection service. Returns `None` if no supported
/// service is found.
pub(crate) async fn fetch_and_select_service(
    location: &str,
    deadline: Duration,
) -> Option<UpnpService> {
    let xml_body = http::http_get(location, deadline).await.ok()?;
    let services = xml::extract_services(&xml_body);

    // Find the best (lowest kind) IGD service.
    let best = services
        .iter()
        .filter_map(|s| xml::igd_service_kind(&s.service_type).map(|k| (k, s)))
        .min_by_key(|(k, _)| *k)?;

    // Resolve the control URL: if it's relative, join it with the location's
    // origin.
    let control_url = resolve_url(location, &best.1.control_url);
    Some(UpnpService {
        control_url,
        kind: best.0,
    })
}

/// Resolve a possibly-relative URL against a base URL's origin.
fn resolve_url(base: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    // Extract origin from base: http://host:port
    let origin_end = base[7..].find('/').map_or(base.len(), |i| i + 7);
    let origin = &base[..origin_end];
    if path.starts_with('/') {
        format!("{origin}{path}")
    } else {
        format!("{origin}/{path}")
    }
}

/// Create a UDP port mapping via SOAP AddPortMapping.
///
/// Returns the external port assigned by the router. If `external_port` is
/// <1024, a random port >=1024 is chosen (some routers reject privileged
/// ports). If the router returns error 725 (OnlyPermanentLeasesSupported) or
/// 402 (InvalidArgs), retries with a permanent lease (lifetime=0).
pub(crate) async fn add_port_mapping(
    svc: &UpnpService,
    internal_client: &str,
    internal_port: u16,
    external_port: u16,
    lease_duration: u32,
    deadline: Duration,
) -> Result<u16, std::io::Error> {
    let port = if external_port < 1024 {
        random_port()
    } else {
        external_port
    };

    let service_type = xml::soap_service_type(svc.kind);
    let soap_action = format!("{service_type}#AddPortMapping");

    // First attempt with the requested lease duration.
    let body = build_add_port_mapping_soap(
        service_type,
        "",
        port,
        "UDP",
        internal_port,
        internal_client,
        true,
        "rustscale-portmap",
        lease_duration,
    );
    let (status, resp) = http::http_post_soap(
        &svc.control_url,
        &soap_action,
        SOAP_CONTENT_TYPE,
        &body,
        deadline,
    )
    .await?;

    if status == 200 && !is_soap_fault(&resp) {
        return Ok(port);
    }

    // Check for UPnP error codes 725 or 402 — retry with permanent lease.
    if let Some(code) = extract_upnp_error_code(&resp) {
        if code == 725 || code == 402 {
            let body = build_add_port_mapping_soap(
                service_type,
                "",
                port,
                "UDP",
                internal_port,
                internal_client,
                true,
                "rustscale-portmap",
                0,
            );
            let (status, resp) = http::http_post_soap(
                &svc.control_url,
                &soap_action,
                SOAP_CONTENT_TYPE,
                &body,
                deadline,
            )
            .await?;
            if status == 200 && !is_soap_fault(&resp) {
                return Ok(port);
            }
        }
    }

    Err(std::io::Error::other(format!(
        "AddPortMapping failed (status={status})"
    )))
}

/// Delete a UDP port mapping via SOAP DeletePortMapping.
pub(crate) async fn delete_port_mapping(svc: &UpnpService, external_port: u16, deadline: Duration) {
    let service_type = xml::soap_service_type(svc.kind);
    let soap_action = format!("{service_type}#DeletePortMapping");
    let body = format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:DeletePortMapping xmlns:u="{service_type}">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>{external_port}</NewExternalPort>
      <NewProtocol>UDP</NewProtocol>
    </u:DeletePortMapping>
  </s:Body>
</s:Envelope>"#
    );
    let _ = http::http_post_soap(
        &svc.control_url,
        &soap_action,
        SOAP_CONTENT_TYPE,
        &body,
        deadline,
    )
    .await;
}

/// Get the external IP address via SOAP GetExternalIPAddress.
pub(crate) async fn get_external_ip(
    svc: &UpnpService,
    deadline: Duration,
) -> Result<Ipv4Addr, std::io::Error> {
    let service_type = xml::soap_service_type(svc.kind);
    let soap_action = format!("{service_type}#GetExternalIPAddress");
    let body = format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddress xmlns:u="{service_type}">
    </u:GetExternalIPAddress>
  </s:Body>
</s:Envelope>"#
    );
    let (status, resp) = http::http_post_soap(
        &svc.control_url,
        &soap_action,
        SOAP_CONTENT_TYPE,
        &body,
        deadline,
    )
    .await?;
    if status != 200 {
        return Err(std::io::Error::other(format!(
            "GetExternalIPAddress failed (status={status})"
        )));
    }
    let ip_str = extract_tag_text(&resp, "NewExternalIPAddress").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no NewExternalIPAddress in response",
        )
    })?;
    let ip: Ipv4Addr = ip_str.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid external IP: {ip_str}"),
        )
    })?;
    if ip.is_unspecified() || ip.is_loopback() {
        return Err(std::io::Error::other(format!(
            "UPnP returned invalid external IP: {ip}"
        )));
    }
    Ok(ip)
}

/// SOAP content type for UPnP.
const SOAP_CONTENT_TYPE: &str = "text/xml; charset=\"utf-8\"";

/// Build the SOAP envelope for AddPortMapping.
fn build_add_port_mapping_soap(
    service_type: &str,
    remote_host: &str,
    external_port: u16,
    protocol: &str,
    internal_port: u16,
    internal_client: &str,
    enabled: bool,
    description: &str,
    lease_duration: u32,
) -> String {
    let enabled_str = if enabled { "1" } else { "0" };
    format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMapping xmlns:u="{service_type}">
      <NewRemoteHost>{remote_host}</NewRemoteHost>
      <NewExternalPort>{external_port}</NewExternalPort>
      <NewProtocol>{protocol}</NewProtocol>
      <NewInternalPort>{internal_port}</NewInternalPort>
      <NewInternalClient>{internal_client}</NewInternalClient>
      <NewEnabled>{enabled_str}</NewEnabled>
      <NewPortMappingDescription>{description}</NewPortMappingDescription>
      <NewLeaseDuration>{lease_duration}</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>"#
    )
}

/// Whether a SOAP response body contains a Fault element.
fn is_soap_fault(body: &str) -> bool {
    body.contains("<s:Fault>") || body.contains("<SOAP:Fault>") || body.contains("<Fault>")
}

/// Extract the UPnP error code from a SOAP fault response.
fn extract_upnp_error_code(body: &str) -> Option<u32> {
    let code_str = extract_tag_text(body, "errorCode")?;
    code_str.parse().ok()
}

/// Extract the text content of an XML tag from a string (first occurrence).
fn extract_tag_text(s: &str, tag: &str) -> Option<String> {
    // Handle both namespaced and bare tags.
    for open in [
        format!("<{tag}>"),
        format!("<u:{tag}>"),
        format!("<m:{tag}>"),
    ] {
        if let Some(start) = s.find(&open) {
            let text_start = start + open.len();
            let close_patterns = [
                format!("</{tag}>"),
                format!("</u:{tag}>"),
                format!("</m:{tag}>"),
            ];
            for close in &close_patterns {
                if let Some(rel) = s[text_start..].find(close.as_str()) {
                    return Some(s[text_start..text_start + rel].trim().to_string());
                }
            }
        }
    }
    None
}

/// Pick a random external port in [1024, 65535].
fn random_port() -> u16 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen_range(1024..=65535)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOGLE_WIFI_DISCO: &str = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nUSN: uuid:a9708184-a6c0-413a-bbac-11bcf7e30ece::urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nEXT:\r\nSERVER: Linux/5.4.0-1034-gcp UPnP/1.1 MiniUPnPd/1.9\r\nLOCATION: http://192.168.86.1:5000/rootDesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: 1\r\nBOOTID.UPNP.ORG: 1\r\nCONFIGID.UPNP.ORG: 1337\r\n\r\n";

    const PFSENSE_DISCO: &str = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nEXT:\r\nSERVER: FreeBSD/12.2-STABLE UPnP/1.1 MiniUPnPd/2.2.1\r\nLOCATION: http://192.168.1.1:2189/rootDesc.xml\r\n\r\n";

    #[test]
    fn parse_google_wifi_disco() {
        let resp = parse_ssdp_response(GOOGLE_WIFI_DISCO.as_bytes()).expect("parse");
        assert_eq!(resp.location, "http://192.168.86.1:5000/rootDesc.xml");
        assert_eq!(resp.server, "Linux/5.4.0-1034-gcp UPnP/1.1 MiniUPnPd/1.9");
        assert_eq!(
            resp.usn,
            "uuid:a9708184-a6c0-413a-bbac-11bcf7e30ece::urn:schemas-upnp-org:device:InternetGatewayDevice:2"
        );
    }

    #[test]
    fn parse_pfsense_disco() {
        let resp = parse_ssdp_response(PFSENSE_DISCO.as_bytes()).expect("parse");
        assert_eq!(resp.location, "http://192.168.1.1:2189/rootDesc.xml");
        assert_eq!(resp.server, "FreeBSD/12.2-STABLE UPnP/1.1 MiniUPnPd/2.2.1");
    }

    #[test]
    fn parse_rejects_non_igd() {
        let non_igd = "HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\nLOCATION: http://192.168.1.5:5000/desc.xml\r\n\r\n";
        assert!(parse_ssdp_response(non_igd.as_bytes()).is_none());
    }

    #[test]
    fn process_responses_dedupes_and_sorts() {
        let responses = vec![
            UpnpDiscoResponse {
                location: "http://192.168.1.1:2828/control.xml".to_string(),
                server: "Test".to_string(),
                usn: "uuid:foo::urn:schemas-upnp-org:device:InternetGatewayDevice:1".to_string(),
            },
            UpnpDiscoResponse {
                location: "http://192.168.1.1:2828/control.xml".to_string(),
                server: "Test".to_string(),
                usn: "uuid:foo::urn:schemas-upnp-org:device:InternetGatewayDevice:2".to_string(),
            },
        ];
        let processed = process_responses(responses);
        // Should keep only the :2 response (higher USN sorts first).
        assert_eq!(processed.len(), 1);
        assert!(processed[0].usn.contains("InternetGatewayDevice:2"));
    }

    #[test]
    fn resolve_url_relative() {
        assert_eq!(
            resolve_url("http://192.168.1.1:5000/rootDesc.xml", "/ctl/IPConn"),
            "http://192.168.1.1:5000/ctl/IPConn"
        );
    }

    #[test]
    fn resolve_url_absolute() {
        assert_eq!(
            resolve_url(
                "http://192.168.1.1:5000/rootDesc.xml",
                "http://other:80/foo"
            ),
            "http://other:80/foo"
        );
    }

    #[test]
    fn extract_tag_text_works() {
        let resp = r#"<?xml version="1.0"?>
<s:Envelope><s:Body>
  <u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
    <NewExternalIPAddress>123.123.123.123</NewExternalIPAddress>
  </u:GetExternalIPAddressResponse>
</s:Body></s:Envelope>"#;
        assert_eq!(
            extract_tag_text(resp, "NewExternalIPAddress"),
            Some("123.123.123.123".to_string())
        );
    }

    #[test]
    fn is_soap_fault_detects_fault() {
        let fault = r#"<?xml version="1.0"?>
<s:Envelope><s:Body><s:Fault><faultCode>s:Client</faultCode></s:Fault></s:Body></s:Envelope>"#;
        assert!(is_soap_fault(fault));
        let ok = r#"<?xml version="1.0"?>
<s:Envelope><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>"#;
        assert!(!is_soap_fault(ok));
    }

    #[test]
    fn extract_upnp_error_code_works() {
        let fault = r#"<?xml version="1.0"?>
<s:Envelope><s:Body><s:Fault><detail>
  <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
    <errorCode>725</errorCode>
    <errorDescription>OnlyPermanentLeasesSupported</errorDescription>
  </UPnPError>
</detail></s:Fault></s:Body></s:Envelope>"#;
        assert_eq!(extract_upnp_error_code(fault), Some(725));
    }
}
