//! UPnP IGD client: SSDP discovery, root-desc fetch, and SOAP
//! AddPortMapping / DeletePortMapping / GetExternalIPAddress.
//!
//! Discovery sends M-SEARCH packets to the gateway's unicast address and the
//! SSDP multicast address (239.255.255.250:1900). Responses are HTTP-over-UDP
//! with `LOCATION`, `SERVER`, and `USN` headers. We fetch the root-desc XML
//! from the LOCATION URL, find the best WAN connection service, and make SOAP
//! calls to create/delete mappings and get the external IP.

use std::collections::{HashMap, HashSet};
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

#[derive(Debug, Clone, Copy)]
pub(crate) struct UpnpAllocation {
    pub port: u16,
    pub permanent: bool,
}

#[derive(Debug)]
pub(crate) struct AmbiguousAddError {
    pub port: u16,
    pub permanent: bool,
    pub source: std::io::Error,
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
    mut before_send: impl FnMut(u16, bool),
    mut rejected: impl FnMut(u16, bool),
) -> Result<UpnpAllocation, AmbiguousAddError> {
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
    before_send(port, false);
    let (status, resp) = http::http_post_soap(
        &svc.control_url,
        &soap_action,
        SOAP_CONTENT_TYPE,
        &body,
        deadline,
    )
    .await
    .map_err(|source| AmbiguousAddError {
        port,
        permanent: false,
        source,
    })?;

    if status == 200 && soap_response_is_success(&resp, "AddPortMappingResponse") {
        return Ok(UpnpAllocation {
            port,
            permanent: false,
        });
    }

    // Only a structurally valid SOAP Fault proves that Add was rejected.
    // Malformed HTTP responses remain ambiguous and retain ownership.
    if let Some(code) = soap_fault_code(&resp) {
        rejected(port, false);
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
            before_send(port, true);
            let (status, resp) = http::http_post_soap(
                &svc.control_url,
                &soap_action,
                SOAP_CONTENT_TYPE,
                &body,
                deadline,
            )
            .await
            .map_err(|source| AmbiguousAddError {
                port,
                permanent: true,
                source,
            })?;
            if status == 200 && soap_response_is_success(&resp, "AddPortMappingResponse") {
                return Ok(UpnpAllocation {
                    port,
                    permanent: true,
                });
            }
            if soap_fault_code(&resp).is_some() {
                rejected(port, true);
            }
            return Err(AmbiguousAddError {
                port,
                permanent: true,
                source: std::io::Error::other(format!(
                    "permanent AddPortMapping malformed/fault (status={status})"
                )),
            });
        }
    }

    Err(AmbiguousAddError {
        port,
        permanent: false,
        source: std::io::Error::other(format!("AddPortMapping failed (status={status})")),
    })
}

/// Delete a UDP port mapping via SOAP DeletePortMapping.
pub(crate) async fn delete_port_mapping(
    svc: &UpnpService,
    external_port: u16,
    deadline: Duration,
) -> Result<(), std::io::Error> {
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
    let (status, response) = http::http_post_soap(
        &svc.control_url,
        &soap_action,
        SOAP_CONTENT_TYPE,
        &body,
        deadline,
    )
    .await?;
    if delete_response_is_success(status, &response) {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "DeletePortMapping failed (status={status})"
    )))
}

fn delete_response_is_success(status: u16, response: &str) -> bool {
    (status == 200 && soap_response_is_success(response, "DeletePortMappingResponse"))
        // 714 NoSuchEntryInArray positively verifies that no mapping remains,
        // but only when carried in a structurally valid SOAP fault.
        || soap_not_found(response)
}

fn soap_not_found(body: &str) -> bool {
    soap_fault_code(body) == Some(714)
}

fn soap_fault_code(body: &str) -> Option<u32> {
    let elements = parse_xml_elements(body)?;
    has_strict_soap_body(&elements, "Fault")
        .then(|| extract_upnp_error_code(body))
        .flatten()
}

fn soap_response_is_success(body: &str, response_element: &str) -> bool {
    parse_xml_elements(body)
        .is_some_and(|elements| has_strict_soap_body(&elements, response_element))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct XmlName {
    prefix: Option<String>,
    local: String,
    namespace: Option<String>,
}

#[derive(Debug)]
struct XmlElement {
    name: XmlName,
    parent: Option<XmlName>,
}

struct XmlFrame {
    name: XmlName,
    namespaces: HashMap<String, String>,
}

fn has_strict_soap_body(elements: &[XmlElement], expected: &str) -> bool {
    if expected != "Fault" && elements.iter().any(|element| element.name.local == "Fault") {
        return false;
    }
    let roots: Vec<_> = elements
        .iter()
        .filter(|element| element.parent.is_none())
        .collect();
    if roots.len() != 1 || roots[0].name.local != "Envelope" {
        return false;
    }
    let envelope_children: Vec<_> = elements
        .iter()
        .filter(|element| {
            element
                .parent
                .as_ref()
                .is_some_and(|parent| parent.local == "Envelope")
        })
        .collect();
    if envelope_children.len() != 1
        || envelope_children[0].name.local != "Body"
        || envelope_children[0].name.namespace != roots[0].name.namespace
    {
        return false;
    }
    let body_children: Vec<_> = elements
        .iter()
        .filter(|element| {
            element
                .parent
                .as_ref()
                .is_some_and(|parent| parent.local == "Body")
        })
        .collect();
    body_children.len() == 1
        && body_children[0].name.local == expected
        && (expected != "Fault"
            || body_children[0].name.namespace == envelope_children[0].name.namespace)
}

fn parse_xml_elements(xml: &str) -> Option<Vec<XmlElement>> {
    let mut stack = Vec::<XmlFrame>::new();
    let mut elements = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find('<') {
        if stack.is_empty() && !rest[..start].trim().is_empty() {
            return None;
        }
        rest = &rest[start + 1..];
        let end = find_xml_tag_end(rest)?;
        let mut token = rest[..end].trim();
        rest = &rest[end + 1..];
        if token.starts_with('?') {
            if !stack.is_empty() || !token.ends_with('?') {
                return None;
            }
            continue;
        }
        // SOAP responses do not need DTDs or comments. Rejecting declarations
        // keeps this small parser fail-closed rather than partially parsing
        // namespace-affecting XML syntax.
        if token.starts_with('!') {
            return None;
        }
        if let Some(close) = token.strip_prefix('/') {
            let qualified = close.trim();
            if qualified.is_empty() || qualified.chars().any(char::is_whitespace) {
                return None;
            }
            let frame = stack.pop()?;
            let closing = resolve_xml_name(qualified, &frame.namespaces)?;
            // XML end tags must use the same qualified prefix, local name,
            // and in-scope binding as their opening tag.
            if closing != frame.name {
                return None;
            }
            continue;
        }

        let self_closing = token.ends_with('/');
        if self_closing {
            token = token[..token.len() - 1].trim_end();
        }
        let (qualified, attributes) = split_xml_name(token)?;
        let mut namespaces = stack
            .last()
            .map_or_else(default_xml_namespaces, |frame| frame.namespaces.clone());
        let parsed_attributes = parse_xml_attributes(attributes)?;
        for (name, value) in &parsed_attributes {
            if name == "xmlns" {
                namespaces.insert(String::new(), value.clone());
            } else if let Some(prefix) = name.strip_prefix("xmlns:") {
                if prefix.is_empty()
                    || prefix == "xmlns"
                    || value.is_empty()
                    || (prefix == "xml" && value != "http://www.w3.org/XML/1998/namespace")
                {
                    return None;
                }
                namespaces.insert(prefix.to_string(), value.clone());
            }
        }
        for (name, _) in &parsed_attributes {
            if name == "xmlns" || name.starts_with("xmlns:") {
                continue;
            }
            if let Some((prefix, _)) = name.split_once(':') {
                if !namespaces.contains_key(prefix) {
                    return None;
                }
            }
        }
        let name = resolve_xml_name(qualified, &namespaces)?;
        elements.push(XmlElement {
            name: name.clone(),
            parent: stack.last().map(|frame| frame.name.clone()),
        });
        if !self_closing {
            stack.push(XmlFrame { name, namespaces });
        }
    }
    (stack.is_empty() && !elements.is_empty() && rest.trim().is_empty()).then_some(elements)
}

fn find_xml_tag_end(token: &str) -> Option<usize> {
    let mut quote = None;
    for (index, ch) in token.char_indices() {
        match (quote, ch) {
            (Some(open), close) if open == close => quote = None,
            (None, '\'' | '"') => quote = Some(ch),
            (None, '>') => return Some(index),
            _ => {}
        }
    }
    None
}

fn split_xml_name(token: &str) -> Option<(&str, &str)> {
    let end = token.find(char::is_whitespace).unwrap_or(token.len());
    let name = &token[..end];
    (!name.is_empty()).then_some((name, token[end..].trim_start()))
}

fn parse_xml_attributes(mut attributes: &str) -> Option<Vec<(String, String)>> {
    let mut parsed = Vec::new();
    let mut seen = HashSet::new();
    while !attributes.is_empty() {
        let name_end = attributes
            .find(|ch: char| ch.is_whitespace() || ch == '=')
            .unwrap_or(attributes.len());
        let name = &attributes[..name_end];
        if name.is_empty() || !seen.insert(name.to_string()) {
            return None;
        }
        attributes = attributes[name_end..].trim_start();
        attributes = attributes.strip_prefix('=')?.trim_start();
        let quote = attributes.chars().next()?;
        if quote != '\'' && quote != '"' {
            return None;
        }
        attributes = &attributes[quote.len_utf8()..];
        let value_end = attributes.find(quote)?;
        parsed.push((name.to_string(), attributes[..value_end].to_string()));
        attributes = attributes[value_end + quote.len_utf8()..].trim_start();
    }
    Some(parsed)
}

fn default_xml_namespaces() -> HashMap<String, String> {
    HashMap::from([(
        "xml".to_string(),
        "http://www.w3.org/XML/1998/namespace".to_string(),
    )])
}

fn resolve_xml_name(qualified: &str, namespaces: &HashMap<String, String>) -> Option<XmlName> {
    let (prefix, local) = if let Some((prefix, local)) = qualified.split_once(':') {
        if prefix.is_empty() || local.is_empty() || local.contains(':') {
            return None;
        }
        (Some(prefix), local)
    } else {
        (None, qualified)
    };
    if local.is_empty() {
        return None;
    }
    let namespace = match prefix {
        Some(prefix) => Some(namespaces.get(prefix)?.clone()),
        None => namespaces.get("").cloned(),
    };
    Some(XmlName {
        prefix: prefix.map(str::to_string),
        local: local.to_string(),
        namespace,
    })
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
    parse_external_ip_response(&resp)
}

fn parse_external_ip_response(resp: &str) -> Result<Ipv4Addr, std::io::Error> {
    let elements = parse_xml_elements(resp).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed SOAP response")
    })?;
    if !has_strict_soap_body(&elements, "GetExternalIPAddressResponse") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid GetExternalIPAddress SOAP structure",
        ));
    }
    let response_children: Vec<_> = elements
        .iter()
        .filter(|element| {
            element
                .parent
                .as_ref()
                .is_some_and(|parent| parent.local == "GetExternalIPAddressResponse")
        })
        .collect();
    if response_children.len() != 1 || response_children[0].name.local != "NewExternalIPAddress" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid GetExternalIPAddress response fields",
        ));
    }
    let ip_str = extract_tag_text(resp, "NewExternalIPAddress")
        .filter(|ip| !ip.is_empty())
        .ok_or_else(|| {
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

/// Whether a SOAP response body is structurally a SOAP Fault.
#[cfg(test)]
fn is_soap_fault(body: &str) -> bool {
    parse_xml_elements(body).is_some_and(|elements| has_strict_soap_body(&elements, "Fault"))
}

/// Extract the UPnP error code from a SOAP fault response.
fn extract_upnp_error_code(body: &str) -> Option<u32> {
    let code_str = extract_tag_text(body, "errorCode")?;
    code_str.parse().ok()
}

/// Extract the text content of an XML tag from a string (first occurrence).
fn extract_tag_text(s: &str, tag: &str) -> Option<String> {
    let mut offset = 0;
    while let Some(relative) = s[offset..].find('<') {
        let start = offset + relative;
        let end = start + s[start..].find('>')?;
        let token = s[start + 1..end].trim();
        if !token.starts_with('/') {
            let qualified = token.split_whitespace().next()?.trim_end_matches('/');
            if qualified.rsplit(':').next() == Some(tag) {
                let close = format!("</{qualified}>");
                let text_start = end + 1;
                let relative_close = s[text_start..].find(&close)?;
                return Some(
                    s[text_start..text_start + relative_close]
                        .trim()
                        .to_string(),
                );
            }
        }
        offset = end + 1;
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
    fn delete_requires_success_or_not_found() {
        assert!(delete_response_is_success(
            200,
            r#"<x:Envelope xmlns:x="urn:soap" xmlns:m="urn:upnp"><x:Body><m:DeletePortMappingResponse/></x:Body></x:Envelope>"#
        ));
        assert!(delete_response_is_success(
            500,
            r#"<s:Envelope xmlns:s="urn:soap" xmlns:x="urn:error"><s:Body><s:Fault><x:errorCode>714</x:errorCode></s:Fault></s:Body></s:Envelope>"#
        ));
        assert!(!delete_response_is_success(
            200,
            "<s:Fault><errorCode>501</errorCode></s:Fault>"
        ));
        assert!(!delete_response_is_success(500, "server error"));
        assert!(!delete_response_is_success(200, ""));
        assert!(!delete_response_is_success(
            200,
            "<Envelope><Body><DeletePortMappingResponse></Body></Envelope>"
        ));
        assert!(soap_response_is_success(
            r#"<soap:Envelope xmlns:soap="urn:soap" xmlns:z="urn:upnp"><soap:Body><z:AddPortMappingResponse/></soap:Body></soap:Envelope>"#,
            "AddPortMappingResponse"
        ));
        assert!(!soap_response_is_success(
            "<Envelope><Body><Fault/><AddPortMappingResponse/></Body></Envelope>",
            "AddPortMappingResponse"
        ));
        assert!(!soap_response_is_success(
            "<Envelope><Body><AddPortMappingResponse><Fault/></AddPortMappingResponse></Body></Envelope>",
            "AddPortMappingResponse"
        ));
        assert!(!soap_response_is_success(
            "<Envelope><Body/><AddPortMappingResponse/></Envelope>",
            "AddPortMappingResponse"
        ));
        assert!(!soap_response_is_success(
            "<Envelope><Body><AddPortMappingResponse/><AddPortMappingResponse/></Body></Envelope>",
            "AddPortMappingResponse"
        ));
    }

    #[test]
    fn xml_qnames_require_bound_and_matching_prefixes() {
        for invalid in [
            "<s:Envelope><s:Body/></s:Envelope>",
            "<s:Envelope xmlns:s=\"urn:soap\"><s:Body></x:Body></s:Envelope>",
            "<s:Envelope xmlns:s=\"urn:soap\" xmlns:x=\"urn:soap\"><s:Body></x:Body></s:Envelope>",
            "<s:Envelope xmlns:s=\"urn:soap\"><x:Body/></s:Envelope>",
            "<s:Envelope xmlns:s=\"urn:soap\"><s:Body><u:Response/></s:Body></s:Envelope>",
            "<s:Envelope xmlns:s=\"urn:soap\"><s:Body></s:Envelope></s:Body>",
        ] {
            assert!(parse_xml_elements(invalid).is_none(), "accepted {invalid}");
        }
        assert!(parse_xml_elements(
            "<a:Envelope xmlns:a=\"urn:soap\"><b:Body xmlns:b=\"urn:soap\"/></a:Envelope>"
        )
        .is_some());
        assert!(!soap_response_is_success(
            "<s:Envelope xmlns:s=\"urn:soap\"><s:Body xmlns:s=\"urn:other\"><Response/></s:Body></s:Envelope>",
            "Response"
        ));
    }

    #[test]
    fn external_ip_requires_exact_soap_structure() {
        let valid = "<x:Envelope xmlns:x=\"urn:soap\" xmlns:u=\"urn:upnp\" xmlns:z=\"urn:field\"><x:Body><u:GetExternalIPAddressResponse><z:NewExternalIPAddress>198.51.100.7</z:NewExternalIPAddress></u:GetExternalIPAddressResponse></x:Body></x:Envelope>";
        assert_eq!(
            parse_external_ip_response(valid).unwrap(),
            Ipv4Addr::new(198, 51, 100, 7)
        );
        for invalid in [
            "<Envelope><Body><NewExternalIPAddress>198.51.100.7</NewExternalIPAddress></Body></Envelope>",
            "<Envelope><Body><GetExternalIPAddressResponse><wrapper><NewExternalIPAddress>198.51.100.7</NewExternalIPAddress></wrapper></GetExternalIPAddressResponse></Body></Envelope>",
            "<Envelope><Body><GetExternalIPAddressResponse><NewExternalIPAddress>198.51.100.7</NewExternalIPAddress><extra/></GetExternalIPAddressResponse></Body></Envelope>",
            "<Envelope><Body><GetExternalIPAddressResponse><NewExternalIPAddress/></GetExternalIPAddressResponse></Body></Envelope>",
            "<Envelope><Body><Fault><NewExternalIPAddress>198.51.100.7</NewExternalIPAddress></Fault></Body></Envelope>",
        ] {
            assert!(parse_external_ip_response(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn fallback_fault_requires_direct_soap_structure() {
        assert_eq!(
            soap_fault_code("<s:Envelope xmlns:s=\"urn:soap\"><s:Body><s:Fault><errorCode>725</errorCode></s:Fault></s:Body></s:Envelope>"),
            Some(725)
        );
        assert_eq!(
            soap_fault_code("<s:Envelope xmlns:s=\"urn:soap\"><s:Body><wrapper><s:Fault><errorCode>725</errorCode></s:Fault></wrapper></s:Body></s:Envelope>"),
            None
        );
        assert_eq!(
            soap_fault_code("<s:Envelope xmlns:s=\"urn:soap\"><s:Body><s:Fault/><extra><errorCode>725</errorCode></extra></s:Body></s:Envelope>"),
            None
        );
    }

    #[test]
    fn is_soap_fault_detects_fault() {
        let fault = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="urn:soap"><s:Body><s:Fault><faultCode>s:Client</faultCode></s:Fault></s:Body></s:Envelope>"#;
        assert!(is_soap_fault(fault));
        let ok = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="urn:soap" xmlns:u="urn:upnp"><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>"#;
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
