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
pub(crate) async fn add_port_mapping<P>(
    svc: &UpnpService,
    internal_client: &str,
    internal_port: u16,
    external_port: u16,
    lease_duration: u32,
    deadline: Duration,
    mut before_send: impl FnMut(u16, bool) -> Result<P, std::io::Error>,
    mut rejected: impl FnMut(u16, bool),
) -> Result<UpnpAllocation, AmbiguousAddError>
where
    P: Send,
{
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
    let send_permit = before_send(port, false).map_err(|source| AmbiguousAddError {
        port,
        permanent: false,
        source,
    })?;
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

    if status == 200 && soap_response_is_success(&resp, "AddPortMappingResponse", service_type) {
        return Ok(UpnpAllocation {
            port,
            permanent: false,
        });
    }

    // Only a structurally valid SOAP Fault proves that Add was rejected.
    // Malformed HTTP responses remain ambiguous and retain ownership.
    if let Some(code) = soap_fault_code(&resp) {
        // A structurally valid UPnP fault is a definitive rejection: this Add
        // did not create our mapping. Resolve provisional ownership before
        // deciding whether this particular code permits a fallback retry.
        rejected(port, false);
        if !code.allows_permanent_add_retry() {
            return Err(AmbiguousAddError {
                port,
                permanent: false,
                source: std::io::Error::other(format!(
                    "AddPortMapping rejected with UPnP error {}",
                    code.0
                )),
            });
        }
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
        drop(send_permit);
        let _send_permit = before_send(port, true).map_err(|source| AmbiguousAddError {
            port,
            permanent: true,
            source,
        })?;
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
        if status == 200 && soap_response_is_success(&resp, "AddPortMappingResponse", service_type)
        {
            return Ok(UpnpAllocation {
                port,
                permanent: true,
            });
        }
        if soap_fault_code(&resp).is_some() {
            // Any valid fault proves the permanent Add was rejected. Unknown
            // codes must not trigger compensation against another owner.
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
    if delete_response_is_success(status, &response, service_type) {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "DeletePortMapping failed (status={status})"
    )))
}

fn delete_response_is_success(status: u16, response: &str, service_type: &str) -> bool {
    (status == 200
        && soap_response_is_success(response, "DeletePortMappingResponse", service_type))
        // 714 NoSuchEntryInArray positively verifies that no mapping remains,
        // but only when carried in a structurally valid SOAP fault.
        || soap_not_found(response)
}

fn soap_not_found(body: &str) -> bool {
    soap_fault_code(body) == Some(SoapFaultCode(714))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SoapFaultCode(u32);

impl SoapFaultCode {
    fn allows_permanent_add_retry(self) -> bool {
        matches!(self.0, 402 | 725)
    }
}

fn soap_fault_code(body: &str) -> Option<SoapFaultCode> {
    const CONTROL_ERROR_NAMESPACE: &str = "urn:schemas-upnp-org:control-1-0";

    let elements = parse_xml_elements(body)?;
    if !has_strict_soap_body(&elements, "Fault") {
        return None;
    }
    let codes: Vec<_> = elements
        .iter()
        .enumerate()
        .filter(|(_, element)| element.name.local == "errorCode")
        .collect();
    if codes.len() != 1 {
        return None;
    }
    let (code_index, code) = codes[0];
    if code.name.namespace.as_deref() != Some(CONTROL_ERROR_NAMESPACE)
        || elements
            .iter()
            .any(|element| element.parent_index == Some(code_index))
    {
        return None;
    }

    let upnp_error_index = code.parent_index?;
    let upnp_error = elements.get(upnp_error_index)?;
    if upnp_error.name.local != "UPnPError"
        || upnp_error.name.namespace.as_deref() != Some(CONTROL_ERROR_NAMESPACE)
    {
        return None;
    }
    let detail_index = upnp_error.parent_index?;
    let detail = elements.get(detail_index)?;
    let fault_index = detail.parent_index?;
    let fault = elements.get(fault_index)?;
    let body_index = fault.parent_index?;
    let soap_body = elements.get(body_index)?;
    let envelope_index = soap_body.parent_index?;
    let envelope = elements.get(envelope_index)?;
    let soap_namespace = envelope.name.namespace.as_deref()?;
    let detail_is_standard = match soap_namespace {
        "http://schemas.xmlsoap.org/soap/envelope/" => {
            detail.name.local == "detail" && detail.name.namespace.is_none()
        }
        "http://www.w3.org/2003/05/soap-envelope" => {
            detail.name.local == "Detail"
                && detail.name.namespace.as_deref() == Some(soap_namespace)
        }
        _ => false,
    };
    if !detail_is_standard
        || fault.name.local != "Fault"
        || fault.name.namespace.as_deref() != Some(soap_namespace)
        || soap_body.name.local != "Body"
        || soap_body.name.namespace.as_deref() != Some(soap_namespace)
        || envelope.name.local != "Envelope"
        || envelope.parent_index.is_some()
    {
        return None;
    }

    let value = code.text.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(SoapFaultCode(value.parse::<u32>().ok()?))
}

fn soap_response_is_success(body: &str, response_element: &str, service_type: &str) -> bool {
    parse_xml_elements(body).is_some_and(|elements| {
        has_strict_soap_body(&elements, response_element)
            && elements.iter().any(|element| {
                element.name.local == response_element
                    && element.name.namespace.as_deref() == Some(service_type)
                    && element
                        .parent
                        .as_ref()
                        .is_some_and(|parent| parent.local == "Body")
            })
    })
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
    parent_index: Option<usize>,
    text: String,
}

struct XmlFrame {
    name: XmlName,
    namespaces: HashMap<String, String>,
    element_index: usize,
}

fn has_strict_soap_body(elements: &[XmlElement], expected: &str) -> bool {
    if expected != "Fault" && elements.iter().any(|element| element.name.local == "Fault") {
        return false;
    }
    let roots: Vec<_> = elements
        .iter()
        .filter(|element| element.parent.is_none())
        .collect();
    if roots.len() != 1
        || roots[0].name.local != "Envelope"
        || !matches!(
            roots[0].name.namespace.as_deref(),
            Some(
                "http://schemas.xmlsoap.org/soap/envelope/"
                    | "http://www.w3.org/2003/05/soap-envelope"
            )
        )
    {
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
    let mut elements = Vec::<XmlElement>::new();
    let mut rest = xml;
    while let Some(start) = rest.find('<') {
        let decoded_text = decode_xml_entities(&rest[..start])?;
        if let Some(frame) = stack.last() {
            elements[frame.element_index].text.push_str(&decoded_text);
        } else if !decoded_text.trim().is_empty() {
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
        let element_index = elements.len();
        elements.push(XmlElement {
            name: name.clone(),
            parent: stack.last().map(|frame| frame.name.clone()),
            parent_index: stack.last().map(|frame| frame.element_index),
            text: String::new(),
        });
        if !self_closing {
            stack.push(XmlFrame {
                name,
                namespaces,
                element_index,
            });
        }
    }
    let trailing = decode_xml_entities(rest)?;
    if let Some(frame) = stack.last() {
        elements[frame.element_index].text.push_str(&trailing);
    } else if !trailing.trim().is_empty() {
        return None;
    }
    (stack.is_empty() && !elements.is_empty()).then_some(elements)
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
        if name.is_empty()
            || !name.split(':').all(xml_ncname_is_valid)
            || name.matches(':').count() > 1
            || !seen.insert(name.to_string())
        {
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
        parsed.push((
            name.to_string(),
            decode_xml_entities(&attributes[..value_end])?,
        ));
        attributes = attributes[value_end + quote.len_utf8()..].trim_start();
    }
    Some(parsed)
}

fn decode_xml_entities(text: &str) -> Option<String> {
    let mut decoded = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        decoded.push_str(&rest[..amp]);
        rest = &rest[amp + 1..];
        let end = rest.find(';')?;
        let entity = &rest[..end];
        let ch = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "apos" => '\'',
            "quot" => '"',
            value if value.starts_with("#x") => {
                char::from_u32(u32::from_str_radix(&value[2..], 16).ok()?)?
            }
            value if value.starts_with('#') => char::from_u32(value[1..].parse().ok()?)?,
            _ => return None,
        };
        decoded.push(ch);
        rest = &rest[end + 1..];
    }
    decoded.push_str(rest);
    decoded.chars().all(xml_char_is_allowed).then_some(decoded)
}

fn xml_char_is_allowed(ch: char) -> bool {
    matches!(ch, '\u{9}' | '\u{A}' | '\u{D}')
        || ('\u{20}'..='\u{D7FF}').contains(&ch)
        || ('\u{E000}'..='\u{FFFD}').contains(&ch)
        || ('\u{10000}'..='\u{10FFFF}').contains(&ch)
}

fn default_xml_namespaces() -> HashMap<String, String> {
    HashMap::from([(
        "xml".to_string(),
        "http://www.w3.org/XML/1998/namespace".to_string(),
    )])
}

fn xml_ncname_is_valid(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_alphabetic())
        && chars.all(|ch| ch == '_' || ch == '-' || ch == '.' || ch.is_alphanumeric())
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
    if !xml_ncname_is_valid(local) || prefix.is_some_and(|prefix| !xml_ncname_is_valid(prefix)) {
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
    parse_external_ip_response(&resp, service_type)
}

fn parse_external_ip_response(resp: &str, service_type: &str) -> Result<Ipv4Addr, std::io::Error> {
    let elements = parse_xml_elements(resp).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed SOAP response")
    })?;
    if !has_strict_soap_body(&elements, "GetExternalIPAddressResponse")
        || !elements.iter().any(|element| {
            element.name.local == "GetExternalIPAddressResponse"
                && element.name.namespace.as_deref() == Some(service_type)
                && element
                    .parent
                    .as_ref()
                    .is_some_and(|parent| parent.local == "Body")
        })
    {
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
    let ip_str = response_children[0].text.trim();
    if ip_str.is_empty()
        || elements.iter().any(|element| {
            element
                .parent
                .as_ref()
                .is_some_and(|parent| parent.local == "NewExternalIPAddress")
        })
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no NewExternalIPAddress in response",
        ));
    }
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
    fn delete_requires_success_or_not_found() {
        assert!(delete_response_is_success(
            200,
            r#"<x:Envelope xmlns:x="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="urn:upnp"><x:Body><m:DeletePortMappingResponse/></x:Body></x:Envelope>"#,
            "urn:upnp"
        ));
        assert!(delete_response_is_success(
            500,
            r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>714</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>"#,
            "urn:upnp"
        ));
        assert!(!delete_response_is_success(
            200,
            "<s:Fault><errorCode>501</errorCode></s:Fault>",
            "urn:upnp"
        ));
        assert!(!delete_response_is_success(500, "server error", "urn:upnp"));
        assert!(!delete_response_is_success(200, "", "urn:upnp"));
        assert!(!delete_response_is_success(
            200,
            "<Envelope><Body><DeletePortMappingResponse></Body></Envelope>",
            "urn:upnp"
        ));
        assert!(soap_response_is_success(
            r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:z="urn:upnp"><soap:Body><z:AddPortMappingResponse/></soap:Body></soap:Envelope>"#,
            "AddPortMappingResponse",
            "urn:upnp"
        ));
        assert!(!soap_response_is_success(
            r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><AddPortMappingResponse/></soap:Body></soap:Envelope>"#,
            "AddPortMappingResponse",
            "urn:upnp"
        ));
        assert!(!soap_response_is_success(
            r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:z="urn:wrong"><soap:Body><z:AddPortMappingResponse/></soap:Body></soap:Envelope>"#,
            "AddPortMappingResponse",
            "urn:upnp"
        ));
        assert!(!soap_response_is_success(
            "<Envelope><Body><Fault/><AddPortMappingResponse/></Body></Envelope>",
            "AddPortMappingResponse",
            "urn:upnp"
        ));
        assert!(!soap_response_is_success(
            "<Envelope><Body><AddPortMappingResponse><Fault/></AddPortMappingResponse></Body></Envelope>",
            "AddPortMappingResponse",
            "urn:upnp"
        ));
        assert!(!soap_response_is_success(
            "<Envelope><Body/><AddPortMappingResponse/></Envelope>",
            "AddPortMappingResponse",
            "urn:upnp"
        ));
        assert!(!soap_response_is_success(
            "<Envelope><Body><AddPortMappingResponse/><AddPortMappingResponse/></Body></Envelope>",
            "AddPortMappingResponse",
            "urn:upnp"
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
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body xmlns:s=\"urn:other\"><Response/></s:Body></s:Envelope>",
            "Response",
            "urn:upnp"
        ));
    }

    #[test]
    fn external_ip_requires_exact_soap_structure() {
        let valid = "<x:Envelope xmlns:x=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:u=\"urn:upnp\" xmlns:z=\"urn:field\"><x:Body><u:GetExternalIPAddressResponse><z:NewExternalIPAddress>198.51.100.7</z:NewExternalIPAddress></u:GetExternalIPAddressResponse></x:Body></x:Envelope>";
        assert_eq!(
            parse_external_ip_response(valid, "urn:upnp").unwrap(),
            Ipv4Addr::new(198, 51, 100, 7)
        );
        let encoded = "<x:Envelope xmlns:x=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:u=\"urn:upnp\"><x:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>198&#46;51.100.8</NewExternalIPAddress></u:GetExternalIPAddressResponse></x:Body></x:Envelope>";
        assert_eq!(
            parse_external_ip_response(encoded, "urn:upnp").unwrap(),
            Ipv4Addr::new(198, 51, 100, 8)
        );
        for invalid in [
            "<Envelope><Body><NewExternalIPAddress>198.51.100.7</NewExternalIPAddress></Body></Envelope>",
            "<Envelope><Body><GetExternalIPAddressResponse><wrapper><NewExternalIPAddress>198.51.100.7</NewExternalIPAddress></wrapper></GetExternalIPAddressResponse></Body></Envelope>",
            "<Envelope><Body><GetExternalIPAddressResponse><NewExternalIPAddress>198.51.100.7</NewExternalIPAddress><extra/></GetExternalIPAddressResponse></Body></Envelope>",
            "<Envelope><Body><GetExternalIPAddressResponse><NewExternalIPAddress/></GetExternalIPAddressResponse></Body></Envelope>",
            "<Envelope><Body><Fault><NewExternalIPAddress>198.51.100.7</NewExternalIPAddress></Fault></Body></Envelope>",
            "<x:Envelope xmlns:x=\"urn:not-soap\" xmlns:u=\"urn:upnp\"><x:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>198.51.100.7</NewExternalIPAddress></u:GetExternalIPAddressResponse></x:Body></x:Envelope>",
            "<x:Envelope xmlns:x=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:u=\"urn:wrong\"><x:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>198.51.100.7</NewExternalIPAddress></u:GetExternalIPAddressResponse></x:Body></x:Envelope>",
            "<x:Envelope xmlns:x=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:u=\"urn:upnp\"><x:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>198&bogus;51.100.7</NewExternalIPAddress></u:GetExternalIPAddressResponse></x:Body></x:Envelope>",
            "<x:Envelope xmlns:x=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:u=\"urn:upnp\"><x:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>&#x110000;</NewExternalIPAddress></u:GetExternalIPAddressResponse></x:Body></x:Envelope>",
            "<x:Envelope xmlns:x=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:u=\"urn:upnp\"><x:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>&#0;</NewExternalIPAddress></u:GetExternalIPAddressResponse></x:Body></x:Envelope>",
        ] {
            assert!(
                parse_external_ip_response(invalid, "urn:upnp").is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn fault_code_requires_exact_upnp_error_path_and_namespace() {
        let valid_725 = r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body><s:Fault><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
<errorCode>7&#50;5</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>"#;
        assert_eq!(soap_fault_code(valid_725), Some(SoapFaultCode(725)));
        assert!(!soap_not_found(valid_725));

        let valid_714 = r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body><s:Fault><detail><u:UPnPError xmlns:u="urn:schemas-upnp-org:control-1-0">
<u:errorCode>714</u:errorCode></u:UPnPError></detail></s:Fault></s:Body></s:Envelope>"#;
        assert_eq!(soap_fault_code(valid_714), Some(SoapFaultCode(714)));
        assert!(soap_not_found(valid_714));

        let valid_402_soap12 = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Body><s:Fault><s:Detail><u:UPnPError xmlns:u="urn:schemas-upnp-org:control-1-0">
<u:errorCode>402</u:errorCode></u:UPnPError></s:Detail></s:Fault></s:Body></s:Envelope>"#;
        assert_eq!(soap_fault_code(valid_402_soap12), Some(SoapFaultCode(402)));
        assert!(!soap_not_found(valid_402_soap12));

        let valid_unknown = r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="urn:schemas-upnp-org:control-1-0"><s:Body><s:Fault><detail><u:UPnPError><u:errorCode>799</u:errorCode></u:UPnPError></detail></s:Fault></s:Body></s:Envelope>"#;
        assert_eq!(soap_fault_code(valid_unknown), Some(SoapFaultCode(799)));
        assert!(!SoapFaultCode(718).allows_permanent_add_retry());
        assert!(!SoapFaultCode(799).allows_permanent_add_retry());
        assert!(SoapFaultCode(402).allows_permanent_add_retry());
        assert!(SoapFaultCode(725).allows_permanent_add_retry());

        for invalid in [
            // Wrong ancestry.
            r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="urn:schemas-upnp-org:control-1-0"><s:Body><s:Fault><u:errorCode>725</u:errorCode></s:Fault></s:Body></s:Envelope>"#,
            r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="urn:schemas-upnp-org:control-1-0"><s:Body><s:Fault><detail><wrapper><u:UPnPError><u:errorCode>725</u:errorCode></u:UPnPError></wrapper></detail></s:Fault></s:Body></s:Envelope>"#,
            // evil:errorCode and wrong UPnP control namespaces.
            r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="urn:schemas-upnp-org:control-1-0" xmlns:evil="urn:evil"><s:Body><s:Fault><detail><u:UPnPError><evil:errorCode>725</evil:errorCode></u:UPnPError></detail></s:Fault></s:Body></s:Envelope>"#,
            r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="urn:wrong"><s:Body><s:Fault><detail><u:UPnPError><u:errorCode>725</u:errorCode></u:UPnPError></detail></s:Fault></s:Body></s:Envelope>"#,
            r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="urn:schemas-upnp-org:control-1-0"><s:Body><s:Fault><detail><u:UPnPError><errorCode>725</errorCode></u:UPnPError></detail></s:Fault></s:Body></s:Envelope>"#,
            // Duplicate, malformed, nested, and unrecognized values.
            r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="urn:schemas-upnp-org:control-1-0"><s:Body><s:Fault><detail><u:UPnPError><u:errorCode>725</u:errorCode><u:errorCode>725</u:errorCode></u:UPnPError></detail></s:Fault></s:Body></s:Envelope>"#,
            r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="urn:schemas-upnp-org:control-1-0"><s:Body><s:Fault><detail><u:UPnPError><u:errorCode>7&bad;5</u:errorCode></u:UPnPError></detail></s:Fault></s:Body></s:Envelope>"#,
            r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="urn:schemas-upnp-org:control-1-0"><s:Body><s:Fault><detail><u:UPnPError><u:errorCode>7<x/>25</u:errorCode></u:UPnPError></detail></s:Fault></s:Body></s:Envelope>"#,
        ] {
            assert_eq!(soap_fault_code(invalid), None, "accepted {invalid}");
        }
    }

    #[test]
    fn is_soap_fault_detects_fault() {
        let fault = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultCode>s:Client</faultCode></s:Fault></s:Body></s:Envelope>"#;
        assert!(is_soap_fault(fault));
        let ok = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="urn:upnp"><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>"#;
        assert!(!is_soap_fault(ok));
    }
}
