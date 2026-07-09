//! Minimal XML text extractor for UPnP root-desc parsing.
//!
//! UPnP root device descriptors are simple XML documents. We don't need a
//! full XML parser — just enough to extract `<service>` blocks with their
//! `<serviceType>`, `<serviceId>`, `<controlURL>`, and `<SCPDURL>` children,
//! plus `<deviceType>` and `<friendlyName>` for logging. This hand-rolled
//! extractor mirrors Go's pragmatic approach (it uses `encoding/xml` but
//! only for simple structs).

/// A discovered UPnP service in a root device descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceDesc {
    pub service_type: String,
    pub service_id: String,
    pub control_url: String,
    #[allow(dead_code)]
    pub scpd_url: String,
}

/// Extract all `<service>` blocks from a UPnP root-desc XML document.
///
/// This is a simple tag-matching extractor: it finds `<service>` ...
/// `</service>` blocks and pulls out the text content of each known child
/// element. It handles the common case of well-formed UPnP descriptors
/// produced by real routers.
pub(crate) fn extract_services(xml: &str) -> Vec<ServiceDesc> {
    let mut services = Vec::new();
    let mut search_start = 0;
    while let Some(rel_start) = xml[search_start..].find("<service>") {
        let start = search_start + rel_start;
        let block_end = match xml[start..].find("</service>") {
            Some(rel) => start + rel + "</service>".len(),
            None => break,
        };
        let block = &xml[start..block_end];
        services.push(ServiceDesc {
            service_type: extract_text(block, "serviceType").unwrap_or_default(),
            service_id: extract_text(block, "serviceId").unwrap_or_default(),
            control_url: extract_text(block, "controlURL").unwrap_or_default(),
            scpd_url: extract_text(block, "SCPDURL").unwrap_or_default(),
        });
        search_start = block_end;
    }
    services
}

/// Extract the text content of the first `<tag>...</tag>` occurrence in `s`.
fn extract_text(s: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = s.find(&open)? + open.len();
    let end = s[start..].find(&close)? + start;
    Some(s[start..end].trim().to_string())
}

/// Extract the friendly name from a root-desc XML document (for logging).
#[allow(dead_code)]
pub(crate) fn extract_friendly_name(xml: &str) -> Option<String> {
    extract_text(xml, "friendlyName")
}

/// Whether a service type string names a UPnP IGD WAN connection service we
/// can use for port mapping. Returns the "kind" for preference ordering:
/// `0` = WANIPConnection2 (best), `1` = WANIPConnection1, `2` =
/// WANPPPConnection1, `3` = legacy dslforum variants.
pub(crate) fn igd_service_kind(service_type: &str) -> Option<u8> {
    if service_type == "urn:schemas-upnp-org:service:WANIPConnection:2" {
        Some(0)
    } else if service_type == "urn:schemas-upnp-org:service:WANIPConnection:1" {
        Some(1)
    } else if service_type == "urn:schemas-upnp-org:service:WANPPPConnection:1" {
        Some(2)
    } else if service_type == "urn:dslforum-org:service:WANPPPConnection:1"
        || service_type == "urn:dslforum-org:service:WANIPConnection:1"
    {
        Some(3)
    } else {
        None
    }
}

/// The SOAP service type URN corresponding to an IGD service kind (for
/// building SOAP action headers).
pub(crate) fn soap_service_type(kind: u8) -> &'static str {
    match kind {
        0 => "urn:schemas-upnp-org:service:WANIPConnection:2",
        1 => "urn:schemas-upnp-org:service:WANIPConnection:1",
        2 => "urn:schemas-upnp-org:service:WANPPPConnection:1",
        3 => "urn:dslforum-org:service:WANPPPConnection:1",
        _ => "urn:schemas-upnp-org:service:WANIPConnection:1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ROOT_DESC: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Tailscale Test Router</friendlyName>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
        <serviceList>
          <service>
            <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
            <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
            <SCPDURL>/WANIPCn.xml</SCPDURL>
            <controlURL>/ctl/IPConn</controlURL>
            <eventSubURL>/evt/IPConn</eventSubURL>
          </service>
        </serviceList>
      </device>
    </deviceList>
  </device>
</root>"#;

    #[test]
    fn extract_services_from_test_desc() {
        let svcs = extract_services(TEST_ROOT_DESC);
        assert_eq!(svcs.len(), 1);
        assert_eq!(
            svcs[0].service_type,
            "urn:schemas-upnp-org:service:WANIPConnection:1"
        );
        assert_eq!(svcs[0].control_url, "/ctl/IPConn");
        assert_eq!(svcs[0].scpd_url, "/WANIPCn.xml");
    }

    #[test]
    fn igd_service_kind_recognizes_variants() {
        assert_eq!(
            igd_service_kind("urn:schemas-upnp-org:service:WANIPConnection:2"),
            Some(0)
        );
        assert_eq!(
            igd_service_kind("urn:schemas-upnp-org:service:WANIPConnection:1"),
            Some(1)
        );
        assert_eq!(
            igd_service_kind("urn:schemas-upnp-org:service:WANPPPConnection:1"),
            Some(2)
        );
        assert_eq!(
            igd_service_kind("urn:dslforum-org:service:WANPPPConnection:1"),
            Some(3)
        );
        assert_eq!(
            igd_service_kind("urn:schemas-upnp-org:service:Layer3Forwarding:1"),
            None
        );
    }

    #[test]
    fn extract_friendly_name_works() {
        assert_eq!(
            extract_friendly_name(TEST_ROOT_DESC),
            Some("Tailscale Test Router".to_string())
        );
    }
}
