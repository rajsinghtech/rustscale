//! DNS response observation — parse DNS answers, match against configured
//! domains, schedule route advertisements.
//!
//! Ports Go's `appc/observe.go`. The [`AppConnector::observe_dns_response`]
//! method is the callback invoked by the DNS resolver when a DNS response is
//! being returned over PeerAPI. The response is parsed and matched against
//! the configured domains; if matched, the route advertiser is advised to
//! advertise the discovered route.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::connector::AppConnector;
use crate::routes::Prefix;

/// DNS record type numbers (subset needed for observation).
const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const CLASS_INET: u16 = 1;

impl AppConnector {
    /// Observe a DNS response and schedule route advertisements for any
    /// newly discovered IPs that match configured domains.
    ///
    /// Ports Go's `ObserveDNSResponse`. The response is parsed for CNAME
    /// chains and A/AAAA records. For each address record, the connector
    /// follows the CNAME chain to find a matching configured domain (exact
    /// or wildcard). If the resolved IP is not already known, a route
    /// advertisement is scheduled.
    pub fn observe_dns_response(&self, res: &[u8]) -> Result<(), crate::connector::AppcError> {
        let parsed = parse_dns_response(res)?;

        // Collect (domain, routes_to_advertise) pairs under the lock, then
        // schedule advertisements outside the lock to avoid deadlocks.
        let to_schedule: Vec<(String, Vec<Prefix>)> = {
            let mut state = self.state.lock().unwrap();

            let mut scheduled = Vec::new();
            for (domain, addrs) in &parsed.address_records {
                let (domain, is_routed) =
                    Self::find_routed_domain_locked(&state, domain.clone(), &parsed.cname_chain);

                if !is_routed {
                    continue;
                }

                let mut to_advertise = Vec::new();
                for addr in addrs {
                    if !Self::is_addr_known_locked(&mut state, &domain, *addr) {
                        to_advertise.push(Prefix::from_addr(*addr));
                    }
                }

                if !to_advertise.is_empty() {
                    (self.logf)(&format!(
                        "observed new routes for {domain}: {to_advertise:?}"
                    ));
                    scheduled.push((domain, to_advertise));
                }
            }
            scheduled
        };

        // Schedule advertisements outside the lock.
        for (domain, routes) in to_schedule {
            self.schedule_advertisement(&domain, &routes);
        }

        Ok(())
    }
}

/// A parsed DNS response with CNAME chains and address records.
struct ParsedDnsResponse {
    /// CNAME chain: maps CNAME target → original name (the name the CNAME
    /// record answers). For `www.example.com CNAME example.com`, the map
    /// contains `["example.com"] = "www.example.com"`.
    cname_chain: BTreeMap<String, String>,
    /// Address records: maps domain → resolved IP addresses.
    address_records: BTreeMap<String, Vec<IpAddr>>,
}

/// Parse a DNS response message, extracting CNAME chains and A/AAAA records.
/// Ports Go's `ObserveDNSResponse` parsing logic.
fn parse_dns_response(res: &[u8]) -> Result<ParsedDnsResponse, crate::connector::AppcError> {
    if res.len() < 12 {
        return Err(crate::connector::AppcError::DnsParse(
            "response too short for header".into(),
        ));
    }

    let qdcount = u16::from_be_bytes([res[4], res[5]]) as usize;
    let ancount = u16::from_be_bytes([res[6], res[7]]) as usize;

    // Skip the question section.
    let mut pos = 12;
    for _ in 0..qdcount {
        let (_, after) = parse_name(res, pos)
            .ok_or_else(|| crate::connector::AppcError::DnsParse("bad question name".into()))?;
        pos = after + 4; // skip QTYPE (2) + QCLASS (2)
        if pos > res.len() {
            return Err(crate::connector::AppcError::DnsParse(
                "question section truncated".into(),
            ));
        }
    }

    let mut cname_chain: BTreeMap<String, String> = BTreeMap::new();
    let mut address_records: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();

    for _ in 0..ancount {
        if pos >= res.len() {
            break;
        }

        let (name, after_name) = parse_name(res, pos)
            .ok_or_else(|| crate::connector::AppcError::DnsParse("bad answer name".into()))?;
        pos = after_name;

        if pos + 10 > res.len() {
            return Err(crate::connector::AppcError::DnsParse(
                "answer header truncated".into(),
            ));
        }

        let rtype = u16::from_be_bytes([res[pos], res[pos + 1]]);
        let rclass = u16::from_be_bytes([res[pos + 2], res[pos + 3]]);
        // TTL: res[pos+4..pos+8]
        let rdlen = u16::from_be_bytes([res[pos + 8], res[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlen > res.len() {
            return Err(crate::connector::AppcError::DnsParse(
                "rdata truncated".into(),
            ));
        }

        let rdata = &res[pos..pos + rdlen];
        pos += rdlen;

        if rclass != CLASS_INET {
            continue;
        }

        let domain = name.trim_end_matches('.').to_lowercase();
        if domain.is_empty() {
            continue;
        }

        match rtype {
            TYPE_CNAME => {
                let (cname, _) = match parse_name(res, pos - rdlen) {
                    Some(v) => v,
                    None => continue,
                };
                let cname = cname.trim_end_matches('.').to_lowercase();
                if !cname.is_empty() {
                    cname_chain.insert(cname, domain);
                }
            }
            TYPE_A => {
                if rdata.len() != 4 {
                    continue;
                }
                let addr = IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
                address_records.entry(domain).or_default().push(addr);
            }
            TYPE_AAAA => {
                if rdata.len() != 16 {
                    continue;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                let addr = IpAddr::V6(Ipv6Addr::from(octets));
                address_records.entry(domain).or_default().push(addr);
            }
            _ => {}
        }
    }

    Ok(ParsedDnsResponse {
        cname_chain,
        address_records,
    })
}

/// Decode a DNS name at `pos`, following compression pointers. Returns the
/// dotted name (without trailing dot) and the offset immediately after the
/// name in the original message.
fn parse_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut after = None;
    let mut jumped = false;
    let mut hops = 0;

    loop {
        if pos >= buf.len() || hops > 64 {
            return None;
        }
        let len = buf[pos];
        if len == 0 {
            if !jumped && after.is_none() {
                after = Some(pos + 1);
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return None;
            }
            if !jumped && after.is_none() {
                after = Some(pos + 2);
            }
            let offset = ((len as usize & 0x3F) << 8) | buf[pos + 1] as usize;
            pos = offset;
            jumped = true;
            hops += 1;
            continue;
        }
        let label_len = len as usize;
        if pos + 1 + label_len > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[pos + 1..pos + 1 + label_len]).ok()?;
        labels.push(label.to_string());
        pos += 1 + label_len;
    }

    Some((labels.join("."), after.unwrap_or(pos)))
}

/// Test helpers for building DNS response packets. Public so other crates
/// can use them in integration tests.
#[allow(dead_code)]
pub mod test_helpers {
    use super::{CLASS_INET, TYPE_A, TYPE_AAAA, TYPE_CNAME};
    use std::net::IpAddr;

    /// Build a minimal DNS A response for `domain` → `address`.
    /// Ports Go's `dnsResponse` test helper.
    pub fn dns_response(domain: &str, address: &str) -> Vec<u8> {
        let addr: IpAddr = address.parse().unwrap();
        build_dns_response(&[(domain, addr)])
    }

    /// Build a DNS CNAME chain response ending in an A/AAAA record.
    /// Ports Go's `dnsCNAMEResponse` test helper.
    pub fn dns_cname_response(address: &str, domains: &[&str]) -> Vec<u8> {
        // domains is a chain: domains[0] CNAME domains[1], domains[1] CNAME domains[2], ...
        // The last domain has the A/AAAA record.
        let addr: IpAddr = address.parse().unwrap();

        let mut builder = DnsBuilder::new();
        for i in 0..domains.len() - 1 {
            builder.add_cname_record(domains[i], domains[i + 1]);
        }
        builder.add_addr_record(domains[domains.len() - 1], &addr);
        builder.finish()
    }

    fn build_dns_response(records: &[(&str, IpAddr)]) -> Vec<u8> {
        let mut builder = DnsBuilder::new();
        for (domain, addr) in records {
            builder.add_addr_record(domain, addr);
        }
        builder.finish()
    }

    struct DnsBuilder {
        buf: Vec<u8>,
        ancount: u16,
    }

    impl DnsBuilder {
        fn new() -> Self {
            // Header: ID=0, flags=0x8000 (QR=1), QDCOUNT=0, ANCOUNT=0,
            // NSCOUNT=0, ARCOUNT=0.
            let mut buf = Vec::new();
            buf.extend_from_slice(&0u16.to_be_bytes()); // ID
            buf.extend_from_slice(&0x8000u16.to_be_bytes()); // flags: QR=1
            buf.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
            buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT (placeholder)
            buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
            buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
            Self { buf, ancount: 0 }
        }

        fn add_cname_record(&mut self, name: &str, target: &str) {
            self.encode_name(name);
            self.buf.extend_from_slice(&TYPE_CNAME.to_be_bytes());
            self.buf.extend_from_slice(&CLASS_INET.to_be_bytes());
            self.buf.extend_from_slice(&0u32.to_be_bytes()); // TTL
            let rdlen_pos = self.buf.len();
            self.buf.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH placeholder
            let rd_start = self.buf.len();
            self.encode_name(target);
            let rdlen = (self.buf.len() - rd_start) as u16;
            self.buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlen.to_be_bytes());
            self.ancount += 1;
        }

        fn add_addr_record(&mut self, name: &str, addr: &IpAddr) {
            let (rtype, rdata): (u16, &[u8]) = match addr {
                IpAddr::V4(v4) => (TYPE_A, &v4.octets()),
                IpAddr::V6(v6) => (TYPE_AAAA, &v6.octets()),
            };
            self.encode_name(name);
            self.buf.extend_from_slice(&rtype.to_be_bytes());
            self.buf.extend_from_slice(&CLASS_INET.to_be_bytes());
            self.buf.extend_from_slice(&0u32.to_be_bytes()); // TTL
            self.buf
                .extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
            self.buf.extend_from_slice(rdata);
            self.ancount += 1;
        }

        fn encode_name(&mut self, name: &str) {
            let name = name.trim_end_matches('.');
            if name.is_empty() {
                self.buf.push(0);
                return;
            }
            for label in name.split('.') {
                self.buf.push(label.len() as u8);
                self.buf.extend_from_slice(label.as_bytes());
            }
            self.buf.push(0);
        }

        fn finish(mut self) -> Vec<u8> {
            self.buf[6..8].copy_from_slice(&self.ancount.to_be_bytes());
            self.buf
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_dns_response, test_helpers};
    use crate::routes::Prefix;
    use std::net::IpAddr;
    use test_helpers::{dns_cname_response, dns_response};

    #[test]
    fn parse_simple_a_response() {
        let resp = dns_response("example.com.", "192.0.0.8");
        let parsed = parse_dns_response(&resp).unwrap();
        assert_eq!(parsed.cname_chain.len(), 0);
        assert_eq!(parsed.address_records.len(), 1);
        let addrs = parsed.address_records.get("example.com").unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "192.0.0.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_aaaa_response() {
        let resp = dns_response("example.com.", "2001:db8::1");
        let parsed = parse_dns_response(&resp).unwrap();
        let addrs = parsed.address_records.get("example.com").unwrap();
        assert_eq!(addrs[0], "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_cname_chain() {
        let resp = dns_cname_response(
            "192.0.0.9",
            &["www.example.com.", "chain.example.com.", "example.com."],
        );
        let parsed = parse_dns_response(&resp).unwrap();
        // CNAME chain: chain.example.com → www.example.com, example.com → chain.example.com
        assert_eq!(
            parsed.cname_chain.get("chain.example.com"),
            Some(&"www.example.com".to_string())
        );
        assert_eq!(
            parsed.cname_chain.get("example.com"),
            Some(&"chain.example.com".to_string())
        );
        // Address record at the end of the chain.
        assert_eq!(parsed.address_records.len(), 1);
        let addrs = parsed.address_records.get("example.com").unwrap();
        assert_eq!(addrs[0], "192.0.0.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn observe_dns_no_domains_no_advertise() {
        use crate::connector::{AppConnector, AppConnectorConfig, RouteCollector};
        let rc = std::sync::Arc::new(RouteCollector::new());
        let a = AppConnector::new(AppConnectorConfig {
            logf: Box::new(|_| {}),
            route_advertiser: Some(Box::new(rc.clone())),
            route_info: None,
            has_stored_routes: false,
        });

        let resp = dns_response("example.com.", "192.0.0.8");
        a.observe_dns_response(&resp).unwrap();
        a.wait();
        assert!(rc.routes().is_empty());
    }

    #[test]
    fn observe_dns_matching_domain_advertises() {
        use crate::connector::{AppConnector, AppConnectorConfig, RouteCollector};
        let rc = std::sync::Arc::new(RouteCollector::new());
        let a = AppConnector::new(AppConnectorConfig {
            logf: Box::new(|_| {}),
            route_advertiser: Some(Box::new(rc.clone())),
            route_info: None,
            has_stored_routes: false,
        });

        a.update_domains(vec!["example.com".into()]);
        a.wait();

        let resp = dns_response("example.com.", "192.0.0.8");
        a.observe_dns_response(&resp).unwrap();
        a.wait();

        assert_eq!(rc.routes(), vec![Prefix::parse("192.0.0.8/32").unwrap()]);
    }

    #[test]
    fn observe_dns_cname_chain_advertises() {
        use crate::connector::{AppConnector, AppConnectorConfig, RouteCollector};
        let rc = std::sync::Arc::new(RouteCollector::new());
        let a = AppConnector::new(AppConnectorConfig {
            logf: Box::new(|_| {}),
            route_advertiser: Some(Box::new(rc.clone())),
            route_info: None,
            has_stored_routes: false,
        });

        a.update_domains(vec!["www.example.com".into(), "example.com".into()]);
        a.wait();

        // CNAME chain: www.example.com → chain.example.com → example.com
        let resp = dns_cname_response(
            "192.0.0.9",
            &["www.example.com.", "chain.example.com.", "example.com."],
        );
        a.observe_dns_response(&resp).unwrap();
        a.wait();

        assert_eq!(rc.routes(), vec![Prefix::parse("192.0.0.9/32").unwrap()]);
    }

    #[test]
    fn observe_dns_cname_chain_mid_match() {
        use crate::connector::{AppConnector, AppConnectorConfig, RouteCollector};
        let rc = std::sync::Arc::new(RouteCollector::new());
        let a = AppConnector::new(AppConnectorConfig {
            logf: Box::new(|_| {}),
            route_advertiser: Some(Box::new(rc.clone())),
            route_info: None,
            has_stored_routes: false,
        });

        a.update_domains(vec!["www.example.com".into(), "example.com".into()]);
        a.wait();

        // CNAME chain: outside.example.org → www.example.com → example.org
        // The mid-chain www.example.com should match.
        let resp = dns_cname_response(
            "192.0.0.10",
            &["outside.example.org.", "www.example.com.", "example.org."],
        );
        a.observe_dns_response(&resp).unwrap();
        a.wait();

        assert_eq!(rc.routes(), vec![Prefix::parse("192.0.0.10/32").unwrap()]);
    }

    #[test]
    fn observe_dns_no_duplicate_advertise() {
        use crate::connector::{AppConnector, AppConnectorConfig, RouteCollector};
        let rc = std::sync::Arc::new(RouteCollector::new());
        let a = AppConnector::new(AppConnectorConfig {
            logf: Box::new(|_| {}),
            route_advertiser: Some(Box::new(rc.clone())),
            route_info: None,
            has_stored_routes: false,
        });

        a.update_domains(vec!["example.com".into()]);
        a.wait();

        let resp = dns_response("example.com.", "2001:db8::1");
        a.observe_dns_response(&resp).unwrap();
        a.wait();
        assert_eq!(rc.routes().len(), 1);

        // Same response again — should not re-advertise.
        a.observe_dns_response(&resp).unwrap();
        a.wait();
        assert_eq!(rc.routes().len(), 1);
    }

    #[test]
    fn observe_dns_control_route_not_advertised() {
        use crate::connector::{AppConnector, AppConnectorConfig, RouteCollector};
        let rc = std::sync::Arc::new(RouteCollector::new());
        let a = AppConnector::new(AppConnectorConfig {
            logf: Box::new(|_| {}),
            route_advertiser: Some(Box::new(rc.clone())),
            route_info: None,
            has_stored_routes: false,
        });

        a.update_domains(vec!["example.com".into()]);
        a.update_routes(&[Prefix::parse("192.0.2.0/24").unwrap()]);
        a.wait();

        // 192.0.2.1 is within the control route 192.0.2.0/24 — should not
        // be advertised as a separate /32.
        let resp = dns_response("example.com.", "192.0.2.1");
        a.observe_dns_response(&resp).unwrap();
        a.wait();

        // The control route is in rc.routes(), but not 192.0.2.1/32.
        assert!(
            !rc.routes()
                .iter()
                .any(|p| p == &Prefix::parse("192.0.2.1/32").unwrap()),
            "192.0.2.1/32 should not be advertised when covered by 192.0.2.0/24"
        );
    }

    #[test]
    fn observe_dns_wildcard_domain() {
        use crate::connector::{AppConnector, AppConnectorConfig, RouteCollector};
        let rc = std::sync::Arc::new(RouteCollector::new());
        let a = AppConnector::new(AppConnectorConfig {
            logf: Box::new(|_| {}),
            route_advertiser: Some(Box::new(rc.clone())),
            route_info: None,
            has_stored_routes: false,
        });

        a.update_domains(vec!["*.example.com".into()]);
        a.wait();

        let resp = dns_response("foo.example.com.", "192.0.0.8");
        a.observe_dns_response(&resp).unwrap();
        a.wait();

        assert_eq!(rc.routes(), vec![Prefix::parse("192.0.0.8/32").unwrap()]);
    }

    #[test]
    fn parse_empty_response() {
        let resp = dns_response("example.com.", "192.0.0.8");
        // Just verify it doesn't panic.
        let parsed = parse_dns_response(&resp).unwrap();
        assert!(parsed.address_records.contains_key("example.com"));
    }

    #[test]
    fn parse_truncated_header_returns_error() {
        let resp = [0u8; 5];
        assert!(parse_dns_response(&resp).is_err());
    }
}
