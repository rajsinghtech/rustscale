use super::*;

/// Build a synthetic `rt_msghdr` message with the given flags, interface
/// index, and sockaddr body.
fn make_rt_msg(msg_type: u8, index: u16, flags: i32, addrs_bitmask: i32, body: &[u8]) -> Vec<u8> {
    let total_len = RT_MSGHDR_SIZE + body.len();
    let mut msg = vec![0u8; total_len];
    // rtm_msglen (u16 LE)
    msg[0..2].copy_from_slice(&(total_len as u16).to_le_bytes());
    // rtm_version
    msg[2] = libc::RTM_VERSION as u8;
    // rtm_type
    msg[3] = msg_type;
    // rtm_index (u16 LE)
    msg[4..6].copy_from_slice(&index.to_le_bytes());
    // rtm_flags (i32 LE) at offset 8
    msg[8..12].copy_from_slice(&flags.to_le_bytes());
    // rtm_addrs (i32 LE) at offset 12
    msg[12..16].copy_from_slice(&addrs_bitmask.to_le_bytes());
    // Body (sockaddrs) at offset RT_MSGHDR_SIZE
    msg[RT_MSGHDR_SIZE..].copy_from_slice(body);
    msg
}

/// Build a sockaddr_in (AF_INET) for the given IPv4 address.
fn sockaddr_in4(ip: Ipv4Addr) -> Vec<u8> {
    let mut buf = vec![0u8; 16]; // SOCKADDR_IN_SIZE = 16, aligned to 4
    buf[0] = SOCKADDR_IN_SIZE; // sa_len
    buf[1] = AF_INET; // sa_family
    buf[4..8].copy_from_slice(&ip.octets());
    buf
}

/// Build a sockaddr_in6 (AF_INET6) for the given IPv6 address.
fn sockaddr_in6(ip: Ipv6Addr) -> Vec<u8> {
    let mut buf = vec![0u8; 28]; // SOCKADDR_IN6_SIZE = 28, aligned to 4
    buf[0] = SOCKADDR_IN6_SIZE; // sa_len
    buf[1] = AF_INET6; // sa_family
    buf[8..24].copy_from_slice(&ip.octets());
    buf
}

/// Build a netmask sockaddr with sa_len=0 (kernel form for 0.0.0.0/0 mask
/// on darwin). The kernel writes 4 bytes of filler, aligned to 4.
fn sockaddr_zero_mask() -> Vec<u8> {
    vec![0u8; 4]
}

/// RTA bitmask for DST | GATEWAY | NETMASK.
const RTA_DST_GW_MASK: i32 = (1 << RTAX_DST) | (1 << RTAX_GATEWAY) | (1 << RTAX_NETMASK);

// -------------------------------------------------------------------------
// is_default_gateway tests
// -------------------------------------------------------------------------

#[test]
fn test_is_default_gateway_v4() {
    let body = [
        sockaddr_in4(Ipv4Addr::UNSPECIFIED),         // DST = 0.0.0.0
        sockaddr_in4(Ipv4Addr::new(192, 168, 1, 1)), // GATEWAY
        sockaddr_zero_mask(),                        // NETMASK = 0.0.0.0
    ]
    .concat();
    let addrs = parse_sockaddrs(&body, RTA_DST_GW_MASK);
    assert!(is_default_gateway(libc::RTF_GATEWAY, &addrs));
}

#[test]
fn test_is_default_gateway_v6() {
    let body = [
        sockaddr_in6(Ipv6Addr::UNSPECIFIED), // DST = ::
        sockaddr_in6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), // GATEWAY
        sockaddr_zero_mask(),                // NETMASK = ::
    ]
    .concat();
    let addrs = parse_sockaddrs(&body, RTA_DST_GW_MASK);
    assert!(is_default_gateway(libc::RTF_GATEWAY, &addrs));
}

#[test]
fn test_not_default_gateway_no_gateway_flag() {
    let body = [
        sockaddr_in4(Ipv4Addr::UNSPECIFIED),
        sockaddr_in4(Ipv4Addr::new(192, 168, 1, 1)),
        sockaddr_zero_mask(),
    ]
    .concat();
    let addrs = parse_sockaddrs(&body, RTA_DST_GW_MASK);
    assert!(!is_default_gateway(0, &addrs));
}

#[test]
fn test_not_default_gateway_ifscope() {
    let body = [
        sockaddr_in4(Ipv4Addr::UNSPECIFIED),
        sockaddr_in4(Ipv4Addr::new(192, 168, 1, 1)),
        sockaddr_zero_mask(),
    ]
    .concat();
    let addrs = parse_sockaddrs(&body, RTA_DST_GW_MASK);
    assert!(!is_default_gateway(libc::RTF_GATEWAY | RTF_IFSCOPE, &addrs));
}

#[test]
fn test_not_default_gateway_nonzero_dst() {
    let body = [
        sockaddr_in4(Ipv4Addr::new(10, 0, 0, 0)), // DST = 10.0.0.0 (not default)
        sockaddr_in4(Ipv4Addr::new(192, 168, 1, 1)),
        sockaddr_in4(Ipv4Addr::new(255, 0, 0, 0)), // NETMASK = 255.0.0.0
    ]
    .concat();
    let addrs = parse_sockaddrs(&body, RTA_DST_GW_MASK);
    assert!(!is_default_gateway(libc::RTF_GATEWAY, &addrs));
}

#[test]
fn test_not_default_gateway_missing_netmask() {
    let rta = (1 << RTAX_DST) | (1 << RTAX_GATEWAY); // no NETMASK bit
    let body = [
        sockaddr_in4(Ipv4Addr::UNSPECIFIED),
        sockaddr_in4(Ipv4Addr::new(192, 168, 1, 1)),
    ]
    .concat();
    let addrs = parse_sockaddrs(&body, rta);
    assert!(!is_default_gateway(libc::RTF_GATEWAY, &addrs));
}

// -------------------------------------------------------------------------
// parse_sockaddrs tests
// -------------------------------------------------------------------------

#[test]
fn test_parse_sockaddrs_v4() {
    let body = [
        sockaddr_in4(Ipv4Addr::new(192, 168, 1, 10)),  // DST
        sockaddr_in4(Ipv4Addr::new(192, 168, 1, 1)),   // GATEWAY
        sockaddr_in4(Ipv4Addr::new(255, 255, 255, 0)), // NETMASK
    ]
    .concat();
    let addrs = parse_sockaddrs(&body, RTA_DST_GW_MASK);
    assert_eq!(addrs.len(), RTAX_MAX);
    assert!(matches!(
        addrs[RTAX_DST],
        Some(SockAddr::Inet4(ip)) if ip == Ipv4Addr::new(192, 168, 1, 10)
    ));
    assert!(matches!(
        addrs[RTAX_GATEWAY],
        Some(SockAddr::Inet4(ip)) if ip == Ipv4Addr::new(192, 168, 1, 1)
    ));
    assert!(matches!(
        addrs[RTAX_NETMASK],
        Some(SockAddr::Inet4(ip)) if ip == Ipv4Addr::new(255, 255, 255, 0)
    ));
}

#[test]
fn test_parse_sockaddrs_zero_mask() {
    let body = [
        sockaddr_in4(Ipv4Addr::UNSPECIFIED),
        sockaddr_in4(Ipv4Addr::new(10, 0, 0, 1)),
        sockaddr_zero_mask(),
    ]
    .concat();
    let addrs = parse_sockaddrs(&body, RTA_DST_GW_MASK);
    assert!(matches!(
        addrs[RTAX_NETMASK],
        Some(SockAddr::Inet4(ip)) if ip.is_unspecified()
    ));
}

#[test]
fn test_parse_sockaddrs_partial_bitmask() {
    // Only DST and NETMASK present (no GATEWAY).
    let rta = (1 << RTAX_DST) | (1 << RTAX_NETMASK);
    let body = [
        sockaddr_in4(Ipv4Addr::new(10, 0, 0, 0)),
        sockaddr_in4(Ipv4Addr::new(255, 0, 0, 0)),
    ]
    .concat();
    let addrs = parse_sockaddrs(&body, rta);
    assert!(addrs[RTAX_DST].is_some());
    assert!(addrs[RTAX_GATEWAY].is_none());
    assert!(addrs[RTAX_NETMASK].is_some());
}

#[test]
fn test_parse_sockaddrs_link_addr() {
    // Mix of AF_LINK (RTAX_IFP=4) and AF_INET.
    let rta = (1 << RTAX_DST) | (1 << 4); // DST + IFP
    let mut link = vec![0u8; 8]; // AF_LINK sockaddr: len=8, family=AF_LINK
    link[0] = 8;
    link[1] = AF_LINK;
    let body = [sockaddr_in4(Ipv4Addr::new(10, 0, 0, 1)), link].concat();
    let addrs = parse_sockaddrs(&body, rta);
    assert!(matches!(addrs[RTAX_DST], Some(SockAddr::Inet4(_))));
    assert!(matches!(addrs[4], Some(SockAddr::Link)));
}

// -------------------------------------------------------------------------
// Full message parsing tests (synthetic rt_msghdr buffers)
// -------------------------------------------------------------------------

#[test]
fn test_parse_default_gateway_from_synthetic_buffer() {
    let body = [
        sockaddr_in4(Ipv4Addr::UNSPECIFIED),
        sockaddr_in4(Ipv4Addr::new(192, 168, 1, 1)),
        sockaddr_zero_mask(),
    ]
    .concat();
    let msg = make_rt_msg(
        0x14, // RTM_GET2
        7,    // interface index
        libc::RTF_GATEWAY,
        RTA_DST_GW_MASK,
        &body,
    );

    let mut buf = msg.clone();
    // Append a second non-matching message to ensure the parser skips it.
    let body2 = [
        sockaddr_in4(Ipv4Addr::new(10, 0, 0, 0)),
        sockaddr_in4(Ipv4Addr::new(10, 0, 0, 1)),
        sockaddr_in4(Ipv4Addr::new(255, 0, 0, 0)),
    ]
    .concat();
    let msg2 = make_rt_msg(0x14, 9, libc::RTF_GATEWAY, RTA_DST_GW_MASK, &body2);
    buf.extend_from_slice(&msg2);

    let route = parse_default_gateway(&buf).expect("should find default gateway");
    assert_eq!(route.interface_index, 7);
    assert!(matches!(
        route.gateway,
        Some(IpAddr::V4(ip)) if ip == Ipv4Addr::new(192, 168, 1, 1)
    ));
}

#[test]
fn test_parse_default_gateway_skips_version_mismatch() {
    let body = [
        sockaddr_in4(Ipv4Addr::UNSPECIFIED),
        sockaddr_in4(Ipv4Addr::new(192, 168, 1, 1)),
        sockaddr_zero_mask(),
    ]
    .concat();
    let mut msg = make_rt_msg(0x14, 5, libc::RTF_GATEWAY, RTA_DST_GW_MASK, &body);
    msg[2] = 99; // wrong version — should be skipped

    let route = parse_default_gateway(&msg);
    assert!(route.is_err());
}

#[test]
fn test_parse_default_gateway_not_found() {
    let body = [
        sockaddr_in4(Ipv4Addr::new(10, 0, 0, 0)),
        sockaddr_in4(Ipv4Addr::new(10, 0, 0, 1)),
        sockaddr_in4(Ipv4Addr::new(255, 0, 0, 0)),
    ]
    .concat();
    let msg = make_rt_msg(0x14, 5, libc::RTF_GATEWAY, RTA_DST_GW_MASK, &body);
    let route = parse_default_gateway(&msg);
    assert!(route.is_err());
}

#[test]
fn test_parse_default_gateway_v6_from_synthetic_buffer() {
    let gw_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let body = [
        sockaddr_in6(Ipv6Addr::UNSPECIFIED),
        sockaddr_in6(gw_v6),
        sockaddr_zero_mask(),
    ]
    .concat();
    let msg = make_rt_msg(0x14, 12, libc::RTF_GATEWAY, RTA_DST_GW_MASK, &body);

    let route = parse_default_gateway(&msg).expect("should find v6 default gateway");
    assert_eq!(route.interface_index, 12);
    assert!(matches!(route.gateway, Some(IpAddr::V6(ip)) if ip == gw_v6));
}

#[test]
fn test_parse_default_gateway_empty_buffer() {
    let route = parse_default_gateway(&[]);
    assert!(route.is_err());
}

// -------------------------------------------------------------------------
// utun detection tests
// -------------------------------------------------------------------------

#[test]
fn test_is_utun_name() {
    assert!(is_utun_name("utun0"));
    assert!(is_utun_name("utun99"));
    assert!(is_utun_name("utun")); // prefix match, matches Go's HasPrefix
    assert!(!is_utun_name("en0"));
    assert!(!is_utun_name(""));
    assert!(!is_utun_name("tailscale0"));
}

// -------------------------------------------------------------------------
// macOS integration test (requires a live network connection)
// -------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn test_default_route_interface_index_live() {
    let idx = default_route_interface_index();
    // On a machine with a network connection, we should get a valid index.
    match idx {
        Ok(index) => {
            assert!(index > 0, "interface index should be > 0");
            // The interface should not be a utun (our own tunnel).
            if let Ok(name) = interface_name_by_index(index) {
                assert!(
                    !is_utun_name(&name),
                    "default route should not be a utun interface, got: {name}"
                );
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // No default route — acceptable on a machine with no network.
        }
        Err(e) => {
            panic!("default_route_interface_index failed: {e}");
        }
    }
}
