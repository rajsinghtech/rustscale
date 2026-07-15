//! Null-tolerance property tests for tailcfg wire types.
//!
//! Go's `encoding/json` marshals nil slices as `null` and nil maps as `null`,
//! nil pointers as `null`. This test ensures every field in every major wire
//! type can deserialize from `null` without error — catching the class of bug
//! where `DNSConfig.Routes` map values were null on the wire and deserialization
//! failed.
//!
//! The `assert_null_tolerant` helper takes a sample JSON value, traverses it
//! recursively, and for each object key creates a copy with that key set to
//! `null`, then asserts deserialization succeeds. This catches any future
//! field added without null tolerance.

use rustscale_key::{DiscoPrivate, MachinePrivate, NodePrivate};
use rustscale_tailcfg::{
    CapGrant, DERPMap, DERPNode, DERPRegion, DNSConfig, FilterRule, Hostinfo, Location, Login,
    MapResponse, NetInfo, NetPortRange, Node, PortRange, RegisterResponse, Resolver, Service,
    TPMInfo, User, UserProfile,
};
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Generic null-tolerance property test helper
// ---------------------------------------------------------------------------

/// Collect every path (as a sequence of string keys and array indices) to an
/// object key inside `value`, traversing recursively through nested objects
/// and array elements. Each path identifies a field that can be nullified.
fn collect_null_paths(value: &serde_json::Value, prefix: &[String]) -> Vec<Vec<String>> {
    match value {
        serde_json::Value::Object(map) => {
            let mut paths = Vec::new();
            for (key, val) in map {
                let mut path = prefix.to_vec();
                path.push(key.clone());
                paths.push(path.clone());
                paths.extend(collect_null_paths(val, &path));
            }
            paths
        }
        serde_json::Value::Array(arr) => {
            let mut paths = Vec::new();
            for (i, val) in arr.iter().enumerate() {
                let mut path = prefix.to_vec();
                path.push(i.to_string());
                paths.extend(collect_null_paths(val, &path));
            }
            paths
        }
        _ => Vec::new(),
    }
}

/// Set the value at the given key path to `null` in a clone of `value`.
fn set_null(value: &mut serde_json::Value, path: &[String]) {
    if path.is_empty() {
        *value = serde_json::Value::Null;
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            if path.len() == 1 {
                map.insert(path[0].clone(), serde_json::Value::Null);
            } else if let Some(child) = map.get_mut(&path[0]) {
                set_null(child, &path[1..]);
            }
        }
        serde_json::Value::Array(arr) => {
            if let Ok(idx) = path[0].parse::<usize>() {
                if path.len() == 1 {
                    if idx < arr.len() {
                        arr[idx] = serde_json::Value::Null;
                    }
                } else if idx < arr.len() {
                    set_null(&mut arr[idx], &path[1..]);
                }
            }
        }
        _ => {}
    }
}

/// Assert that deserializing `T` from `sample_json` succeeds when **any single
/// field** (at any nesting depth) is replaced with `null`.
///
/// This is the reusable helper enforced forever: if a new field is added
/// without null tolerance, this test will fail with a clear message showing
/// which path caused the failure.
fn assert_null_tolerant<T>(sample: &serde_json::Value)
where
    T: DeserializeOwned,
{
    let paths = collect_null_paths(sample, &[]);
    assert!(
        !paths.is_empty(),
        "sample JSON has no object fields to nullify"
    );
    for path in &paths {
        let mut modified = sample.clone();
        set_null(&mut modified, path);
        let json_str = serde_json::to_string(&modified).unwrap();
        let result: Result<T, _> = serde_json::from_str(&json_str);
        assert!(
            result.is_ok(),
            "Deserialization of {} failed when nullifying path {:?}:\n  error: {}\n  JSON:  {}",
            std::any::type_name::<T>(),
            path,
            result.err().unwrap(),
            json_str
        );
    }
}

// ---------------------------------------------------------------------------
// Sample builders — richly populated values with all fields set
// ---------------------------------------------------------------------------

fn sample_hostinfo() -> Hostinfo {
    Hostinfo {
        IPNVersion: "1.99.0".into(),
        FrontendLogID: "fe-log-id".into(),
        BackendLogID: "be-log-id".into(),
        OS: "linux".into(),
        OSVersion: "6.8.0".into(),
        Container: rustscale_tailcfg::OptBool::True,
        Env: "k8s".into(),
        Distro: "ubuntu".into(),
        DistroVersion: "22.04".into(),
        DistroCodeName: "jammy".into(),
        App: "tsnet".into(),
        Desktop: rustscale_tailcfg::OptBool::False,
        Package: "snap".into(),
        DeviceModel: "raspberrypi".into(),
        PushDeviceToken: "token-abc".into(),
        Hostname: "host.example.com".into(),
        ShieldsUp: true,
        ShareeNode: false,
        NoLogsNoSupport: false,
        WireIngress: true,
        IngressEnabled: false,
        AllowsUpdate: true,
        Machine: "x86_64".into(),
        GoArch: "amd64".into(),
        GoArchVar: "v1".into(),
        GoVersion: "go1.22".into(),
        Services: vec![Service {
            Proto: "peerapi4".into(),
            Port: 1234,
            Description: "peerapi".into(),
        }],
        RoutableIPs: vec!["192.168.1.0/24".into()],
        RequestTags: vec!["tag:prod".into()],
        WoLMACs: vec!["aa:bb:cc:dd:ee:ff".into()],
        SSH_HostKeys: vec!["ssh-ed25519 AAAA...".into()],
        NetInfo: Some(sample_netinfo()),
        Cloud: "gcp".into(),
        Userspace: rustscale_tailcfg::OptBool::True,
        UserspaceRouter: rustscale_tailcfg::OptBool::False,
        AppConnector: rustscale_tailcfg::OptBool::Unset,
        PeerRelay: true,
        ServicesHash: "deadbeef".into(),
        ExitNodeID: "nodeXYZ123".into(),
        Location: Some(Location {
            Country: "Canada".into(),
            CountryCode: "CA".into(),
            Priority: 10,
        }),
        TPM: Some(TPMInfo {
            Manufacturer: "MSFT".into(),
            Vendor: "MSFT".into(),
            Model: 42,
            FirmwareVersion: 511,
            SpecRevision: 127,
            FamilyIndicator: "2.0".into(),
        }),
        StateEncrypted: rustscale_tailcfg::OptBool::True,
    }
}

fn sample_netinfo() -> NetInfo {
    let mut latency = BTreeMap::new();
    latency.insert("1-v4".to_string(), 0.012);
    latency.insert("1-v6".to_string(), 0.020);
    NetInfo {
        MappingVariesByDestIP: rustscale_tailcfg::OptBool::False,
        WorkingIPv6: rustscale_tailcfg::OptBool::True,
        OSHasIPv6: rustscale_tailcfg::OptBool::True,
        WorkingUDP: rustscale_tailcfg::OptBool::True,
        WorkingICMPv4: rustscale_tailcfg::OptBool::True,
        HavePortMap: true,
        UPnP: rustscale_tailcfg::OptBool::False,
        PMP: rustscale_tailcfg::OptBool::True,
        PCP: rustscale_tailcfg::OptBool::False,
        PreferredDERP: 1,
        LinkType: "wired".into(),
        DERPLatency: latency,
        FirewallMode: "nft".into(),
    }
}

fn sample_node() -> Node {
    let np = NodePrivate::generate().public();
    let mp = MachinePrivate::generate().public();
    let dp = DiscoPrivate::generate().public();
    Node {
        ID: 42,
        StableID: "nodeABC".into(),
        Name: "host.tail-scale.ts.net.".into(),
        User: 7,
        Key: np,
        KeyExpiry: Some(
            chrono::DateTime::parse_from_rfc3339("2025-12-31T23:59:59Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        ),
        KeySignature: None,
        Machine: mp,
        DiscoKey: dp,
        Addresses: vec!["100.64.0.1/32".into(), "fd7a:115c::1/128".into()],
        AllowedIPs: vec!["100.64.0.1/32".into()],
        PrimaryRoutes: vec!["192.168.1.0/24".into()],
        Endpoints: vec!["1.2.3.4:5".into(), "[::1]:6".into()],
        HomeDERP: 1,
        Hostinfo: Some(sample_hostinfo()),
        Created: Some(
            chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        ),
        Cap: 999,
        Tags: vec!["tag:prod".into()],
        LastSeen: None,
        Online: Some(true),
        Capabilities: vec!["https://tailscale.com/cap/file-sharing".into()],
        CapMap: BTreeMap::from([
            ("cap-a".to_string(), vec![]),
            (
                "cap-b".to_string(),
                vec![rustscale_tailcfg::RawMessage("42".into())],
            ),
        ]),
        UnsignedPeerAPIOnly: false,
        Expired: false,
        IsWireGuardOnly: false,
        IsJailed: false,
    }
}

fn sample_dns_config() -> DNSConfig {
    use std::collections::HashMap;
    DNSConfig {
        Resolvers: vec![Resolver {
            Addr: "1.1.1.1".into(),
        }],
        Routes: HashMap::from([(
            "corp.example.com.".to_string(),
            vec![Resolver {
                Addr: "10.0.0.53".into(),
            }],
        )]),
        FallbackResolvers: vec![Resolver {
            Addr: "8.8.8.8".into(),
        }],
        Domains: vec!["ts.net".into(), "tail-scale.ts.net".into()],
        Proxied: true,
        CertDomains: vec!["node.ts.net".into()],
        ExtraRecords: vec![rustscale_tailcfg::DNSRecord {
            Name: "app.ts.net".into(),
            Type: "A".into(),
            Value: "100.64.0.5".into(),
        }],
        Nameservers: vec!["1.1.1.1".into()],
    }
}

fn sample_derpmap() -> DERPMap {
    let mut regions = BTreeMap::new();
    regions.insert(
        1,
        DERPRegion {
            RegionID: 1,
            RegionCode: "nyc".into(),
            RegionName: "New York City".into(),
            Latitude: 40.71,
            Longitude: -74.01,
            Avoid: false,
            NoMeasureNoHome: false,
            Nodes: Some(vec![DERPNode {
                Name: "1a".into(),
                RegionID: 1,
                HostName: "derp1.tailscale.com".into(),
                CertName: "derp1".into(),
                IPv4: "1.2.3.4".into(),
                IPv6: "::1".into(),
                STUNPort: 3478,
                STUNOnly: false,
                DERPPort: 443,
                InsecureForTests: false,
                STUNTestIP: String::new(),
                CanPort80: true,
            }]),
        },
    );
    regions.insert(
        9,
        DERPRegion {
            RegionID: 9,
            RegionCode: "sin".into(),
            RegionName: "Singapore".into(),
            Nodes: Some(vec![]),
            ..Default::default()
        },
    );
    DERPMap {
        HomeParams: Some(rustscale_tailcfg::DERPHomeParams {
            RegionScore: BTreeMap::from([(1, 0.5), (9, 1.0)]),
        }),
        Regions: regions,
        OmitDefaultRegions: false,
    }
}

fn sample_register_response() -> RegisterResponse {
    RegisterResponse {
        User: User {
            ID: 5,
            DisplayName: "Alice".into(),
            ProfilePicURL: "https://x/a.png".into(),
            Created: Some(
                chrono::DateTime::parse_from_rfc3339("2023-06-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
        },
        Login: Login {
            ID: 9,
            Provider: "google".into(),
            LoginName: "alice@example.com".into(),
            DisplayName: "Alice Smith".into(),
            ProfilePicURL: "https://x/alice.png".into(),
        },
        NodeKeyExpired: false,
        MachineAuthorized: true,
        AuthURL: "https://login.tailscale.com/a/x".into(),
        NodeKeySignature: None,
        Error: String::new(),
    }
}

fn sample_filter_rule() -> FilterRule {
    FilterRule {
        SrcIPs: vec![rustscale_tsaddr::cgnat_range().to_string(), "*".into()],
        SrcBits: vec![32, 0],
        DstPorts: vec![NetPortRange {
            IP: "1.2.3.4".into(),
            Bits: Some(32),
            Ports: PortRange {
                First: 22,
                Last: 22,
            },
        }],
        IPProto: vec![6, 17],
        CapGrant: vec![CapGrant {
            Dsts: vec!["0.0.0.0/0".into()],
            Caps: vec!["is-ipv4".into()],
            CapMap: BTreeMap::from([(
                "cap-foo".to_string(),
                vec![rustscale_tailcfg::RawMessage("42".into())],
            )]),
        }],
    }
}

fn sample_map_response() -> MapResponse {
    MapResponse {
        MapSessionHandle: "session-abc".into(),
        Seq: 42,
        KeepAlive: false,
        Node: Some(sample_node()),
        DERPMap: Some(sample_derpmap()),
        Peers: vec![sample_node()],
        PeersChanged: vec![sample_node()],
        PeersRemoved: vec![3, 7],
        Domain: "tail-scale.ts.net".into(),
        DNSConfig: Some(sample_dns_config()),
        UserProfiles: vec![UserProfile {
            ID: 7,
            LoginName: "alice@example.com".into(),
            DisplayName: "Alice".into(),
            ProfilePicURL: "https://x/a.png".into(),
        }],
        PacketFilter: Some(vec![sample_filter_rule()]),
        PacketFilters: Some(BTreeMap::from([
            ("base".to_string(), Some(vec![sample_filter_rule()])),
            ("*".to_string(), None),
        ])),
        NodeKeyExpired: false,
        ControlTime: None,
        CollectServices: rustscale_tailcfg::OptBool::Unset,
        SSHPolicy: None,
        PeersChangedPatch: None,
        NetInfo: None,
        ClientVersion: None,
        SuggestedExitNode: String::new(),
    }
}

// ---------------------------------------------------------------------------
// Property tests — one per major wire type
// ---------------------------------------------------------------------------

#[test]
fn null_tolerant_map_response() {
    let sample = serde_json::to_value(sample_map_response()).unwrap();
    assert_null_tolerant::<MapResponse>(&sample);
}

#[test]
fn null_tolerant_node() {
    let sample = serde_json::to_value(sample_node()).unwrap();
    assert_null_tolerant::<Node>(&sample);
}

#[test]
fn null_tolerant_hostinfo() {
    let sample = serde_json::to_value(sample_hostinfo()).unwrap();
    assert_null_tolerant::<Hostinfo>(&sample);
}

#[test]
fn null_tolerant_netinfo() {
    let sample = serde_json::to_value(sample_netinfo()).unwrap();
    assert_null_tolerant::<NetInfo>(&sample);
}

#[test]
fn null_tolerant_dns_config() {
    let sample = serde_json::to_value(sample_dns_config()).unwrap();
    assert_null_tolerant::<DNSConfig>(&sample);
}

#[test]
fn null_tolerant_derpmap() {
    let sample = serde_json::to_value(sample_derpmap()).unwrap();
    assert_null_tolerant::<DERPMap>(&sample);
}

#[test]
fn null_tolerant_register_response() {
    let sample = serde_json::to_value(sample_register_response()).unwrap();
    assert_null_tolerant::<RegisterResponse>(&sample);
}

// ---------------------------------------------------------------------------
// Fixture test — realistic MapResponse with Go-style nulls sprinkled in
// ---------------------------------------------------------------------------

#[test]
fn realistic_map_response_fixture_with_nulls() {
    // A realistic MapResponse as Go control would send it, with nil slices
    // and maps marshaled as `null` in several places.
    let np = NodePrivate::generate().public();
    let mp = MachinePrivate::generate().public();
    let dp = DiscoPrivate::generate().public();
    let node_key_str = serde_json::to_string(&np).unwrap();
    let machine_key_str = serde_json::to_string(&mp).unwrap();
    let disco_key_str = serde_json::to_string(&dp).unwrap();

    let json = r#"{
      "MapSessionHandle": "session-xyz",
      "Seq": 1,
      "KeepAlive": false,
      "Node": {
        "ID": 100,
        "StableID": "nodeXYZ",
        "Name": "rs-gcp.tail-scale.ts.net.",
        "User": 42,
        "Key": __NODE_KEY__,
        "KeyExpiry": "2025-12-31T23:59:59Z",
        "Machine": __MACHINE_KEY__,
        "DiscoKey": __DISCO_KEY__,
        "Addresses": ["100.64.0.1/32"],
        "AllowedIPs": null,
        "PrimaryRoutes": null,
        "Endpoints": ["1.2.3.4:41641"],
        "HomeDERP": 1,
        "Hostinfo": {
          "IPNVersion": "1.99.0",
          "FrontendLogID": "",
          "BackendLogID": "",
          "OS": "linux",
          "OSVersion": "6.8.0",
          "Container": true,
          "Env": "",
          "Distro": "ubuntu",
          "DistroVersion": "22.04",
          "DistroCodeName": "jammy",
          "App": "tsnet",
          "Hostname": "rs-gcp",
          "ShieldsUp": false,
          "ShareeNode": false,
          "NoLogsNoSupport": false,
          "WireIngress": false,
          "IngressEnabled": false,
          "AllowsUpdate": false,
          "Machine": "x86_64",
          "GoArch": "amd64",
          "GoArchVar": "",
          "GoVersion": "",
          "Services": null,
          "RoutableIPs": null,
          "RequestTags": null,
          "WoLMACs": null,
          "sshHostKeys": null,
          "NetInfo": {
            "MappingVariesByDestIP": false,
            "WorkingIPv6": true,
            "OSHasIPv6": true,
            "WorkingUDP": true,
            "WorkingICMPv4": null,
            "HavePortMap": false,
            "UPnP": null,
            "PMP": null,
            "PCP": null,
            "PreferredDERP": 1,
            "LinkType": "",
            "DERPLatency": {},
            "FirewallMode": ""
          },
          "Cloud": "gcp",
          "Userspace": true,
          "UserspaceRouter": true,
          "AppConnector": null,
          "PeerRelay": false,
          "ServicesHash": "",
          "ExitNodeID": "",
          "Location": null,
          "TPM": null,
          "StateEncrypted": null
        },
        "Created": "2024-01-01T00:00:00Z",
        "Cap": 141,
        "Tags": null,
        "Online": true,
        "Capabilities": null,
        "CapMap": null
      },
      "DERPMap": {
        "HomeParams": null,
        "Regions": {
          "1": {
            "RegionID": 1,
            "RegionCode": "nyc",
            "RegionName": "New York City",
            "Latitude": 40.71,
            "Longitude": -74.01,
            "Avoid": false,
            "NoMeasureNoHome": false,
            "Nodes": [
              {
                "Name": "1a",
                "RegionID": 1,
                "HostName": "derp1.tailscale.com",
                "CertName": "",
                "IPv4": "",
                "IPv6": "",
                "STUNPort": 3478,
                "STUNOnly": false,
                "DERPPort": 443,
                "InsecureForTests": false,
                "STUNTestIP": "",
                "CanPort80": false
              }
            ]
          },
          "9": {
            "RegionID": 9,
            "RegionCode": "sin",
            "RegionName": "Singapore",
            "Latitude": 0,
            "Longitude": 0,
            "Avoid": false,
            "NoMeasureNoHome": false,
            "Nodes": null
          }
        },
        "OmitDefaultRegions": false
      },
      "Peers": null,
      "PeersChanged": null,
      "PeersRemoved": null,
      "Domain": "tail-scale.ts.net",
      "DNSConfig": {
        "Resolvers": [{"Addr": "1.1.1.1"}],
        "Routes": {
          "corp.example.com.": null,
          ".": [{"Addr": "100.100.100.100"}]
        },
        "FallbackResolvers": null,
        "Domains": ["tail-scale.ts.net"],
        "Proxied": true,
        "CertDomains": ["rs-gcp.tail-scale.ts.net"],
        "ExtraRecords": null,
        "Nameservers": null
      },
      "UserProfiles": [
        {
          "ID": 42,
          "LoginName": "user@example.com",
          "DisplayName": "Raj",
          "ProfilePicURL": ""
        }
      ],
      "PacketFilter": [
        {
          "SrcIPs": ["*"],
          "SrcBits": null,
          "DstPorts": [
            {
              "IP": "*",
              "Bits": null,
              "Ports": {"First": 0, "Last": 65535}
            }
          ],
          "IPProto": null,
          "CapGrant": null
        }
      ],
      "PacketFilters": null
    }"#;

    let json = json
        .replace("__NODE_KEY__", &node_key_str)
        .replace("__MACHINE_KEY__", &machine_key_str)
        .replace("__DISCO_KEY__", &disco_key_str);

    let resp: MapResponse = serde_json::from_str(&json).expect("fixture MapResponse must parse");

    assert_eq!(resp.Node.as_ref().unwrap().ID, 100);
    assert_eq!(
        resp.Node.as_ref().unwrap().AllowedIPs,
        Vec::<String>::new(),
        "null AllowedIPs -> empty vec"
    );
    assert_eq!(
        resp.Node.as_ref().unwrap().Tags,
        Vec::<String>::new(),
        "null Tags -> empty vec"
    );
    assert_eq!(
        resp.Node.as_ref().unwrap().CapMap,
        BTreeMap::new(),
        "null CapMap -> empty map"
    );
    assert!(resp.Peers.is_empty(), "null Peers -> empty vec");
    assert!(
        resp.PeersChanged.is_empty(),
        "null PeersChanged -> empty vec"
    );
    assert!(
        resp.PeersRemoved.is_empty(),
        "null PeersRemoved -> empty vec"
    );

    let dns = resp.DNSConfig.as_ref().expect("DNSConfig present");
    assert!(dns.Routes.contains_key("corp.example.com."));
    assert!(
        dns.Routes["corp.example.com."].is_empty(),
        "null route value -> empty vec"
    );
    assert_eq!(dns.Routes["."].len(), 1, "non-null route value preserved");
    assert!(
        dns.FallbackResolvers.is_empty(),
        "null FallbackResolvers -> empty vec"
    );
    assert!(
        dns.ExtraRecords.is_empty(),
        "null ExtraRecords -> empty vec"
    );
    assert!(dns.Nameservers.is_empty(), "null Nameservers -> empty vec");

    let sin = resp.DERPMap.as_ref().unwrap().Regions.get(&9).unwrap();
    assert!(sin.Nodes.is_none(), "null Nodes -> None");

    let pf = resp.PacketFilter.as_ref().unwrap();
    assert_eq!(pf.len(), 1);
    assert!(pf[0].SrcBits.is_empty(), "null SrcBits -> empty vec");
    assert!(pf[0].IPProto.is_empty(), "null IPProto -> empty vec");
    assert!(pf[0].CapGrant.is_empty(), "null CapGrant -> empty vec");

    let ni = resp
        .Node
        .as_ref()
        .unwrap()
        .Hostinfo
        .as_ref()
        .unwrap()
        .NetInfo
        .as_ref()
        .unwrap();
    assert_eq!(
        ni.WorkingICMPv4,
        rustscale_tailcfg::OptBool::Unset,
        "null OptBool -> Unset"
    );
    assert_eq!(ni.UPnP, rustscale_tailcfg::OptBool::Unset);
    assert_eq!(ni.PMP, rustscale_tailcfg::OptBool::Unset);
    assert_eq!(ni.PCP, rustscale_tailcfg::OptBool::Unset);

    let hi = resp.Node.as_ref().unwrap().Hostinfo.as_ref().unwrap();
    assert!(hi.Services.is_empty(), "null Services -> empty vec");
    assert!(hi.RoutableIPs.is_empty(), "null RoutableIPs -> empty vec");
    assert!(hi.RequestTags.is_empty(), "null RequestTags -> empty vec");
    assert!(hi.WoLMACs.is_empty(), "null WoLMACs -> empty vec");
    assert!(hi.SSH_HostKeys.is_empty(), "null sshHostKeys -> empty vec");
}
