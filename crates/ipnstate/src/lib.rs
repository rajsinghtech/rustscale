#![allow(non_snake_case)]

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

fn deserialize_null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let opt: Option<T> = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Status {
    #[serde(default)]
    pub Version: String,
    #[serde(default)]
    pub TUN: bool,
    #[serde(default)]
    pub BackendState: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub HaveNodeKey: Option<bool>,
    #[serde(default)]
    pub AuthURL: String,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub TailscaleIPs: Vec<IpAddr>,
    #[serde(rename = "Self", skip_serializing_if = "Option::is_none", default)]
    pub SelfPeer: Option<Box<PeerStatus>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ExitNodeStatus: Option<Box<ExitNodeStatus>>,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Health: Vec<String>,
    #[serde(default)]
    pub MagicDNSSuffix: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub CurrentTailnet: Option<Box<TailnetStatus>>,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub CertDomains: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub ExtraRecords: Vec<serde_json::Value>,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Peer: BTreeMap<String, PeerStatus>,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub User: BTreeMap<i64, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ClientVersion: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerStatusLite {
    #[serde(default)]
    pub NodeKey: String,
    #[serde(default)]
    pub TxBytes: i64,
    #[serde(default)]
    pub RxBytes: i64,
    #[serde(default)]
    pub LastHandshake: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerStatus {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub NodeID: i64,
    #[serde(default)]
    pub PublicKey: String,
    #[serde(default)]
    pub HostName: String,
    #[serde(default)]
    pub DNSName: String,
    #[serde(default)]
    pub OS: String,
    #[serde(default)]
    pub UserID: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub AltSharerUserID: i64,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub TailscaleIPs: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub AllowedIPs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub Tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub PrimaryRoutes: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Addrs: Vec<String>,
    #[serde(default)]
    pub CurAddr: String,
    #[serde(default)]
    pub Relay: String,
    #[serde(default)]
    pub PeerRelay: String,
    #[serde(default)]
    pub RxBytes: i64,
    #[serde(default)]
    pub TxBytes: i64,
    #[serde(default)]
    pub Created: DateTime<Utc>,
    #[serde(default)]
    pub LastWrite: DateTime<Utc>,
    #[serde(default)]
    pub LastSeen: DateTime<Utc>,
    #[serde(default)]
    pub LastHandshake: DateTime<Utc>,
    #[serde(default)]
    pub Online: bool,
    #[serde(default)]
    pub ExitNode: bool,
    #[serde(default)]
    pub ExitNodeOption: bool,
    #[serde(default)]
    pub Active: bool,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub PeerAPIURL: Vec<String>,
    #[serde(default)]
    pub TaildropTarget: TaildropTargetStatus,
    #[serde(default)]
    pub NoFileSharingReason: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub Capabilities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub CapMap: Option<BTreeMap<String, Vec<serde_json::Value>>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub SSH_HostKeys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ShareeNode: Option<bool>,
    #[serde(default)]
    pub InNetworkMap: bool,
    #[serde(default)]
    pub InMagicSock: bool,
    #[serde(default)]
    pub InEngine: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub Expired: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub KeyExpiry: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub Location: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TailnetStatus {
    #[serde(default)]
    pub Name: String,
    #[serde(default)]
    pub MagicDNSSuffix: String,
    #[serde(default)]
    pub MagicDNSEnabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExitNodeStatus {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub Online: bool,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub TailscaleIPs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TaildropTargetStatus {
    #[default]
    Unknown = 0,
    Available = 1,
    NoNetmapAvailable = 2,
    IpnStateNotRunning = 3,
    MissingCap = 4,
    Offline = 5,
    NoPeerInfo = 6,
    UnsupportedOS = 7,
    NoPeerAPI = 8,
    OwnedByOtherUser = 9,
}

impl Serialize for TaildropTargetStatus {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i64(*self as i64)
    }
}

impl<'de> Deserialize<'de> for TaildropTargetStatus {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v: i64 = Deserialize::deserialize(d)?;
        match v {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Available),
            2 => Ok(Self::NoNetmapAvailable),
            3 => Ok(Self::IpnStateNotRunning),
            4 => Ok(Self::MissingCap),
            5 => Ok(Self::Offline),
            6 => Ok(Self::NoPeerInfo),
            7 => Ok(Self::UnsupportedOS),
            8 => Ok(Self::NoPeerAPI),
            9 => Ok(Self::OwnedByOtherUser),
            _ => Err(serde::de::Error::custom(format!(
                "invalid TaildropTargetStatus value: {v}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_status_with_peers() {
        let status = Status {
            Version: "1.2.3".into(),
            TUN: true,
            BackendState: "Running".into(),
            HaveNodeKey: Some(true),
            AuthURL: String::new(),
            TailscaleIPs: vec!["100.64.1.1".parse().unwrap()],
            SelfPeer: None,
            ExitNodeStatus: None,
            Health: vec![],
            MagicDNSSuffix: "example.ts.net".into(),
            CurrentTailnet: None,
            CertDomains: vec![],
            ExtraRecords: vec![],
            Peer: BTreeMap::from([(
                "mnode:abc123".into(),
                PeerStatus {
                    ID: "node1".into(),
                    NodeID: 42,
                    PublicKey: "mnode:abc123".into(),
                    HostName: "myhost".into(),
                    DNSName: "myhost.example.ts.net.".into(),
                    OS: "linux".into(),
                    UserID: 1,
                    AltSharerUserID: 0,
                    TailscaleIPs: vec!["100.64.1.2".parse().unwrap()],
                    AllowedIPs: None,
                    Tags: None,
                    PrimaryRoutes: None,
                    Addrs: vec!["1.2.3.4:51820".into()],
                    CurAddr: "1.2.3.4:51820".into(),
                    Relay: String::new(),
                    PeerRelay: String::new(),
                    RxBytes: 1000,
                    TxBytes: 500,
                    Created: DateTime::UNIX_EPOCH,
                    LastWrite: DateTime::UNIX_EPOCH,
                    LastSeen: DateTime::UNIX_EPOCH,
                    LastHandshake: DateTime::UNIX_EPOCH,
                    Online: true,
                    ExitNode: false,
                    ExitNodeOption: true,
                    Active: true,
                    PeerAPIURL: vec![],
                    TaildropTarget: TaildropTargetStatus::Available,
                    NoFileSharingReason: String::new(),
                    Capabilities: None,
                    CapMap: None,
                    SSH_HostKeys: None,
                    ShareeNode: None,
                    InNetworkMap: true,
                    InMagicSock: true,
                    InEngine: true,
                    Expired: None,
                    KeyExpiry: None,
                    Location: None,
                },
            )]),
            User: BTreeMap::new(),
            ClientVersion: None,
        };

        let json = serde_json::to_string_pretty(&status).unwrap();
        let back: Status = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }

    #[test]
    fn deserialize_status_null_fields() {
        let json = r#"{
            "Version": "",
            "TUN": false,
            "BackendState": "Running",
            "TailscaleIPs": null,
            "Health": null,
            "CertDomains": null,
            "ExtraRecords": null,
            "Peer": null,
            "User": null
        }"#;
        let status: Status = serde_json::from_str(json).unwrap();
        assert!(status.TailscaleIPs.is_empty());
        assert!(status.Health.is_empty());
        assert!(status.Peer.is_empty());
        assert!(status.User.is_empty());
    }

    #[test]
    fn deserialize_peer_status_minimal() {
        let json = r#"{
            "ID": "nodeABC",
            "NodeID": 7,
            "PublicKey": "mnode:def456",
            "HostName": "test-node",
            "DNSName": "test-node.tailnet.ts.net.",
            "OS": "darwin",
            "UserID": 2,
            "TailscaleIPs": ["100.64.0.1"],
            "Addrs": [],
            "CurAddr": "",
            "Relay": "",
            "PeerRelay": "",
            "RxBytes": 0,
            "TxBytes": 0,
            "Created": "2024-01-01T00:00:00Z",
            "LastWrite": "2024-01-01T00:00:00Z",
            "LastSeen": "2024-01-01T00:00:00Z",
            "LastHandshake": "2024-01-01T00:00:00Z",
            "Online": false,
            "ExitNode": false,
            "ExitNodeOption": false,
            "Active": false,
            "PeerAPIURL": null,
            "InNetworkMap": false,
            "InMagicSock": false,
            "InEngine": false
        }"#;
        let peer: PeerStatus = serde_json::from_str(json).unwrap();
        assert_eq!(peer.ID, "nodeABC");
        assert_eq!(peer.NodeID, 7);
        assert_eq!(peer.PublicKey, "mnode:def456");
        assert_eq!(peer.HostName, "test-node");
        assert!(peer.TailscaleIPs.contains(&"100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn roundtrip_tailnet_status() {
        let ts = TailnetStatus {
            Name: "my-tailnet.ts.net".into(),
            MagicDNSSuffix: "my-tailnet.ts.net".into(),
            MagicDNSEnabled: true,
        };
        let json = serde_json::to_string(&ts).unwrap();
        let back: TailnetStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(ts, back);
    }

    #[test]
    fn roundtrip_exit_node_status() {
        let ens = ExitNodeStatus {
            ID: "exitNode1".into(),
            Online: true,
            TailscaleIPs: vec!["100.64.0.1/32".into()],
        };
        let json = serde_json::to_string(&ens).unwrap();
        let back: ExitNodeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(ens, back);
    }

    #[test]
    fn roundtrip_taildrop_target_status() {
        let v = TaildropTargetStatus::Available;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "1");
        let back: TaildropTargetStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TaildropTargetStatus::Available);
    }

    #[test]
    fn deserialize_go_style_json_with_null_slices() {
        let json = r#"{
            "Peer": {
                "mnode:abc": {
                    "ID": "n1",
                    "NodeID": 1,
                    "PublicKey": "mnode:abc",
                    "HostName": "n1",
                    "DNSName": "n1.ts.net.",
                    "OS": "linux",
                    "UserID": 1,
                    "TailscaleIPs": null,
                    "Addrs": null,
                    "CurAddr": "",
                    "Relay": "",
                    "PeerRelay": "",
                    "RxBytes": 0,
                    "TxBytes": 0,
                    "Created": "2024-06-15T00:00:00Z",
                    "LastWrite": "2024-06-15T00:00:00Z",
                    "LastSeen": "2024-06-15T00:00:00Z",
                    "LastHandshake": "2024-06-15T00:00:00Z",
                    "Online": true,
                    "ExitNode": false,
                    "ExitNodeOption": false,
                    "Active": true,
                    "PeerAPIURL": null,
                    "InNetworkMap": true,
                    "InMagicSock": true,
                    "InEngine": true
                }
            }
        }"#;
        let status: Status = serde_json::from_str(json).unwrap();
        assert_eq!(status.Peer.len(), 1);
        let peer = &status.Peer["mnode:abc"];
        assert!(peer.TailscaleIPs.is_empty());
        assert!(peer.Addrs.is_empty());
    }
}
