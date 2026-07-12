#![allow(non_snake_case)]

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

use rustscale_key::NodePublic;
use rustscale_tailcfg::{DNSRecord, UserID, UserProfile};

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

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(v: &bool) -> bool {
    !*v
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_epoch_time(v: &DateTime<Utc>) -> bool {
    *v == DateTime::UNIX_EPOCH
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_taildrop_unknown(v: &TaildropTargetStatus) -> bool {
    *v == TaildropTargetStatus::Unknown
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Status {
    #[serde(default)]
    pub Version: String,
    #[serde(default)]
    pub TUN: bool,
    #[serde(default)]
    pub BackendState: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub HaveNodeKey: Option<bool>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub AuthURL: String,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub TailscaleIPs: Vec<IpAddr>,
    #[serde(rename = "Self", skip_serializing_if = "Option::is_none", default)]
    pub SelfPeer: Option<Box<PeerStatus>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ExitNodeStatus: Option<Box<ExitNodeStatus>>,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Health: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub MagicDNSSuffix: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub CurrentTailnet: Option<Box<TailnetStatus>>,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub CertDomains: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_null_to_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ExtraRecords: Vec<DNSRecord>,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Peer: BTreeMap<String, PeerStatus>,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub User: BTreeMap<UserID, UserProfile>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PeerStatus {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ID: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub NodeID: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub PublicKey: String,
    #[serde(default)]
    pub HostName: String,
    #[serde(default)]
    pub DNSName: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub OS: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
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
    #[serde(
        default,
        deserialize_with = "deserialize_null_to_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub Addrs: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub CurAddr: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub Relay: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub PeerRelay: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub RxBytes: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub TxBytes: i64,
    #[serde(default, skip_serializing_if = "is_epoch_time")]
    pub Created: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "is_epoch_time")]
    pub LastWrite: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "is_epoch_time")]
    pub LastSeen: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "is_epoch_time")]
    pub LastHandshake: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub Online: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ExitNode: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ExitNodeOption: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub Active: bool,
    #[serde(
        default,
        deserialize_with = "deserialize_null_to_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub PeerAPIURL: Vec<String>,
    #[serde(default, skip_serializing_if = "is_taildrop_unknown")]
    pub TaildropTarget: TaildropTargetStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub NoFileSharingReason: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub Capabilities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub CapMap: Option<BTreeMap<String, Vec<serde_json::Value>>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub SSH_HostKeys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ShareeNode: Option<bool>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub InNetworkMap: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub InMagicSock: bool,
    #[serde(default, skip_serializing_if = "is_false")]
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

pub struct StatusBuilder {
    locked: bool,
    status: Status,
}

impl Default for StatusBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusBuilder {
    pub fn new() -> Self {
        Self {
            locked: false,
            status: Status::default(),
        }
    }

    pub fn mutate_status(&mut self, f: impl FnOnce(&mut Status)) {
        assert!(!self.locked, "StatusBuilder already locked");
        f(&mut self.status);
    }

    pub fn mutate_self_status(&mut self, f: impl FnOnce(&mut PeerStatus)) {
        assert!(!self.locked, "StatusBuilder already locked");
        if self.status.SelfPeer.is_none() {
            self.status.SelfPeer = Some(Box::new(PeerStatus::default()));
        }
        if let Some(ref mut ps) = self.status.SelfPeer {
            f(ps);
        }
    }

    pub fn add_user(&mut self, id: UserID, up: UserProfile) {
        assert!(!self.locked, "StatusBuilder already locked");
        self.status.User.insert(id, up);
    }

    pub fn add_tailscale_ip(&mut self, ip: IpAddr) {
        assert!(!self.locked, "StatusBuilder already locked");
        self.status.TailscaleIPs.push(ip);
    }

    pub fn add_peer(&mut self, peer: &NodePublic, mut st: PeerStatus) {
        assert!(!self.locked, "StatusBuilder already locked");
        let key_str = peer.to_string();
        st.PublicKey.clone_from(&key_str);
        if let Some(e) = self.status.Peer.get_mut(&key_str) {
            merge_peer_status(e, &st);
        } else {
            self.status.Peer.insert(key_str, st);
        }
    }

    pub fn status(&mut self) -> Status {
        self.locked = true;
        std::mem::take(&mut self.status)
    }
}

fn merge_peer_status(e: &mut PeerStatus, st: &PeerStatus) {
    if !st.ID.is_empty() {
        e.ID.clone_from(&st.ID);
    }
    if st.NodeID != 0 {
        e.NodeID = st.NodeID;
    }
    if !st.HostName.is_empty() {
        e.HostName.clone_from(&st.HostName);
    }
    if !st.DNSName.is_empty() {
        e.DNSName.clone_from(&st.DNSName);
    }
    if !st.Relay.is_empty() {
        e.Relay.clone_from(&st.Relay);
    }
    if !st.PeerRelay.is_empty() {
        e.PeerRelay.clone_from(&st.PeerRelay);
    }
    if st.UserID != 0 {
        e.UserID = st.UserID;
    }
    if st.AltSharerUserID != 0 {
        e.AltSharerUserID = st.AltSharerUserID;
    }
    if !st.TailscaleIPs.is_empty() {
        e.TailscaleIPs.clone_from(&st.TailscaleIPs);
    }
    if st.PrimaryRoutes.is_some() {
        e.PrimaryRoutes.clone_from(&st.PrimaryRoutes);
    }
    if st.AllowedIPs.is_some() {
        e.AllowedIPs.clone_from(&st.AllowedIPs);
    }
    if st.Tags.is_some() {
        e.Tags.clone_from(&st.Tags);
    }
    if !st.OS.is_empty() {
        e.OS.clone_from(&st.OS);
    }
    if st.SSH_HostKeys.is_some() {
        e.SSH_HostKeys.clone_from(&st.SSH_HostKeys);
    }
    if !st.Addrs.is_empty() {
        e.Addrs.clone_from(&st.Addrs);
    }
    if !st.CurAddr.is_empty() {
        e.CurAddr.clone_from(&st.CurAddr);
    }
    if st.RxBytes != 0 {
        e.RxBytes = st.RxBytes;
    }
    if st.TxBytes != 0 {
        e.TxBytes = st.TxBytes;
    }
    if st.LastHandshake != DateTime::UNIX_EPOCH {
        e.LastHandshake = st.LastHandshake;
    }
    if st.Created != DateTime::UNIX_EPOCH {
        e.Created = st.Created;
    }
    if st.LastSeen != DateTime::UNIX_EPOCH {
        e.LastSeen = st.LastSeen;
    }
    if st.LastWrite != DateTime::UNIX_EPOCH {
        e.LastWrite = st.LastWrite;
    }
    if st.Online {
        e.Online = true;
    }
    if st.InNetworkMap {
        e.InNetworkMap = true;
    }
    if st.InMagicSock {
        e.InMagicSock = true;
    }
    if st.InEngine {
        e.InEngine = true;
    }
    if st.ExitNode {
        e.ExitNode = true;
    }
    if st.ExitNodeOption {
        e.ExitNodeOption = true;
    }
    if st.ShareeNode.is_some() {
        e.ShareeNode = st.ShareeNode;
    }
    if st.Active {
        e.Active = true;
    }
    if !st.PeerAPIURL.is_empty() {
        e.PeerAPIURL.clone_from(&st.PeerAPIURL);
    }
    if st.CapMap.is_some() {
        e.CapMap.clone_from(&st.CapMap);
    }
    if st.Capabilities.is_some() {
        e.Capabilities.clone_from(&st.Capabilities);
    }
    if st.TaildropTarget != TaildropTargetStatus::Unknown {
        e.TaildropTarget = st.TaildropTarget;
    }
    if st.Expired == Some(true) {
        e.Expired = Some(true);
    }
    if st.KeyExpiry.is_some() {
        e.KeyExpiry = st.KeyExpiry;
    }
    e.Location.clone_from(&st.Location);
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

    #[test]
    fn status_builder_basic() {
        let mut sb = StatusBuilder::new();
        sb.mutate_status(|s| {
            s.Version = "1.0.0".into();
            s.BackendState = "Running".into();
            s.HaveNodeKey = Some(true);
        });
        sb.mutate_self_status(|ps| {
            ps.HostName = "myhost".into();
            ps.Online = true;
            ps.InNetworkMap = true;
            ps.InMagicSock = true;
            ps.InEngine = true;
        });
        sb.add_tailscale_ip("100.64.0.1".parse().unwrap());

        let st = sb.status();
        assert_eq!(st.Version, "1.0.0");
        assert_eq!(st.BackendState, "Running");
        assert_eq!(st.HaveNodeKey, Some(true));
        assert_eq!(st.TailscaleIPs.len(), 1);
        assert!(st.SelfPeer.is_some());
        assert_eq!(st.SelfPeer.as_ref().unwrap().HostName, "myhost");
        assert!(st.SelfPeer.as_ref().unwrap().Online);
    }

    #[test]
    fn status_builder_add_peer_merge() {
        let key = NodePublic::from_raw32([1u8; 32]);
        let key_str = key.to_string();

        let mut sb = StatusBuilder::new();
        let ps1 = PeerStatus {
            HostName: "node1".into(),
            Online: true,
            InNetworkMap: true,
            ..Default::default()
        };
        sb.add_peer(&key, ps1);

        let ps2 = PeerStatus {
            RxBytes: 1000,
            TxBytes: 500,
            InMagicSock: true,
            ..Default::default()
        };
        sb.add_peer(&key, ps2);

        let st = sb.status();
        assert_eq!(st.Peer.len(), 1);
        let peer = &st.Peer[&key_str];
        assert_eq!(peer.HostName, "node1");
        assert!(peer.Online);
        assert!(peer.InNetworkMap);
        assert!(peer.InMagicSock);
        assert_eq!(peer.RxBytes, 1000);
        assert_eq!(peer.TxBytes, 500);
    }

    #[test]
    fn status_builder_add_user() {
        let mut sb = StatusBuilder::new();
        let profile = UserProfile {
            ID: 1,
            LoginName: "alice@example.com".into(),
            DisplayName: "Alice".into(),
            ProfilePicURL: String::new(),
        };
        sb.add_user(1, profile);

        let st = sb.status();
        assert_eq!(st.User.len(), 1);
        assert_eq!(st.User[&1].LoginName, "alice@example.com");
    }

    #[test]
    fn skip_serializing_default_fields() {
        let ps = PeerStatus::default();
        let json = serde_json::to_string(&ps).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("ID"));
        assert!(!obj.contains_key("NodeID"));
        assert!(!obj.contains_key("OS"));
        assert!(!obj.contains_key("Online"));
        assert!(!obj.contains_key("ExitNode"));
        assert!(!obj.contains_key("Relay"));
        assert!(!obj.contains_key("RxBytes"));
        assert!(!obj.contains_key("TxBytes"));
        assert!(!obj.contains_key("Addrs"));
        assert!(!obj.contains_key("PeerAPIURL"));
        assert!(!obj.contains_key("InNetworkMap"));
        assert!(!obj.contains_key("InMagicSock"));
        assert!(!obj.contains_key("InEngine"));
        assert!(obj.contains_key("HostName"));
        assert!(obj.contains_key("DNSName"));
        assert!(obj.contains_key("TailscaleIPs"));
    }

    #[test]
    fn serialize_status_omits_empty_collections() {
        let st = Status::default();
        let json = serde_json::to_string(&st).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("ExtraRecords"));
        assert!(!obj.contains_key("HaveNodeKey"));
        assert!(!obj.contains_key("AuthURL"));
        assert!(!obj.contains_key("MagicDNSSuffix"));
        assert!(!obj.contains_key("Self"));
        assert!(obj.contains_key("Version"));
        assert!(obj.contains_key("TUN"));
        assert!(obj.contains_key("BackendState"));
        assert!(obj.contains_key("TailscaleIPs"));
        assert!(obj.contains_key("Peer"));
        assert!(obj.contains_key("Health"));
        assert!(obj.contains_key("CertDomains"));
        assert!(obj.contains_key("User"));
    }
}
