//! DERP protocol types: ClientInfo, ServerInfo, MeshKey, Received.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use rustscale_key::NodePublic;

use crate::frame::peer_gone_reason;

/// A DERP mesh key — 32 bytes serialized as a 64-char hex string.
///
/// Matches Go's `key.DERPMesh` JSON encoding. Omitted from JSON when zero
/// (via `skip_serializing_if` on the containing struct).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct MeshKey(pub [u8; 32]);

impl MeshKey {
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    pub fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn raw(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for MeshKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return f.write_str("MeshKey(zero)");
        }
        write!(f, "MeshKey({})", hex::encode(self.0))
    }
}

impl Serialize for MeshKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for MeshKey {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(d)?;
        if s.len() != 64 {
            return Err(serde::de::Error::custom(
                "invalid mesh key: must be 64 hex chars",
            ));
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&s, &mut bytes)
            .map_err(|_| serde::de::Error::custom("invalid mesh key: bad hex"))?;
        Ok(MeshKey(bytes))
    }
}

/// ClientInfo is sent by the client to the server during the DERP handshake.
///
/// JSON field names match Go's `encoding/json` output exactly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ClientInfo {
    #[serde(rename = "meshKey", default, skip_serializing_if = "MeshKey::is_zero")]
    pub mesh_key: MeshKey,
    #[serde(rename = "version", default, skip_serializing_if = "is_zero_u32")]
    pub version: u32,
    #[serde(rename = "CanAckPings", default)]
    pub can_ack_pings: bool,
    #[serde(rename = "IsProber", default, skip_serializing_if = "is_false")]
    pub is_prober: bool,
}

/// ServerInfo is sent by the server to the client during the handshake.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ServerInfo {
    #[serde(rename = "version", default, skip_serializing_if = "is_zero_u32")]
    pub version: u32,
    #[serde(
        rename = "TokenBucketBytesPerSecond",
        default,
        skip_serializing_if = "is_zero_u32"
    )]
    pub token_bucket_bytes_per_second: u32,
    #[serde(
        rename = "TokenBucketBytesBurst",
        default,
        skip_serializing_if = "is_zero_u32"
    )]
    pub token_bucket_bytes_burst: u32,
}

/// A message received from the DERP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    ServerInfo(ServerInfo),
    ReceivedPacket {
        source: NodePublic,
        data: Vec<u8>,
    },
    KeepAlive,
    PeerGone {
        peer: NodePublic,
        reason: u8,
    },
    PeerPresent {
        key: NodePublic,
        ip_port: Option<SocketAddr>,
        flags: u8,
    },
    Ping([u8; 8]),
    Pong([u8; 8]),
    Health {
        problem: String,
    },
    Restarting {
        reconnect_in: Duration,
        try_for: Duration,
    },
}

/// Parse a received frame body into a [`Received`] message.
///
/// `typ` is the frame type byte, `body` is the frame payload (past the 5-byte
/// header). `private_key` and `server_key` are used to open the ServerInfo box.
pub fn parse_received(
    typ: u8,
    body: &[u8],
    private_key: &rustscale_key::NodePrivate,
    server_key: &NodePublic,
) -> Option<Received> {
    use crate::frame::frame_type as ft;
    match typ {
        ft::SERVER_INFO => {
            let info = parse_server_info(body, private_key, server_key)?;
            Some(Received::ServerInfo(info))
        }
        ft::KEEP_ALIVE => Some(Received::KeepAlive),
        ft::PEER_GONE => {
            if body.len() < KEY_LEN_BYTES {
                return None;
            }
            let peer = read_node_pub(&body[..KEY_LEN_BYTES]);
            let reason = if body.len() > KEY_LEN_BYTES {
                body[KEY_LEN_BYTES]
            } else {
                peer_gone_reason::DISCONNECTED
            };
            Some(Received::PeerGone { peer, reason })
        }
        ft::PEER_PRESENT => {
            const IP_LEN: usize = 16;
            const PORT_LEN: usize = 2;

            if body.len() < KEY_LEN_BYTES {
                return None;
            }
            let key = read_node_pub(&body[..KEY_LEN_BYTES]);
            let rest = &body[KEY_LEN_BYTES..];

            let ip_port = if rest.len() >= IP_LEN + PORT_LEN {
                let ip = ip_from16(&rest[..IP_LEN]);
                let port = u16::from_be_bytes([rest[IP_LEN], rest[IP_LEN + 1]]);
                Some(SocketAddr::new(ip, port))
            } else {
                None
            };

            let flags_off = IP_LEN + PORT_LEN;
            let flags = if rest.len() > flags_off {
                rest[flags_off]
            } else {
                0
            };

            Some(Received::PeerPresent {
                key,
                ip_port,
                flags,
            })
        }
        ft::RECV_PACKET => {
            if body.len() < KEY_LEN_BYTES {
                return None;
            }
            let source = read_node_pub(&body[..KEY_LEN_BYTES]);
            let data = body[KEY_LEN_BYTES..].to_vec();
            Some(Received::ReceivedPacket { source, data })
        }
        ft::PING => {
            if body.len() < 8 {
                return None;
            }
            let mut data = [0u8; 8];
            data.copy_from_slice(&body[..8]);
            Some(Received::Ping(data))
        }
        ft::PONG => {
            if body.len() < 8 {
                return None;
            }
            let mut data = [0u8; 8];
            data.copy_from_slice(&body[..8]);
            Some(Received::Pong(data))
        }
        ft::HEALTH => {
            let problem = String::from_utf8_lossy(body).into_owned();
            Some(Received::Health { problem })
        }
        ft::RESTARTING => {
            if body.len() < 8 {
                return None;
            }
            let reconnect_ms = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let try_for_ms = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            Some(Received::Restarting {
                reconnect_in: Duration::from_millis(u64::from(reconnect_ms)),
                try_for: Duration::from_millis(u64::from(try_for_ms)),
            })
        }
        _ => None,
    }
}

/// Parse and decrypt a ServerInfo frame body.
fn parse_server_info(
    body: &[u8],
    private_key: &rustscale_key::NodePrivate,
    server_key: &NodePublic,
) -> Option<ServerInfo> {
    if body.len() < crate::frame::NONCE_LEN {
        return None;
    }
    let plaintext = private_key.open_from(server_key, body)?;
    serde_json::from_slice(&plaintext).ok()
}

const KEY_LEN_BYTES: usize = 32;

fn read_node_pub(buf: &[u8]) -> NodePublic {
    let mut k = [0u8; 32];
    k.copy_from_slice(&buf[..32]);
    NodePublic::from_raw32(k)
}

fn ip_from16(bytes: &[u8]) -> std::net::IpAddr {
    use std::net::{IpAddr, Ipv6Addr};
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes[..16]);
    if let Some(v4) = Ipv6Addr::from(arr).to_ipv4_mapped() {
        IpAddr::V4(v4)
    } else {
        IpAddr::V6(Ipv6Addr::from(arr))
    }
}

// ---- serde helpers ----

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !b
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_info_serializes_default_with_version() {
        let ci = ClientInfo {
            mesh_key: MeshKey::default(),
            version: 2,
            can_ack_pings: true,
            is_prober: false,
        };
        let json = serde_json::to_string(&ci).unwrap();
        // mesh_key is zero -> omitted; is_prober is false -> omitted.
        assert!(json.contains("\"version\":2"));
        assert!(json.contains("\"CanAckPings\":true"));
        assert!(!json.contains("meshKey"));
        assert!(!json.contains("IsProber"));
    }

    #[test]
    fn client_info_with_mesh_key() {
        let mut mk = [0u8; 32];
        mk[0] = 0x6d;
        mk[1] = 0x52;
        let ci = ClientInfo {
            mesh_key: MeshKey(mk),
            version: 5,
            can_ack_pings: false,
            is_prober: true,
        };
        let json = serde_json::to_string(&ci).unwrap();
        assert!(json.contains("\"meshKey\":\"6d52"));
        assert!(json.contains("\"IsProber\":true"));
    }

    #[test]
    fn client_info_roundtrip() {
        let ci = ClientInfo {
            version: 2,
            can_ack_pings: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&ci).unwrap();
        let back: ClientInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ci);
    }

    #[test]
    fn mesh_key_deserialize_rejects_bad_length() {
        assert!(serde_json::from_str::<MeshKey>("\"abcdefg\"").is_err());
    }
}
