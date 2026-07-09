//! Disco message types: parse, marshal, and summary.
//!
//! The inner payload format (after NaCl box decryption) is:
//! ```text
//! messageType     byte
//! messageVersion  byte   (0 for now; ignore trailing bytes)
//! message-payload [...]byte
//! ```

use std::time::Duration;

use rustscale_key::{DiscoPublic, NodePublic, KEY_LEN};

use crate::wire::{AddrPort, EP_LENGTH};

pub(crate) const V0: u8 = 0;

fn zero_disco_pair() -> [DiscoPublic; 2] {
    [
        DiscoPublic::from_raw32([0u8; KEY_LEN]),
        DiscoPublic::from_raw32([0u8; KEY_LEN]),
    ]
}

// Message type bytes (match Go's disco.go exactly).
pub const TYPE_PING: u8 = 0x01;
pub const TYPE_PONG: u8 = 0x02;
pub const TYPE_CALL_ME_MAYBE: u8 = 0x03;
pub const TYPE_BIND_UDP_RELAY_ENDPOINT: u8 = 0x04;
pub const TYPE_BIND_UDP_RELAY_ENDPOINT_CHALLENGE: u8 = 0x05;
pub const TYPE_BIND_UDP_RELAY_ENDPOINT_ANSWER: u8 = 0x06;
pub const TYPE_CALL_ME_MAYBE_VIA: u8 = 0x07;
pub const TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST: u8 = 0x08;
pub const TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE: u8 = 0x09;

// Length constants (without the 2-byte message header).
pub const PING_LEN: usize = 12 + KEY_LEN;
pub const PONG_LEN: usize = 12 + 16 + 2;
pub const BIND_UDP_RELAY_ENDPOINT_COMMON_LEN: usize = 72;
pub const BIND_UDP_RELAY_CHALLENGE_LEN: usize = 32;
pub const ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST_LEN: usize = KEY_LEN * 2 + 4;
pub const UDP_RELAY_ENDPOINT_LEN_MINUS_ADDRPORTS: usize = KEY_LEN + KEY_LEN * 2 + 8 + 4 + 8 + 8;

/// A parsed disco message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Ping(Ping),
    Pong(Pong),
    CallMeMaybe(CallMeMaybe),
    BindUdpRelayEndpoint(BindUdpRelayEndpoint),
    BindUdpRelayEndpointChallenge(BindUdpRelayEndpointChallenge),
    BindUdpRelayEndpointAnswer(BindUdpRelayEndpointAnswer),
    CallMeMaybeVia(CallMeMaybeVia),
    AllocateUdpRelayEndpointRequest(AllocateUdpRelayEndpointRequest),
    AllocateUdpRelayEndpointResponse(AllocateUdpRelayEndpointResponse),
}

impl Message {
    /// Parse the decrypted payload (type + version + body).
    pub fn parse(payload: &[u8]) -> Result<Message, DiscoError> {
        if payload.len() < MESSAGE_HEADER_LEN {
            return Err(DiscoError::Short);
        }
        let typ = payload[0];
        let ver = payload[1];
        let body = &payload[2..];
        match typ {
            TYPE_PING => parse_ping(ver, body),
            TYPE_PONG => parse_pong(ver, body),
            TYPE_CALL_ME_MAYBE => parse_call_me_maybe(ver, body),
            TYPE_BIND_UDP_RELAY_ENDPOINT => parse_bind_udp_relay_endpoint(ver, body),
            TYPE_BIND_UDP_RELAY_ENDPOINT_CHALLENGE => {
                parse_bind_udp_relay_endpoint_challenge(ver, body)
            }
            TYPE_BIND_UDP_RELAY_ENDPOINT_ANSWER => parse_bind_udp_relay_endpoint_answer(ver, body),
            TYPE_CALL_ME_MAYBE_VIA => parse_call_me_maybe_via(ver, body),
            TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST => {
                parse_allocate_udp_relay_endpoint_request(ver, body)
            }
            TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE => {
                parse_allocate_udp_relay_endpoint_response(ver, body)
            }
            _ => Err(DiscoError::UnknownType(typ)),
        }
    }

    /// Marshal the payload (type + version + body), WITHOUT the crypto envelope.
    pub fn marshal(&self) -> Vec<u8> {
        match self {
            Message::Ping(m) => m.marshal(),
            Message::Pong(m) => m.marshal(),
            Message::CallMeMaybe(m) => m.marshal(),
            Message::BindUdpRelayEndpoint(m) => m.marshal(),
            Message::BindUdpRelayEndpointChallenge(m) => m.marshal(),
            Message::BindUdpRelayEndpointAnswer(m) => m.marshal(),
            Message::CallMeMaybeVia(m) => m.marshal(),
            Message::AllocateUdpRelayEndpointRequest(m) => m.marshal(),
            Message::AllocateUdpRelayEndpointResponse(m) => m.marshal(),
        }
    }

    /// Short summary for logging, matching Go's `MessageSummary`.
    pub fn summary(&self) -> String {
        match self {
            Message::Ping(m) => {
                format!("ping tx={} padding={}", hex::encode(&m.tx_id[..6]), m.padding)
            }
            Message::Pong(m) => format!("pong tx={}", hex::encode(&m.tx_id[..6])),
            Message::CallMeMaybe(_) => "call-me-maybe".into(),
            Message::CallMeMaybeVia(_) => "call-me-maybe-via".into(),
            Message::BindUdpRelayEndpoint(_) => "bind-udp-relay-endpoint".into(),
            Message::BindUdpRelayEndpointChallenge(_) => "bind-udp-relay-endpoint-challenge".into(),
            Message::BindUdpRelayEndpointAnswer(_) => "bind-udp-relay-endpoint-answer".into(),
            Message::AllocateUdpRelayEndpointRequest(_) => {
                "allocate-udp-relay-endpoint-request".into()
            }
            Message::AllocateUdpRelayEndpointResponse(_) => {
                "allocate-udp-relay-endpoint-response".into()
            }
        }
    }
}

/// Errors from parsing a disco message.
#[derive(Debug, thiserror::Error)]
pub enum DiscoError {
    #[error("short message")]
    Short,
    #[error("unknown message type 0x{0:02x}")]
    UnknownType(u8),
}

pub const MESSAGE_HEADER_LEN: usize = 2;

// ---------------------------------------------------------------------------
// Ping
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ping {
    pub tx_id: [u8; 12],
    pub node_key: NodePublic,
    pub padding: usize,
}

impl Ping {
    fn marshal(&self) -> Vec<u8> {
        let has_key = !self.node_key.is_zero();
        let data_len = 12 + if has_key { KEY_LEN } else { 0 } + self.padding;
        let mut out = vec![0u8; MESSAGE_HEADER_LEN + data_len];
        out[0] = TYPE_PING;
        out[1] = V0;
        let off = MESSAGE_HEADER_LEN;
        out[off..off + 12].copy_from_slice(&self.tx_id);
        if has_key {
            out[off + 12..off + 12 + KEY_LEN].copy_from_slice(&self.node_key.raw32());
        }
        out
    }
}

fn parse_ping(_ver: u8, body: &[u8]) -> Result<Message, DiscoError> {
    if body.len() < 12 {
        return Err(DiscoError::Short);
    }
    let mut tx_id = [0u8; 12];
    tx_id.copy_from_slice(&body[..12]);
    let rest = &body[12..];
    let mut padding = rest.len();
    let mut node_key = NodePublic::from_raw32([0u8; KEY_LEN]);
    if rest.len() >= KEY_LEN {
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&rest[..KEY_LEN]);
        node_key = NodePublic::from_raw32(k);
        padding -= KEY_LEN;
    }
    Ok(Message::Ping(Ping {
        tx_id,
        node_key,
        padding,
    }))
}

// ---------------------------------------------------------------------------
// Pong
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pong {
    pub tx_id: [u8; 12],
    pub src: AddrPort,
}

impl Pong {
    fn marshal(&self) -> Vec<u8> {
        let mut out = vec![0u8; MESSAGE_HEADER_LEN + PONG_LEN];
        out[0] = TYPE_PONG;
        out[1] = V0;
        let off = MESSAGE_HEADER_LEN;
        out[off..off + 12].copy_from_slice(&self.tx_id);
        self.src.encode_to(&mut out[off + 12..off + 12 + EP_LENGTH]);
        out
    }
}

fn parse_pong(_ver: u8, body: &[u8]) -> Result<Message, DiscoError> {
    if body.len() < PONG_LEN {
        return Err(DiscoError::Short);
    }
    let mut tx_id = [0u8; 12];
    tx_id.copy_from_slice(&body[..12]);
    let src = AddrPort::decode_from(&body[12..12 + EP_LENGTH]);
    Ok(Message::Pong(Pong { tx_id, src }))
}

// ---------------------------------------------------------------------------
// CallMeMaybe
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallMeMaybe {
    pub my_number: Vec<AddrPort>,
}

impl CallMeMaybe {
    fn marshal(&self) -> Vec<u8> {
        let data_len = EP_LENGTH * self.my_number.len();
        let mut out = vec![0u8; MESSAGE_HEADER_LEN + data_len];
        out[0] = TYPE_CALL_ME_MAYBE;
        out[1] = V0;
        let mut off = MESSAGE_HEADER_LEN;
        for ep in &self.my_number {
            ep.encode_to(&mut out[off..off + EP_LENGTH]);
            off += EP_LENGTH;
        }
        out
    }
}

#[allow(clippy::unnecessary_wraps)]
fn parse_call_me_maybe(ver: u8, body: &[u8]) -> Result<Message, DiscoError> {
    let mut m = CallMeMaybe::default();
    if !body.len().is_multiple_of(EP_LENGTH) || ver != 0 || body.is_empty() {
        return Ok(Message::CallMeMaybe(m));
    }
    m.my_number = Vec::with_capacity(body.len() / EP_LENGTH);
    let mut off = 0;
    while off < body.len() {
        m.my_number
            .push(AddrPort::decode_from(&body[off..off + EP_LENGTH]));
        off += EP_LENGTH;
    }
    Ok(Message::CallMeMaybe(m))
}

// ---------------------------------------------------------------------------
// BindUDPRelayEndpoint common
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindUdpRelayEndpointCommon {
    pub vni: u32,
    pub generation: u32,
    pub remote_key: DiscoPublic,
    pub challenge: [u8; BIND_UDP_RELAY_CHALLENGE_LEN],
}

impl BindUdpRelayEndpointCommon {
    fn encode_to(&self, buf: &mut [u8]) {
        debug_assert_eq!(buf.len(), BIND_UDP_RELAY_ENDPOINT_COMMON_LEN);
        buf[0..4].copy_from_slice(&self.vni.to_be_bytes());
        buf[4..8].copy_from_slice(&self.generation.to_be_bytes());
        buf[8..8 + KEY_LEN].copy_from_slice(&self.remote_key.raw32());
        buf[8 + KEY_LEN..].copy_from_slice(&self.challenge);
    }

    fn decode_from(body: &[u8]) -> Result<Self, DiscoError> {
        if body.len() < BIND_UDP_RELAY_ENDPOINT_COMMON_LEN {
            return Err(DiscoError::Short);
        }
        let vni = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let generation = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
        let mut rk = [0u8; KEY_LEN];
        rk.copy_from_slice(&body[8..8 + KEY_LEN]);
        let mut challenge = [0u8; BIND_UDP_RELAY_CHALLENGE_LEN];
        challenge.copy_from_slice(&body[8 + KEY_LEN..8 + KEY_LEN + BIND_UDP_RELAY_CHALLENGE_LEN]);
        Ok(Self {
            vni,
            generation,
            remote_key: DiscoPublic::from_raw32(rk),
            challenge,
        })
    }
}

macro_rules! bind_relay_msg {
    ($name:ident, $type_byte:expr, $marshal_name:ident, $parse_name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            pub common: BindUdpRelayEndpointCommon,
        }

        impl $name {
            fn marshal(&self) -> Vec<u8> {
                let mut out = vec![0u8; MESSAGE_HEADER_LEN + BIND_UDP_RELAY_ENDPOINT_COMMON_LEN];
                out[0] = $type_byte;
                out[1] = V0;
                self.common
                    .encode_to(&mut out[MESSAGE_HEADER_LEN..]);
                out
            }
        }

        fn $parse_name(_ver: u8, body: &[u8]) -> Result<Message, DiscoError> {
            let common = BindUdpRelayEndpointCommon::decode_from(body)?;
            Ok(Message::$name($name { common }))
        }
    };
}

bind_relay_msg!(
    BindUdpRelayEndpoint,
    TYPE_BIND_UDP_RELAY_ENDPOINT,
    marshal_bind_udp_relay_endpoint,
    parse_bind_udp_relay_endpoint,
    "First message of the 3-way UDP relay bind handshake (client -> server)."
);
bind_relay_msg!(
    BindUdpRelayEndpointChallenge,
    TYPE_BIND_UDP_RELAY_ENDPOINT_CHALLENGE,
    marshal_bind_udp_relay_endpoint_challenge,
    parse_bind_udp_relay_endpoint_challenge,
    "Second message of the 3-way UDP relay bind handshake (server -> client)."
);
bind_relay_msg!(
    BindUdpRelayEndpointAnswer,
    TYPE_BIND_UDP_RELAY_ENDPOINT_ANSWER,
    marshal_bind_udp_relay_endpoint_answer,
    parse_bind_udp_relay_endpoint_answer,
    "Third message of the 3-way UDP relay bind handshake (client -> server)."
);

// ---------------------------------------------------------------------------
// UDPRelayEndpoint (shared by CallMeMaybeVia and AllocateUDPRelayEndpointResponse)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpRelayEndpoint {
    pub server_disco: DiscoPublic,
    pub client_disco: [DiscoPublic; 2],
    pub lamport_id: u64,
    pub vni: u32,
    pub bind_lifetime: Duration,
    pub steady_state_lifetime: Duration,
    pub addr_ports: Vec<AddrPort>,
}

impl UdpRelayEndpoint {
    fn encode_to(&self, buf: &mut [u8]) {
        let mut off = 0;
        buf[off..off + KEY_LEN].copy_from_slice(&self.server_disco.raw32());
        off += KEY_LEN;
        for cd in &self.client_disco {
            buf[off..off + KEY_LEN].copy_from_slice(&cd.raw32());
            off += KEY_LEN;
        }
        buf[off..off + 8].copy_from_slice(&self.lamport_id.to_be_bytes());
        off += 8;
        buf[off..off + 4].copy_from_slice(&self.vni.to_be_bytes());
        off += 4;
        buf[off..off + 8].copy_from_slice(&(self.bind_lifetime.as_nanos() as u64).to_be_bytes());
        off += 8;
        buf[off..off + 8]
            .copy_from_slice(&(self.steady_state_lifetime.as_nanos() as u64).to_be_bytes());
        off += 8;
        for ep in &self.addr_ports {
            ep.encode_to(&mut buf[off..off + EP_LENGTH]);
            off += EP_LENGTH;
        }
    }

    fn total_len(&self) -> usize {
        UDP_RELAY_ENDPOINT_LEN_MINUS_ADDRPORTS + EP_LENGTH * self.addr_ports.len()
    }

    fn decode_from(body: &[u8]) -> Result<Self, DiscoError> {
        if body.len() < UDP_RELAY_ENDPOINT_LEN_MINUS_ADDRPORTS + EP_LENGTH
            || !(body.len() - UDP_RELAY_ENDPOINT_LEN_MINUS_ADDRPORTS).is_multiple_of(EP_LENGTH)
        {
            return Err(DiscoError::Short);
        }
        let mut off = 0;
        let mut sd = [0u8; KEY_LEN];
        sd.copy_from_slice(&body[off..off + KEY_LEN]);
        off += KEY_LEN;
        let mut client_disco = zero_disco_pair();
        for cd in &mut client_disco {
            let mut k = [0u8; KEY_LEN];
            k.copy_from_slice(&body[off..off + KEY_LEN]);
            *cd = DiscoPublic::from_raw32(k);
            off += KEY_LEN;
        }
        let lamport_id = u64::from_be_bytes([
            body[off],
            body[off + 1],
            body[off + 2],
            body[off + 3],
            body[off + 4],
            body[off + 5],
            body[off + 6],
            body[off + 7],
        ]);
        off += 8;
        let vni = u32::from_be_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]);
        off += 4;
        let bind_ns = u64::from_be_bytes([
            body[off],
            body[off + 1],
            body[off + 2],
            body[off + 3],
            body[off + 4],
            body[off + 5],
            body[off + 6],
            body[off + 7],
        ]);
        off += 8;
        let steady_ns = u64::from_be_bytes([
            body[off],
            body[off + 1],
            body[off + 2],
            body[off + 3],
            body[off + 4],
            body[off + 5],
            body[off + 6],
            body[off + 7],
        ]);
        off += 8;
        let remaining = &body[off..];
        let n = remaining.len() / EP_LENGTH;
        let mut addr_ports = Vec::with_capacity(n);
        let mut roff = 0;
        while roff < remaining.len() {
            addr_ports.push(AddrPort::decode_from(&remaining[roff..roff + EP_LENGTH]));
            roff += EP_LENGTH;
        }
        Ok(Self {
            server_disco: DiscoPublic::from_raw32(sd),
            client_disco,
            lamport_id,
            vni,
            bind_lifetime: Duration::from_nanos(bind_ns),
            steady_state_lifetime: Duration::from_nanos(steady_ns),
            addr_ports,
        })
    }
}

// ---------------------------------------------------------------------------
// CallMeMaybeVia
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallMeMaybeVia {
    pub endpoint: UdpRelayEndpoint,
}

impl CallMeMaybeVia {
    fn marshal(&self) -> Vec<u8> {
        let data_len = self.endpoint.total_len();
        let mut out = vec![0u8; MESSAGE_HEADER_LEN + data_len];
        out[0] = TYPE_CALL_ME_MAYBE_VIA;
        out[1] = V0;
        self.endpoint.encode_to(&mut out[MESSAGE_HEADER_LEN..]);
        out
    }
}

fn parse_call_me_maybe_via(ver: u8, body: &[u8]) -> Result<Message, DiscoError> {
    let mut m = CallMeMaybeVia {
        endpoint: UdpRelayEndpoint {
            server_disco: DiscoPublic::from_raw32([0u8; KEY_LEN]),
            client_disco: zero_disco_pair(),
            lamport_id: 0,
            vni: 0,
            bind_lifetime: Duration::ZERO,
            steady_state_lifetime: Duration::ZERO,
            addr_ports: Vec::new(),
        },
    };
    if ver != 0 {
        return Ok(Message::CallMeMaybeVia(m));
    }
    m.endpoint = UdpRelayEndpoint::decode_from(body)?;
    Ok(Message::CallMeMaybeVia(m))
}

// ---------------------------------------------------------------------------
// AllocateUDPRelayEndpointRequest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocateUdpRelayEndpointRequest {
    pub client_disco: [DiscoPublic; 2],
    pub generation: u32,
}

impl AllocateUdpRelayEndpointRequest {
    fn marshal(&self) -> Vec<u8> {
        let mut out = vec![0u8; MESSAGE_HEADER_LEN + ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST_LEN];
        out[0] = TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST;
        out[1] = V0;
        let mut off = MESSAGE_HEADER_LEN;
        for cd in &self.client_disco {
            out[off..off + KEY_LEN].copy_from_slice(&cd.raw32());
            off += KEY_LEN;
        }
        out[off..off + 4].copy_from_slice(&self.generation.to_be_bytes());
        out
    }
}

fn parse_allocate_udp_relay_endpoint_request(
    ver: u8,
    body: &[u8],
) -> Result<Message, DiscoError> {
    let mut m = AllocateUdpRelayEndpointRequest {
        client_disco: zero_disco_pair(),
        generation: 0,
    };
    if ver != 0 {
        return Ok(Message::AllocateUdpRelayEndpointRequest(m));
    }
    if body.len() < ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST_LEN {
        return Err(DiscoError::Short);
    }
    let mut off = 0;
    for cd in &mut m.client_disco {
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&body[off..off + KEY_LEN]);
        *cd = DiscoPublic::from_raw32(k);
        off += KEY_LEN;
    }
    m.generation = u32::from_be_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]);
    Ok(Message::AllocateUdpRelayEndpointRequest(m))
}

// ---------------------------------------------------------------------------
// AllocateUDPRelayEndpointResponse
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocateUdpRelayEndpointResponse {
    pub generation: u32,
    pub endpoint: UdpRelayEndpoint,
}

impl AllocateUdpRelayEndpointResponse {
    fn marshal(&self) -> Vec<u8> {
        let data_len = 4 + self.endpoint.total_len();
        let mut out = vec![0u8; MESSAGE_HEADER_LEN + data_len];
        out[0] = TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE;
        out[1] = V0;
        let off = MESSAGE_HEADER_LEN;
        out[off..off + 4].copy_from_slice(&self.generation.to_be_bytes());
        self.endpoint.encode_to(&mut out[off + 4..]);
        out
    }
}

fn parse_allocate_udp_relay_endpoint_response(
    ver: u8,
    body: &[u8],
) -> Result<Message, DiscoError> {
    let mut m = AllocateUdpRelayEndpointResponse {
        generation: 0,
        endpoint: UdpRelayEndpoint {
            server_disco: DiscoPublic::from_raw32([0u8; KEY_LEN]),
            client_disco: zero_disco_pair(),
            lamport_id: 0,
            vni: 0,
            bind_lifetime: Duration::ZERO,
            steady_state_lifetime: Duration::ZERO,
            addr_ports: Vec::new(),
        },
    };
    if ver != 0 {
        return Ok(Message::AllocateUdpRelayEndpointResponse(m));
    }
    if body.len() < 4 {
        return Err(DiscoError::Short);
    }
    m.generation = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    m.endpoint = UdpRelayEndpoint::decode_from(&body[4..])?;
    Ok(Message::AllocateUdpRelayEndpointResponse(m))
}
