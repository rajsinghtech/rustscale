//! Noise IK handshake and post-handshake framing for the Tailscale
//! control protocol (ts2021).
//!
//! Ports Go's `control/controlbase` package. The protocol is
//! `Noise_IK_25519_ChaChaPoly_BLAKE2s` with a Tailscale-specific
//! protocol-version prologue mixed into the handshake hash.
//!
//! ## Wire format
//!
//! Handshake initiation (client -> server, 101 bytes):
//! ```text
//! u16 BE  protocol version
//! u8      message type (1 = initiation)
//! u16 BE  payload length (96)
//! [32]    client ephemeral public key (cleartext)
//! [48]    client machine public key (encrypted + 16-byte tag)
//! [16]    message tag (empty-payload auth)
//! ```
//!
//! Handshake response (server -> client, 51 bytes):
//! ```text
//! u8      message type (2 = response)
//! u16 BE  payload length (48)
//! [32]    server ephemeral public key (cleartext)
//! [16]    message tag (empty-payload auth)
//! ```
//!
//! Post-handshake records:
//! ```text
//! u8      message type (4 = record)
//! u16 BE  ciphertext length (plaintext + 16-byte tag)
//! [N]     ChaCha20Poly1305 ciphertext with incrementing 12-byte BE nonce
//! ```

use std::io;

use blake2::digest::Update;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use curve25519_dalek::{constants::X25519_BASEPOINT, montgomery::MontgomeryPoint};
use rand::RngCore;
use rustscale_key::{MachinePrivate, MachinePublic};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Errors from the Noise handshake and transport.
#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    /// The server returned an error message during the handshake.
    #[error("server error: {0}")]
    ServerError(String),
    /// The handshake response was malformed or failed authentication.
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// An I/O error on the underlying transport.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// Decryption of a transport record failed (connection desynchronized).
    #[error("decrypt failed")]
    Decrypt,
    /// The cipher nonce space is exhausted (2^64 - 1 records sent/received).
    #[error("cipher exhausted")]
    CipherExhausted,
    /// A frame exceeded the maximum Noise message size.
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
}

/// Tailscale control protocol version (mixed into the handshake prologue).
pub type ProtocolVersion = u16;

const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROTOCOL_VERSION_PREFIX: &[u8] = b"Tailscale Control Protocol v";

// Message type bytes.
const MSG_TYPE_INITIATION: u8 = 1;
const MSG_TYPE_RESPONSE: u8 = 2;
const MSG_TYPE_ERROR: u8 = 3;
const MSG_TYPE_RECORD: u8 = 4;

// Header sizes.
const HEADER_LEN: usize = 3;
const INITIATION_HEADER_LEN: usize = 5;

// Payload sizes (derived from the Go `initiationMessage`/`responseMessage`).
const CHACHA_TAG_LEN: usize = 16;
const INITIATION_PAYLOAD_LEN: usize = 32 + 48 + 16; // 96
const RESPONSE_PAYLOAD_LEN: usize = 32 + 16; // 48
const INITIATION_MSG_LEN: usize = INITIATION_HEADER_LEN + INITIATION_PAYLOAD_LEN; // 101
const RESPONSE_MSG_LEN: usize = HEADER_LEN + RESPONSE_PAYLOAD_LEN; // 51

// Transport framing limits (from Go `conn.go`).
const MAX_MESSAGE_SIZE: usize = 4096;
const MAX_CIPHERTEXT_SIZE: usize = MAX_MESSAGE_SIZE - HEADER_LEN;
const MAX_PLAINTEXT_SIZE: usize = MAX_CIPHERTEXT_SIZE - CHACHA_TAG_LEN;

const CHACHA_KEY_LEN: usize = 32;
const CHACHA_NONCE_LEN: usize = 12;
const BLAKE2S_SIZE: usize = 32;
const INVALID_NONCE: u64 = u64::MAX;

fn protocol_version_prologue(version: ProtocolVersion) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROTOCOL_VERSION_PREFIX.len() + 5);
    out.extend_from_slice(PROTOCOL_VERSION_PREFIX);
    out.extend_from_slice(version.to_string().as_bytes());
    out
}

/// A BLAKE2s-256 hasher producing 32-byte output.
fn blake2s256_hash(data: &[u8]) -> [u8; BLAKE2S_SIZE] {
    use blake2::Digest;
    let mut hasher = blake2::Blake2s256::new();
    Update::update(&mut hasher, data);
    let result = hasher.finalize();
    let mut out = [0u8; BLAKE2S_SIZE];
    out.copy_from_slice(&result);
    out
}

/// `MixHash`: `h = BLAKE2s(h || data)`.
fn mix_hash(h: &mut [u8; BLAKE2S_SIZE], data: &[u8]) {
    use blake2::Digest;
    let mut hasher = blake2::Blake2s256::new();
    Update::update(&mut hasher, h);
    Update::update(&mut hasher, data);
    let result = hasher.finalize();
    h.copy_from_slice(&result);
}

/// HMAC-BLAKE2s (RFC 2104) with 64-byte block size, 32-byte output.
/// Go's `hkdf.New(blake2s.New256, ...)` uses this internally.
fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; BLAKE2S_SIZE] {
    use blake2::Digest;
    const BLOCK_SIZE: usize = 64;
    let mut k = [0u8; BLOCK_SIZE];
    if key.len() <= BLOCK_SIZE {
        k[..key.len()].copy_from_slice(key);
    } else {
        let h = blake2s256_hash(key);
        k[..BLAKE2S_SIZE].copy_from_slice(&h);
    }
    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    let mut inner = blake2::Blake2s256::new();
    Update::update(&mut inner, &ipad);
    Update::update(&mut inner, data);
    let inner_result = inner.finalize();

    let mut outer = blake2::Blake2s256::new();
    Update::update(&mut outer, &opad);
    Update::update(&mut outer, &inner_result);
    let result = outer.finalize();
    let mut out = [0u8; BLAKE2S_SIZE];
    out.copy_from_slice(&result);
    out
}

/// HKDF-BLAKE2s (RFC 5869): extract+expand. Matches Go's
/// `hkdf.New(newBLAKE2s, ikm, salt, info)`.
fn hkdf_blake2s(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let prk = hmac_blake2s(salt, ikm);
    // Expand
    let mut t: Vec<u8> = Vec::new();
    let mut pos = 0;
    let mut counter: u8 = 1;
    while pos < out.len() {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(counter);
        t = hmac_blake2s(&prk, &input).to_vec();
        let take = (out.len() - pos).min(t.len());
        out[pos..pos + take].copy_from_slice(&t[..take]);
        pos += take;
        counter += 1;
    }
}

/// `MixKey(X25519(priv, pub))`: HKDF(ck, dh) -> (new_ck, k).
fn mix_key(ck: &mut [u8; BLAKE2S_SIZE], ikm: &[u8]) -> [u8; CHACHA_KEY_LEN] {
    let mut both = [0u8; BLAKE2S_SIZE + CHACHA_KEY_LEN];
    hkdf_blake2s(ck, ikm, &[], &mut both);
    let mut new_ck = [0u8; BLAKE2S_SIZE];
    let mut k = [0u8; CHACHA_KEY_LEN];
    new_ck.copy_from_slice(&both[..BLAKE2S_SIZE]);
    k.copy_from_slice(&both[BLAKE2S_SIZE..]);
    *ck = new_ck;
    k
}

/// HKDF-Split: derive two 32-byte keys from `ck`.
fn split(ck: &[u8; BLAKE2S_SIZE]) -> ([u8; CHACHA_KEY_LEN], [u8; CHACHA_KEY_LEN]) {
    let mut both = [0u8; 2 * CHACHA_KEY_LEN];
    hkdf_blake2s(ck, &[], &[], &mut both);
    let mut k1 = [0u8; CHACHA_KEY_LEN];
    let mut k2 = [0u8; CHACHA_KEY_LEN];
    k1.copy_from_slice(&both[..CHACHA_KEY_LEN]);
    k2.copy_from_slice(&both[CHACHA_KEY_LEN..]);
    (k1, k2)
}

/// X25519 scalar multiplication: `X25519(priv, pub)`.
fn x25519(priv_key: &[u8; 32], pub_key: &[u8; 32]) -> [u8; 32] {
    let pub_point = MontgomeryPoint(*pub_key);
    pub_point.mul_clamped(*priv_key).0
}

/// Derive the public key from a clamped private scalar (X25519 basepoint mult).
fn x25519_basepoint(priv_key: &[u8; 32]) -> [u8; 32] {
    X25519_BASEPOINT.mul_clamped(*priv_key).0
}

/// In-flight Noise handshake state (the Go `symmetricState`).
struct SymmetricState {
    h: [u8; BLAKE2S_SIZE],
    ck: [u8; BLAKE2S_SIZE],
    finished: bool,
}

impl SymmetricState {
    fn new() -> Self {
        let h = blake2s256_hash(PROTOCOL_NAME);
        let ck = h;
        Self {
            h,
            ck,
            finished: false,
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        mix_hash(&mut self.h, data);
    }

    /// MixDH: `MixKey(X25519(priv, pub))` -> returns a one-shot AEAD key.
    fn mix_dh(&mut self, priv_key: &[u8; 32], pub_key: &[u8; 32]) -> [u8; CHACHA_KEY_LEN] {
        let dh = x25519(priv_key, pub_key);
        mix_key(&mut self.ck, &dh)
    }

    /// EncryptAndHash: AEAD seal with all-zero nonce, AD = h, then MixHash(ct).
    fn encrypt_and_hash(&mut self, key: &[u8; CHACHA_KEY_LEN], plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(&[0u8; CHACHA_NONCE_LEN]);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &self.h,
                },
            )
            .expect("chacha seal");
        self.mix_hash(&ct);
        ct
    }

    /// DecryptAndHash: AEAD open with all-zero nonce, AD = h, then MixHash(ct).
    fn decrypt_and_hash(
        &mut self,
        key: &[u8; CHACHA_KEY_LEN],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(&[0u8; CHACHA_NONCE_LEN]);
        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &self.h,
                },
            )
            .map_err(|_| NoiseError::Decrypt)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    fn split(&mut self) -> ([u8; CHACHA_KEY_LEN], [u8; CHACHA_KEY_LEN]) {
        self.finished = true;
        split(&self.ck)
    }
}

/// Build the 101-byte initiation message (client side).
fn build_initiation(
    version: ProtocolVersion,
    machine_key: &MachinePrivate,
    control_key: &MachinePublic,
    machine_ephemeral: &[u8; 32],
) -> (Vec<u8>, SymmetricState) {
    let mut s = SymmetricState::new();
    // prologue
    s.mix_hash(&protocol_version_prologue(version));
    // <- s (server's known static)
    s.mix_hash(&control_key.raw32());

    let mut msg = vec![0u8; INITIATION_MSG_LEN];
    // header
    msg[0..2].copy_from_slice(&version.to_be_bytes());
    msg[2] = MSG_TYPE_INITIATION;
    msg[3..5].copy_from_slice(&(INITIATION_PAYLOAD_LEN as u16).to_be_bytes());

    // -> e
    let ephemeral_pub = x25519_basepoint(machine_ephemeral);
    msg[INITIATION_HEADER_LEN..INITIATION_HEADER_LEN + 32].copy_from_slice(&ephemeral_pub);
    s.mix_hash(&ephemeral_pub);

    // -> es (DH with client ephemeral priv, server static pub)
    let es_key = s.mix_dh(machine_ephemeral, &control_key.raw32());

    // -> s (encrypted machine static pub, 32 bytes -> 48 with tag)
    let machine_pub = machine_key.public();
    let ct = s.encrypt_and_hash(&es_key, &machine_pub.raw32());
    msg[INITIATION_HEADER_LEN + 32..INITIATION_HEADER_LEN + 32 + 48].copy_from_slice(&ct);

    // -> ss (DH with machine static priv, server static pub)
    let ss_key = s.mix_dh(&machine_key.raw32(), &control_key.raw32());

    // empty payload -> 16-byte tag
    let tag = s.encrypt_and_hash(&ss_key, &[]);
    msg[INITIATION_HEADER_LEN + 32 + 48..].copy_from_slice(&tag);

    (msg, s)
}

/// Result of [`client_deferred`]: the initial handshake bytes plus a
/// continuation that finishes the handshake once the server replies.
pub struct DeferredHandshake {
    /// The 101-byte initiation message to send to the server.
    pub init: Vec<u8>,
    machine_ephemeral: [u8; 32],
    state: SymmetricState,
    machine_key: MachinePrivate,
    control_key: MachinePublic,
    version: ProtocolVersion,
}

/// Begin a client handshake, returning the initial message to send and a
/// continuation. Matches Go's `controlbase.ClientDeferred`.
pub fn client_deferred(
    machine_key: &MachinePrivate,
    control_key: &MachinePublic,
    version: ProtocolVersion,
) -> DeferredHandshake {
    let mut machine_ephemeral = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut machine_ephemeral);
    // Clamp the ephemeral private (X25519 clamping, like Go's NewMachine).
    machine_ephemeral[0] &= 248;
    machine_ephemeral[31] = (machine_ephemeral[31] & 127) | 64;

    let (init, state) = build_initiation(version, machine_key, control_key, &machine_ephemeral);

    DeferredHandshake {
        init,
        machine_ephemeral,
        state,
        machine_key: machine_key.clone(),
        control_key: control_key.clone(),
        version,
    }
}

impl DeferredHandshake {
    /// Continue the handshake by reading the server's 51-byte response
    /// from `r`, finalizing the Noise session.
    pub fn continue_handshake<R: io::Read>(self, r: &mut R) -> Result<NoiseConn, NoiseError> {
        // Read response header + payload (51 bytes total).
        let mut resp = [0u8; RESPONSE_MSG_LEN];
        r.read_exact(&mut resp)?;
        self.finish_from_response_bytes(&resp)
    }

    /// Finish the handshake from an already-read response buffer (sync).
    /// Used when the response bytes have been read separately (e.g. async).
    pub fn finish_from_response_bytes(mut self, resp: &[u8]) -> Result<NoiseConn, NoiseError> {
        if resp[0] != MSG_TYPE_RESPONSE {
            if resp[0] == MSG_TYPE_ERROR {
                let len = u16::from_be_bytes([resp[1], resp[2]]) as usize;
                if resp.len() < HEADER_LEN + len {
                    return Err(NoiseError::ServerError("(truncated error)".into()));
                }
                let msg = String::from_utf8_lossy(&resp[HEADER_LEN..HEADER_LEN + len]);
                return Err(NoiseError::ServerError(msg.into_owned()));
            }
            return Err(NoiseError::Handshake(format!(
                "unexpected response message type {}",
                resp[0]
            )));
        }
        let declared_len = u16::from_be_bytes([resp[1], resp[2]]) as usize;
        if declared_len != RESPONSE_PAYLOAD_LEN {
            return Err(NoiseError::Handshake(format!(
                "wrong response length {declared_len}"
            )));
        }

        // <- e, ee, se
        let control_ephemeral_pub: [u8; 32] =
            resp[HEADER_LEN..HEADER_LEN + 32].try_into().expect("32");
        self.state.mix_hash(&control_ephemeral_pub);
        let _ee_key = self
            .state
            .mix_dh(&self.machine_ephemeral, &control_ephemeral_pub);
        let se_key = self
            .state
            .mix_dh(&self.machine_key.raw32(), &control_ephemeral_pub);
        let tag = &resp[HEADER_LEN + 32..];
        let _ = self.state.decrypt_and_hash(&se_key, tag)?;
        let (c1, c2) = self.state.split();

        Ok(NoiseConn {
            version: self.version,
            peer: self.control_key,
            handshake_hash: self.state.h,
            tx: CipherState::new(c1), // client tx = c1 (matching Go)
            rx: CipherState::new(c2), // client rx = c2
        })
    }
}

/// Server-side handshake responder (used by tests and in-process fakes).
///
/// Reads the initiation (or accepts it inline), processes it, and writes
/// the 51-byte response. Matches Go's `controlbase.Server`.
pub fn server_handshake<R: io::Read, W: io::Write>(
    r: &mut R,
    w: &mut W,
    control_key: &MachinePrivate,
    optional_init: Option<&[u8]>,
) -> Result<NoiseConn, NoiseError> {
    let mut init = [0u8; INITIATION_MSG_LEN];
    if let Some(provided) = optional_init {
        if provided.len() != INITIATION_MSG_LEN {
            send_error(w, "wrong handshake initiation size")?;
            return Err(NoiseError::Handshake(
                "wrong handshake initiation size".into(),
            ));
        }
        init.copy_from_slice(provided);
    } else {
        r.read_exact(&mut init)?;
    }

    let client_version = u16::from_be_bytes([init[0], init[1]]);
    if init[2] != MSG_TYPE_INITIATION {
        send_error(w, "unexpected handshake message type")?;
        return Err(NoiseError::Handshake(
            "unexpected handshake message type".into(),
        ));
    }
    let declared_len = u16::from_be_bytes([init[3], init[4]]) as usize;
    if declared_len != INITIATION_PAYLOAD_LEN {
        send_error(w, "wrong handshake initiation length")?;
        return Err(NoiseError::Handshake(
            "wrong handshake initiation length".into(),
        ));
    }

    let mut s = SymmetricState::new();
    s.mix_hash(&protocol_version_prologue(client_version));

    // <- s (server's own static, known to both)
    let control_pub = control_key.public();
    s.mix_hash(&control_pub.raw32());

    // -> e
    let machine_ephemeral_pub: [u8; 32] = init[INITIATION_HEADER_LEN..INITIATION_HEADER_LEN + 32]
        .try_into()
        .expect("32");
    s.mix_hash(&machine_ephemeral_pub);

    // -> es
    let es_key = s.mix_dh(&control_key.raw32(), &machine_ephemeral_pub);

    // -> s (decrypt machine static pub)
    let machine_pub_ct = &init[INITIATION_HEADER_LEN + 32..INITIATION_HEADER_LEN + 32 + 48];
    let machine_pub_bytes = s.decrypt_and_hash(&es_key, machine_pub_ct)?;
    let mut machine_pub_arr = [0u8; 32];
    machine_pub_arr.copy_from_slice(&machine_pub_bytes);
    let machine_key = MachinePublic::from_raw32(machine_pub_arr);

    // -> ss
    let ss_key = s.mix_dh(&control_key.raw32(), &machine_key.raw32());
    let init_tag = &init[INITIATION_HEADER_LEN + 32 + 48..];
    let _ = s.decrypt_and_hash(&ss_key, init_tag)?;

    // <- e, ee, se (build response)
    let mut control_ephemeral = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut control_ephemeral);
    control_ephemeral[0] &= 248;
    control_ephemeral[31] = (control_ephemeral[31] & 127) | 64;
    let control_ephemeral_pub = x25519_basepoint(&control_ephemeral);

    let mut resp = [0u8; RESPONSE_MSG_LEN];
    resp[0] = MSG_TYPE_RESPONSE;
    resp[1..3].copy_from_slice(&(RESPONSE_PAYLOAD_LEN as u16).to_be_bytes());
    resp[HEADER_LEN..HEADER_LEN + 32].copy_from_slice(&control_ephemeral_pub);
    s.mix_hash(&control_ephemeral_pub);

    // ee
    let _ = s.mix_dh(&control_ephemeral, &machine_ephemeral_pub);
    // se
    let dh_se = s.mix_dh(&control_ephemeral, &machine_key.raw32());
    let tag = s.encrypt_and_hash(&dh_se, &[]);
    resp[HEADER_LEN + 32..].copy_from_slice(&tag);

    let (c1, c2) = s.split();
    w.write_all(&resp)?;

    Ok(NoiseConn {
        version: client_version,
        peer: machine_key,
        handshake_hash: s.h,
        tx: CipherState::new(c2), // server tx = c2 (matching Go)
        rx: CipherState::new(c1), // server rx = c1
    })
}

fn send_error<W: io::Write>(w: &mut W, msg: &str) -> io::Result<()> {
    let msg = if msg.len() >= 1 << 16 {
        &msg[..1 << 16]
    } else {
        msg
    };
    let mut hdr = [0u8; HEADER_LEN];
    hdr[0] = MSG_TYPE_ERROR;
    hdr[1..3].copy_from_slice(&(msg.len() as u16).to_be_bytes());
    w.write_all(&hdr)?;
    w.write_all(msg.as_bytes())?;
    Ok(())
}

/// A 12-byte incrementing nonce for post-handshake transport records.
#[derive(Clone, Copy)]
struct TransportNonce([u8; CHACHA_NONCE_LEN]);

impl TransportNonce {
    const fn zero() -> Self {
        Self([0u8; CHACHA_NONCE_LEN])
    }

    fn valid(&self) -> bool {
        let prefix = u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]]);
        let counter = u64::from_be_bytes([
            self.0[4], self.0[5], self.0[6], self.0[7], self.0[8], self.0[9], self.0[10],
            self.0[11],
        ]);
        prefix == 0 && counter != INVALID_NONCE
    }

    fn increment(&mut self) {
        let mut counter = u64::from_be_bytes([
            self.0[4], self.0[5], self.0[6], self.0[7], self.0[8], self.0[9], self.0[10],
            self.0[11],
        ]);
        counter += 1;
        let bytes = counter.to_be_bytes();
        self.0[4..].copy_from_slice(&bytes);
    }
}

/// Post-handshake cipher state (one direction).
pub(crate) struct CipherState {
    key: [u8; CHACHA_KEY_LEN],
    nonce: TransportNonce,
}

impl CipherState {
    fn new(key: [u8; CHACHA_KEY_LEN]) -> Self {
        Self {
            key,
            nonce: TransportNonce::zero(),
        }
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if !self.nonce.valid() {
            return Err(NoiseError::CipherExhausted);
        }
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
        let nonce = Nonce::from_slice(&self.nonce.0);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|_| NoiseError::Decrypt)?;
        self.nonce.increment();
        Ok(ct)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if !self.nonce.valid() {
            return Err(NoiseError::CipherExhausted);
        }
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
        let nonce = Nonce::from_slice(&self.nonce.0);
        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &[],
                },
            )
            .map_err(|_| NoiseError::Decrypt)?;
        self.nonce.increment();
        Ok(pt)
    }
}

/// A secured Noise transport connection.
///
/// Wraps a synchronous reader/writer pair (the upgraded HTTP connection).
/// For async use, see the [`crate::controlhttp`] and [`crate::client`]
/// modules which drive this over `tokio` via `tokio::io::AsyncRead`.
pub struct NoiseConn {
    version: ProtocolVersion,
    peer: MachinePublic,
    handshake_hash: [u8; BLAKE2S_SIZE],
    tx: CipherState,
    rx: CipherState,
}

impl NoiseConn {
    /// The negotiated protocol version.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.version
    }

    /// The peer's long-term machine public key.
    pub fn peer(&self) -> MachinePublic {
        self.peer.clone()
    }

    /// The Noise handshake hash (binds this session to the handshake).
    pub fn handshake_hash(&self) -> [u8; BLAKE2S_SIZE] {
        self.handshake_hash
    }

    /// Encrypt and frame one plaintext record, writing it to `w`.
    pub fn write_record<W: io::Write>(&mut self, w: &mut W, plaintext: &[u8]) -> io::Result<()> {
        let mut plaintext = plaintext;
        while !plaintext.is_empty() {
            let chunk = &plaintext[..plaintext.len().min(MAX_PLAINTEXT_SIZE)];
            let ct = self
                .tx
                .encrypt(chunk)
                .map_err(|_| io::Error::other("noise encrypt failed"))?;
            let mut frame = Vec::with_capacity(HEADER_LEN + ct.len());
            frame.push(MSG_TYPE_RECORD);
            frame.extend_from_slice(&(ct.len() as u16).to_be_bytes());
            frame.extend_from_slice(&ct);
            w.write_all(&frame)?;
            plaintext = &plaintext[chunk.len()..];
        }
        Ok(())
    }

    /// Read and decrypt one framed record from `r`.
    pub fn read_record<R: io::Read>(&mut self, r: &mut R) -> Result<Vec<u8>, NoiseError> {
        let mut hdr = [0u8; HEADER_LEN];
        r.read_exact(&mut hdr)?;
        if hdr[0] != MSG_TYPE_RECORD {
            return Err(NoiseError::Handshake(format!(
                "unexpected transport message type {}",
                hdr[0]
            )));
        }
        let len = u16::from_be_bytes([hdr[1], hdr[2]]) as usize;
        if len > MAX_CIPHERTEXT_SIZE {
            return Err(NoiseError::FrameTooLarge(len));
        }
        let mut ct = vec![0u8; len];
        r.read_exact(&mut ct)?;
        self.rx.decrypt(&ct)
    }

    /// Async: encrypt and frame one plaintext record, writing to `w`.
    pub async fn write_record_async<W>(&mut self, w: &mut W, plaintext: &[u8]) -> io::Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        let mut plaintext = plaintext;
        while !plaintext.is_empty() {
            let chunk = &plaintext[..plaintext.len().min(MAX_PLAINTEXT_SIZE)];
            let ct = self
                .tx
                .encrypt(chunk)
                .map_err(|_| io::Error::other("noise encrypt failed"))?;
            let mut frame = Vec::with_capacity(HEADER_LEN + ct.len());
            frame.push(MSG_TYPE_RECORD);
            frame.extend_from_slice(&(ct.len() as u16).to_be_bytes());
            frame.extend_from_slice(&ct);
            w.write_all(&frame).await?;
            plaintext = &plaintext[chunk.len()..];
        }
        Ok(())
    }

    /// Async: read and decrypt one framed record from `r`.
    pub async fn read_record_async<R>(&mut self, r: &mut R) -> Result<Vec<u8>, NoiseError>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;
        let mut hdr = [0u8; HEADER_LEN];
        r.read_exact(&mut hdr).await?;
        if hdr[0] != MSG_TYPE_RECORD {
            return Err(NoiseError::Handshake(format!(
                "unexpected transport message type {}",
                hdr[0]
            )));
        }
        let len = u16::from_be_bytes([hdr[1], hdr[2]]) as usize;
        if len > MAX_CIPHERTEXT_SIZE {
            return Err(NoiseError::FrameTooLarge(len));
        }
        let mut ct = vec![0u8; len];
        r.read_exact(&mut ct).await?;
        self.rx.decrypt(&ct)
    }

    /// Consume the NoiseConn and return the transmit and receive cipher
    /// states. Used by the streaming adapter to split read/write into
    /// independent tasks.
    pub(crate) fn into_ciphers(self) -> (CipherState, CipherState) {
        (self.tx, self.rx)
    }
}

/// An adapter that presents a raw `AsyncRead + AsyncWrite` byte-stream
/// interface over a Noise-encrypted connection.
///
/// Internally spawns two pump tasks:
/// - **Read pump**: reads Noise records from the underlying stream, decrypts
///   them, and writes plaintext to a duplex stream that `h2` reads from.
/// - **Write pump**: reads plaintext that `h2` wrote to the duplex stream,
///   encrypts it into Noise records, and writes them to the underlying stream.
///
/// This matches Go's `controlbase.Conn` which implements `net.Conn` by
/// transparently encrypting/decrypting records.
pub struct NoiseIo {
    inner: tokio::io::DuplexStream,
    _pump: tokio::task::JoinHandle<()>,
}

impl NoiseIo {
    /// Create a NoiseIo from a completed NoiseConn and the underlying async
    /// stream. Spawns background pump tasks.
    pub fn new<S>(conn: NoiseConn, stream: S) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (tx_cipher, rx_cipher) = conn.into_ciphers();
        let (plain_side, noise_side) = tokio::io::duplex(64 * 1024);
        let (mut noise_rx, mut noise_tx) = tokio::io::split(noise_side);
        let (mut stream_rx, mut stream_tx) = tokio::io::split(stream);

        // Read pump: stream → decrypt → noise_tx (h2 reads this via plain_side).
        let pump = tokio::spawn(async move {
            let mut rx = rx_cipher;
            let mut hdr = [0u8; HEADER_LEN];
            loop {
                if stream_rx.read_exact(&mut hdr).await.is_err() {
                    break;
                }
                if hdr[0] != MSG_TYPE_RECORD {
                    break;
                }
                let len = u16::from_be_bytes([hdr[1], hdr[2]]) as usize;
                if len > MAX_CIPHERTEXT_SIZE {
                    break;
                }
                let mut ct = vec![0u8; len];
                if stream_rx.read_exact(&mut ct).await.is_err() {
                    break;
                }
                match rx.decrypt(&ct) {
                    Ok(pt) => {
                        if noise_tx.write_all(&pt).await.is_err() {
                            break;
                        }
                        let _ = noise_tx.flush().await;
                    }
                    Err(_) => break,
                }
            }
            let _ = noise_tx.shutdown().await;
        });

        // Write pump: noise_rx (h2 writes to plain_side) → encrypt → stream.
        let pump2 = tokio::spawn(async move {
            let mut tx = tx_cipher;
            let mut buf = vec![0u8; MAX_PLAINTEXT_SIZE];
            loop {
                match noise_rx.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let data = &buf[..n];
                        match tx.encrypt(data) {
                            Ok(ct) => {
                                let mut frame = Vec::with_capacity(HEADER_LEN + ct.len());
                                frame.push(MSG_TYPE_RECORD);
                                frame.extend_from_slice(&(ct.len() as u16).to_be_bytes());
                                frame.extend_from_slice(&ct);
                                if stream_tx.write_all(&frame).await.is_err() {
                                    break;
                                }
                                let _ = stream_tx.flush().await;
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            let _ = stream_tx.shutdown().await;
        });

        // Keep both pumps alive. We store one handle; the other is leaked
        // (it will be cleaned up when the streams close).
        drop(pump2);

        Self {
            inner: plain_side,
            _pump: pump,
        }
    }
}

impl tokio::io::AsyncRead for NoiseIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for NoiseIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
