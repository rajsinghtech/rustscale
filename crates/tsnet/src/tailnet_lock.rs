//! Scoped Tailnet Lock runtime: durable authority state, bounded control sync,
//! LocalAPI operations, and fail-closed peer authorization.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rand_core::RngCore as _;
use rustscale_controlclient::{ControlClient, TkaClient, TkaSession};
use rustscale_key::{MachinePrivate, MachinePublic, NLPrivate, NodePrivate, NodePublic};
use rustscale_tailcfg::{
    Node, TKABootstrapRequest, TKADisableRequest, TKAInfo, TKAInitBeginRequest,
    TKAInitFinishRequest, TKASubmitSignatureRequest, TKASyncOfferRequest, TKASyncSendRequest,
};
use rustscale_tka::{
    Aum, AumSigner, Authority, FsChonk, Key, MemChonk, NodeKeySignature, SigKind, State,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MAX_SYNC_AUMS: usize = 2000;
const MAX_INIT_NODES: usize = 4096;
const MAX_DISABLEMENT_SECRET: usize = 1024;
const LOCAL_DISABLE_DENYLIST_VERSION: u32 = 1;
const MAX_LOCAL_DISABLED_STATES: usize = 256;
const MAX_LOCAL_DISABLE_DENYLIST_BYTES: u64 = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum TailnetLockError {
    #[error("Tailnet Lock requires a durable state directory")]
    NoStateDirectory,
    #[error("Tailnet Lock state is unavailable")]
    StateUnavailable,
    #[error("Tailnet Lock is already enabled")]
    AlreadyEnabled,
    #[error("Tailnet Lock is not enabled")]
    NotEnabled,
    #[error("the local Tailnet Lock key is not trusted")]
    SigningKeyNotTrusted,
    #[error("invalid Tailnet Lock request: {0}")]
    InvalidRequest(String),
    #[error("Tailnet Lock control operation failed")]
    Control(#[source] rustscale_controlclient::TkaRpcError),
    #[error("Tailnet Lock authority operation failed")]
    Authority(#[source] rustscale_tka::AuthorityError),
    #[error("Tailnet Lock synchronization failed: {0}")]
    Sync(String),
    #[error("Tailnet Lock initialization outcome is ambiguous; disablement secrets remain in the durable receipt; check lock status or resume the same transaction")]
    InitAmbiguous,
    #[error("Tailnet Lock was locally disabled, but retired authority cleanup is incomplete; retry the same local-disable operation")]
    LocalDisableCommitted,
    #[error("Tailnet Lock persistence failed")]
    Persistence(#[source] std::io::Error),
}

impl From<rustscale_controlclient::TkaRpcError> for TailnetLockError {
    fn from(error: rustscale_controlclient::TkaRpcError) -> Self {
        Self::Control(error)
    }
}

impl From<rustscale_tka::AuthorityError> for TailnetLockError {
    fn from(error: rustscale_tka::AuthorityError) -> Self {
        Self::Authority(error)
    }
}

#[derive(Clone)]
pub(crate) struct TailnetLockParams {
    pub control_url: String,
    pub machine_key: MachinePrivate,
    pub server_pub_key: MachinePublic,
    pub node_key: NodePrivate,
    pub signing_key: NLPrivate,
    pub capability_version: i32,
    pub protocol_version: u16,
    pub state_dir: Option<PathBuf>,
    pub extra_root_certs: Option<Vec<Vec<u8>>>,
}

struct Inner {
    authority: Option<Authority>,
    storage: Option<Arc<FsChonk>>,
    /// Authority state IDs explicitly disabled for this profile/control
    /// namespace. The complete bounded set is atomically persisted before a
    /// local-disable operation can withdraw the active authority.
    disallowed_state_ids: BTreeSet<AuthorityStateId>,
    /// A verified disallowed authority selected by the latest authenticated
    /// control bootstrap. This is the explicit local-disable escape hatch:
    /// peer signatures are not enforced only while `ready` proves that the
    /// current advertised head still belongs to this state ID.
    locally_disabled_state: Option<AuthorityStateId>,
    locally_disabled_head: Option<rustscale_tka::AumHash>,
    local_disable_cleanup_pending: bool,
    /// Control has advertised enabled state. This is set before attempting
    /// bootstrap/sync so failed or partial state can never open the peer set.
    required: bool,
    /// The authority reached the control head during the latest operation, or
    /// an authenticated bootstrap proved that authority is locally disabled.
    ready: bool,
    filtered: Vec<FilteredPeer>,
    self_node: Option<Node>,
}

pub(crate) struct TailnetLock {
    current_node_key: Mutex<NodePrivate>,
    params: TailnetLockParams,
    path: Option<PathBuf>,
    operation: tokio::sync::Mutex<()>,
    init_flight: tokio::sync::Mutex<Option<InitFlightState>>,
    local_disable_flight: tokio::sync::Mutex<Option<LocalDisableFlightState>>,
    peer_authority: Mutex<Option<Arc<crate::map_update::PeerAuthorityRuntime>>>,
    inner: Mutex<Inner>,
}

/// A LocalAPI initialization waiter. Dropping this value only disconnects the
/// caller: the retained flight continues to own the TKA operation lock and
/// peer-publication barriers until initialization finishes fail-closed.
pub(crate) struct InitFlight {
    result: tokio::sync::watch::Receiver<Option<SharedInitResult>>,
}

type SharedInitResult = Arc<Result<Vec<Vec<u8>>, TailnetLockError>>;

struct InitFlightState {
    request_hash: [u8; 32],
    result: tokio::sync::watch::Receiver<Option<SharedInitResult>>,
    task: tokio::task::JoinHandle<()>,
}

/// A LocalAPI local-disable waiter. The retained task, rather than the socket
/// handler, owns the durable denylist commit and traffic-withdrawal barrier.
pub(crate) struct LocalDisableFlight {
    result: tokio::sync::watch::Receiver<Option<SharedLocalDisableResult>>,
}

type SharedLocalDisableResult = Arc<Result<(), TailnetLockError>>;

struct LocalDisableFlightState {
    result: tokio::sync::watch::Receiver<Option<SharedLocalDisableResult>>,
    task: tokio::task::JoinHandle<()>,
}

impl InitFlight {
    pub(crate) async fn wait(mut self) -> SharedInitResult {
        loop {
            if let Some(result) = self.result.borrow().clone() {
                return result;
            }
            if self.result.changed().await.is_err() {
                return Arc::new(Err(TailnetLockError::StateUnavailable));
            }
        }
    }
}

impl LocalDisableFlight {
    pub(crate) async fn wait(mut self) -> SharedLocalDisableResult {
        loop {
            if let Some(result) = self.result.borrow().clone() {
                return result;
            }
            if self.result.changed().await.is_err() {
                return Arc::new(Err(TailnetLockError::StateUnavailable));
            }
        }
    }
}

/// Holds the one ordered TKA operation across a control-state decision,
/// synchronization, and the peer-map commit derived from that decision.
pub(crate) struct Operation<'a> {
    lock: &'a TailnetLock,
    _guard: tokio::sync::MutexGuard<'a, ()>,
}

impl Operation<'_> {
    pub(crate) fn control_change_requires_revocation(
        &self,
        info: Option<&TKAInfo>,
        initial: bool,
    ) -> bool {
        self.lock
            .control_change_requires_revocation_inner(info, initial)
    }

    pub(crate) async fn apply_control_info(
        &self,
        info: Option<&TKAInfo>,
        initial: bool,
    ) -> Result<(), TailnetLockError> {
        self.lock.apply_control_info_inner(info, initial).await
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityStateId {
    id1: u64,
    id2: u64,
}

impl AuthorityStateId {
    fn from_authority(authority: &Authority) -> Self {
        let (id1, id2) = authority.state_ids();
        Self { id1, id2 }
    }

    fn display(self) -> String {
        format!("{}:{}", self.id1, self.id2)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalDisableDenylist {
    version: u32,
    state_ids: Vec<AuthorityStateId>,
}

impl Default for LocalDisableDenylist {
    fn default() -> Self {
        Self {
            version: LOCAL_DISABLE_DENYLIST_VERSION,
            state_ids: Vec::new(),
        }
    }
}

enum PersistGenesisOutcome {
    Installed(Box<Authority>, Arc<FsChonk>),
    LocallyDisabled(AuthorityStateId),
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct FilteredPeer {
    name: String,
    id: i64,
    stable_id: String,
    node_key: NodePublic,
    tailscale_ips: Vec<String>,
    reason: &'static str,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct InitRequest {
    #[serde(default)]
    pub keys: Vec<Key>,
    #[serde(default)]
    pub disablement_values: Vec<Vec<u8>>,
    /// Raw one-time secrets corresponding exactly to `disablement_values`.
    /// They are persisted privately before the first irreversible RPC.
    #[serde(default)]
    pub disablement_secrets: Vec<Vec<u8>>,
    #[serde(default)]
    pub support_disablement: Vec<u8>,
    #[serde(default)]
    pub resume: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InitReceiptPhase {
    Prepared,
    BeginAccepted,
    Ambiguous,
    ControlCommitted,
    LocalCommitted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InitReceipt {
    version: u32,
    transaction_id: String,
    created_unix: u64,
    phase: InitReceiptPhase,
    keys: Vec<Key>,
    disablement_values: Vec<Vec<u8>>,
    disablement_secrets: Vec<Vec<u8>>,
    support_disablement: Vec<u8>,
    genesis_aum: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SignRequest {
    pub node_key: NodePublic,
    #[serde(default)]
    pub rotation_public: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct InitReceiptAck {
    pub transaction_id: String,
}

struct NlSigner<'a>(&'a NLPrivate);

impl AumSigner for NlSigner<'_> {
    fn sign_aum(&self, hash: &[u8; 32]) -> Result<Vec<rustscale_tka::Signature>, String> {
        Ok(vec![rustscale_tka::Signature {
            key_id: self.0.public().raw32().to_vec(),
            signature: self.0.sign(hash).map_err(|error| error.to_string())?,
        }])
    }
}

fn local_disable_denylist_path(state_dir: &Path) -> PathBuf {
    state_dir.join("tailnet-lock-local-disable.json")
}

fn path_entry_exists(path: &Path) -> Result<bool, std::io::Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn validate_local_disable_denylist(
    denylist: LocalDisableDenylist,
) -> Result<BTreeSet<AuthorityStateId>, TailnetLockError> {
    if denylist.version != LOCAL_DISABLE_DENYLIST_VERSION {
        return Err(TailnetLockError::InvalidRequest(
            "durable local-disable denylist version is unsupported".into(),
        ));
    }
    if denylist.state_ids.len() > MAX_LOCAL_DISABLED_STATES {
        return Err(TailnetLockError::InvalidRequest(
            "durable local-disable denylist exceeds its state bound".into(),
        ));
    }
    let state_count = denylist.state_ids.len();
    let states = denylist.state_ids.into_iter().collect::<BTreeSet<_>>();
    if states.len() != state_count {
        return Err(TailnetLockError::InvalidRequest(
            "durable local-disable denylist contains duplicate state IDs".into(),
        ));
    }
    Ok(states)
}

fn load_local_disable_denylist(
    state_dir: Option<&Path>,
) -> Result<BTreeSet<AuthorityStateId>, TailnetLockError> {
    let Some(state_dir) = state_dir else {
        return Ok(BTreeSet::new());
    };
    let path = local_disable_denylist_path(state_dir);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BTreeSet::new());
        }
        Err(error) => return Err(TailnetLockError::Persistence(error)),
    };
    if metadata.len() > MAX_LOCAL_DISABLE_DENYLIST_BYTES {
        return Err(TailnetLockError::InvalidRequest(
            "durable local-disable denylist exceeds its byte bound".into(),
        ));
    }
    let bytes = rustscale_atomicfile::read_private(&path).map_err(TailnetLockError::Persistence)?;
    if bytes.len() as u64 > MAX_LOCAL_DISABLE_DENYLIST_BYTES {
        return Err(TailnetLockError::InvalidRequest(
            "durable local-disable denylist exceeds its byte bound".into(),
        ));
    }
    let denylist = serde_json::from_slice::<LocalDisableDenylist>(&bytes).map_err(|_| {
        TailnetLockError::InvalidRequest("durable local-disable denylist is malformed".into())
    })?;
    validate_local_disable_denylist(denylist)
}

fn save_local_disable_denylist(
    state_dir: Option<&Path>,
    states: &BTreeSet<AuthorityStateId>,
) -> Result<(), TailnetLockError> {
    let state_dir = state_dir.ok_or(TailnetLockError::NoStateDirectory)?;
    if states.len() > MAX_LOCAL_DISABLED_STATES {
        return Err(TailnetLockError::InvalidRequest(
            "local-disable denylist is full".into(),
        ));
    }
    let bytes = serde_json::to_vec_pretty(&LocalDisableDenylist {
        version: LOCAL_DISABLE_DENYLIST_VERSION,
        state_ids: states.iter().copied().collect(),
    })
    .map_err(|error| TailnetLockError::Persistence(std::io::Error::other(error)))?;
    if bytes.len() as u64 > MAX_LOCAL_DISABLE_DENYLIST_BYTES {
        return Err(TailnetLockError::InvalidRequest(
            "local-disable denylist exceeds its byte bound".into(),
        ));
    }
    rustscale_atomicfile::write_private(&local_disable_denylist_path(state_dir), &bytes)
        .map_err(TailnetLockError::Persistence)
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

fn cleanup_authority_tombstone(path: &Path) -> Result<(), std::io::Error> {
    let tombstone = path.with_extension("deleting");
    if !path_entry_exists(&tombstone)? {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(&tombstone)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Tailnet Lock deletion tombstone is not a real directory",
        ));
    }
    std::fs::remove_dir_all(&tombstone)?;
    sync_parent(&tombstone)
}

/// Retire one authority directory with a crash-recoverable rename. A
/// previously renamed tombstone is removed first. Unexpected file types are
/// never followed or deleted.
fn retire_authority_path(path: &Path) -> Result<(), std::io::Error> {
    cleanup_authority_tombstone(path)?;
    let tombstone = path.with_extension("deleting");
    if !path_entry_exists(path)? {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Tailnet Lock authority path is not a real directory",
        ));
    }
    std::fs::rename(path, &tombstone)?;
    sync_parent(path)?;
    std::fs::remove_dir_all(&tombstone)?;
    sync_parent(&tombstone)
}

impl TailnetLock {
    pub(crate) fn open(params: TailnetLockParams) -> Result<Arc<Self>, TailnetLockError> {
        let disallowed_state_ids = load_local_disable_denylist(params.state_dir.as_deref())?;
        let path = params.state_dir.as_ref().map(|dir| {
            dir.join("tailnet-lock")
                .join(hex::encode(params.signing_key.public().raw32()))
        });
        let mut local_disable_cleanup_pending = false;
        if let Some(path) = path.as_ref() {
            if let Err(error) = cleanup_authority_tombstone(path) {
                local_disable_cleanup_pending = true;
                log::warn!(
                    "tsnet: retained Tailnet Lock local-disable cleanup requires retry: {error}"
                );
            }
        }

        let authority_path_exists = match path.as_ref() {
            Some(path) => path_entry_exists(path).map_err(TailnetLockError::Persistence)?,
            None => false,
        };
        if authority_path_exists {
            rustscale_atomicfile::ensure_private_dir(path.as_ref().expect("authority path exists"))
                .map_err(TailnetLockError::Persistence)?;
        }
        let (mut authority, mut storage) = if authority_path_exists {
            let path = path.as_ref().expect("authority path exists");
            let storage = Arc::new(
                FsChonk::open(path)
                    .map_err(rustscale_tka::AuthorityError::from)
                    .map_err(TailnetLockError::Authority)?,
            );
            let authority = Authority::open(storage.as_ref())?;
            (Some(authority), Some(storage))
        } else {
            (None, None)
        };
        let mut locally_disabled_state = None;
        if let Some(state_id) = authority
            .as_ref()
            .map(AuthorityStateId::from_authority)
            .filter(|state_id| disallowed_state_ids.contains(state_id))
        {
            // The denylist commit is authoritative even if a crash left the
            // old Chonk directory in place. Never reinstall that authority.
            authority = None;
            storage = None;
            locally_disabled_state = Some(state_id);
            if let Some(path) = path.as_ref() {
                if let Err(error) = retire_authority_path(path) {
                    local_disable_cleanup_pending = true;
                    log::warn!("tsnet: locally disabled authority cleanup requires retry: {error}");
                }
            }
        }
        let enabled = authority.is_some();
        let state_unknown = !disallowed_state_ids.is_empty() || locally_disabled_state.is_some();
        let current_node_key = Mutex::new(params.node_key.clone());
        Ok(Arc::new(Self {
            current_node_key,
            params,
            path,
            operation: tokio::sync::Mutex::new(()),
            init_flight: tokio::sync::Mutex::new(None),
            local_disable_flight: tokio::sync::Mutex::new(None),
            peer_authority: Mutex::new(None),
            inner: Mutex::new(Inner {
                authority,
                storage,
                disallowed_state_ids,
                locally_disabled_state,
                locally_disabled_head: None,
                local_disable_cleanup_pending,
                required: enabled || state_unknown,
                ready: enabled,
                filtered: Vec::new(),
                self_node: None,
            }),
        }))
    }

    /// Mark cached control state as insufficient to prove whether locking is
    /// currently enabled. Peers stay withdrawn until a fresh stream response.
    pub(crate) fn require_fresh_control_state(&self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.required = true;
        inner.ready = false;
    }

    pub(crate) fn set_node_key(&self, key: NodePrivate) {
        *self
            .current_node_key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = key;
    }

    fn node_public(&self) -> NodePublic {
        self.current_node_key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .public()
    }

    pub(crate) fn head(&self) -> String {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .authority
            .as_ref()
            .map_or_else(String::new, |authority| authority.head().to_string())
    }

    fn control(&self) -> ControlClient {
        let mut control = ControlClient::new(
            &self.params.control_url,
            self.params.machine_key.clone(),
            self.params.server_pub_key.clone(),
            self.params.protocol_version,
        );
        if let Some(certificates) = self.params.extra_root_certs.clone() {
            control.set_extra_root_certs(certificates);
        }
        control
    }

    pub(crate) fn attach_peer_authority(
        &self,
        runtime: Arc<crate::map_update::PeerAuthorityRuntime>,
    ) -> Result<(), TailnetLockError> {
        let mut attached = self
            .peer_authority
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if attached.is_some() {
            return Err(TailnetLockError::StateUnavailable);
        }
        *attached = Some(runtime);
        Ok(())
    }

    pub(crate) fn peer_authority(
        &self,
    ) -> Result<Arc<crate::map_update::PeerAuthorityRuntime>, TailnetLockError> {
        self.peer_authority
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or(TailnetLockError::StateUnavailable)
    }

    pub(crate) async fn operation(&self) -> Operation<'_> {
        Operation {
            lock: self,
            _guard: self.operation.lock().await,
        }
    }

    /// Whether applying this control state can change peer authorization.
    /// This is called only while holding [`Operation`] through the subsequent
    /// apply and peer commit. Repeated ready advertisements at the same head
    /// deliberately return false.
    fn control_change_requires_revocation_inner(
        &self,
        info: Option<&TKAInfo>,
        initial: bool,
    ) -> bool {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match info {
            Some(info) if !info.Disabled => {
                if !inner.required || !inner.ready {
                    return true;
                }
                let Ok(wanted) = info.Head.parse::<rustscale_tka::AumHash>() else {
                    return true;
                };
                if inner.locally_disabled_state.is_some() {
                    inner.locally_disabled_head != Some(wanted)
                } else {
                    inner.authority.as_ref().map(Authority::head) != Some(wanted)
                }
            }
            Some(_) => {
                inner.required
                    || inner.authority.is_some()
                    || inner.locally_disabled_state.is_some()
            }
            None if initial => {
                inner.required
                    || inner.authority.is_some()
                    || inner.locally_disabled_state.is_some()
            }
            None => false,
        }
    }

    pub(crate) fn authorization_ready(&self) -> bool {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.locally_disabled_state.is_some() {
            return inner.ready;
        }
        if inner.required || inner.authority.is_some() {
            inner.ready && inner.authority.is_some()
        } else {
            inner.ready
        }
    }

    /// Apply an initial or delta TKAInfo. The caller must filter peers after
    /// this returns regardless of success.
    pub(crate) async fn apply_control_info(
        &self,
        info: Option<&TKAInfo>,
        initial: bool,
    ) -> Result<(), TailnetLockError> {
        let operation = self.operation().await;
        operation.apply_control_info(info, initial).await
    }

    async fn apply_control_info_inner(
        &self,
        info: Option<&TKAInfo>,
        initial: bool,
    ) -> Result<(), TailnetLockError> {
        let desired_enabled = match info {
            Some(info) => !info.Disabled,
            None if initial => false,
            None => return Ok(()),
        };

        {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if desired_enabled {
                inner.required = true;
                inner.ready = false;
            }
        }

        if desired_enabled {
            let advertised_head = info
                .and_then(|info| (!info.Head.is_empty()).then_some(info.Head.as_str()))
                .ok_or_else(|| {
                    TailnetLockError::Sync("control omitted the authority head".into())
                })?;
            let wanted = advertised_head
                .parse::<rustscale_tka::AumHash>()
                .map_err(|_| {
                    TailnetLockError::Sync("control sent an invalid authority head".into())
                })?;
            // A repeated full map at the same head needs no network round
            // trip and, importantly, must not transiently withdraw peers.
            {
                let mut inner = self
                    .inner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let authority_matches =
                    inner.authority.as_ref().map(Authority::head) == Some(wanted);
                let local_disable_matches = inner.locally_disabled_state.is_some()
                    && inner.locally_disabled_head == Some(wanted);
                if authority_matches || local_disable_matches {
                    inner.ready = true;
                    return Ok(());
                }
            }

            let control = self.control();
            let session = TkaClient::new(&control).connect().await?;
            if self.authority_snapshot().is_none() {
                if let Some(state_id) = self.bootstrap_from_control(&session).await? {
                    let mut inner = self
                        .inner
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    inner.required = true;
                    inner.ready = true;
                    inner.locally_disabled_state = Some(state_id);
                    inner.locally_disabled_head = Some(wanted);
                    return Ok(());
                }
            }
            self.sync_with_control(&session).await?;
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let local_head = inner.authority.as_ref().map(Authority::head);
            if local_head != Some(wanted) {
                return Err(TailnetLockError::Sync(
                    "local and advertised authority heads differ".into(),
                ));
            }
            inner.ready = true;
            inner.locally_disabled_state = None;
            inner.locally_disabled_head = None;
            return Ok(());
        }

        if self.authority_snapshot().is_some() {
            {
                let mut inner = self
                    .inner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                inner.required = true;
                inner.ready = false;
            }
            self.disable_from_control().await?;
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.required = false;
        inner.ready = true;
        inner.locally_disabled_state = None;
        inner.locally_disabled_head = None;
        inner.filtered.clear();
        Ok(())
    }

    fn authority_snapshot(&self) -> Option<(Authority, Arc<FsChonk>)> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Some((inner.authority.clone()?, inner.storage.clone()?))
    }

    /// Return `Some(state_id)` when the authenticated, fully verified genesis
    /// belongs to an explicitly denylisted authority. That is the only path
    /// which activates local-disable mode for an enabled control map.
    async fn bootstrap_from_control(
        &self,
        session: &TkaSession,
    ) -> Result<Option<AuthorityStateId>, TailnetLockError> {
        let request = TKABootstrapRequest {
            Version: self.params.capability_version,
            NodeKey: self.node_public(),
            Head: String::new(),
        };
        let response = session.bootstrap(&request).await?;
        if response.GenesisAUM.is_empty() {
            return Err(TailnetLockError::Sync(
                "control returned no genesis authority update".into(),
            ));
        }
        let genesis = Aum::decode(&response.GenesisAUM).map_err(|_| {
            TailnetLockError::Sync("control returned malformed genesis state".into())
        })?;
        match self.persist_genesis(&genesis)? {
            PersistGenesisOutcome::Installed(authority, storage) => {
                let mut inner = self
                    .inner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                inner.authority = Some(*authority);
                inner.storage = Some(storage);
                inner.locally_disabled_state = None;
                inner.locally_disabled_head = None;
                Ok(None)
            }
            PersistGenesisOutcome::LocallyDisabled(state_id) => Ok(Some(state_id)),
        }
    }

    fn receipt_path(&self) -> Result<PathBuf, TailnetLockError> {
        self.params
            .state_dir
            .as_ref()
            .map(|dir| dir.join("tailnet-lock-init-receipt.json"))
            .ok_or(TailnetLockError::NoStateDirectory)
    }

    fn load_init_receipt(&self) -> Result<Option<InitReceipt>, TailnetLockError> {
        let path = self.receipt_path()?;
        if !path.exists() {
            return Ok(None);
        }
        let bytes =
            rustscale_atomicfile::read_private(&path).map_err(TailnetLockError::Persistence)?;
        let receipt = serde_json::from_slice::<InitReceipt>(&bytes).map_err(|_| {
            TailnetLockError::InvalidRequest("durable initialization receipt is corrupt".into())
        })?;
        if receipt.version != 1 {
            return Err(TailnetLockError::InvalidRequest(
                "durable initialization receipt version is unsupported".into(),
            ));
        }
        Ok(Some(receipt))
    }

    fn save_init_receipt(&self, receipt: &InitReceipt) -> Result<(), TailnetLockError> {
        let bytes = serde_json::to_vec_pretty(receipt)
            .map_err(|error| TailnetLockError::Persistence(std::io::Error::other(error)))?;
        rustscale_atomicfile::write_private(&self.receipt_path()?, &bytes)
            .map_err(TailnetLockError::Persistence)
    }

    fn persist_genesis(&self, genesis: &Aum) -> Result<PersistGenesisOutcome, TailnetLockError> {
        let path = self
            .path
            .as_ref()
            .ok_or(TailnetLockError::NoStateDirectory)?;
        let parent = path.parent().ok_or(TailnetLockError::NoStateDirectory)?;
        rustscale_atomicfile::ensure_private_dir(parent).map_err(TailnetLockError::Persistence)?;
        cleanup_authority_tombstone(path).map_err(TailnetLockError::Persistence)?;

        let pending = path.with_extension("pending");
        if path_entry_exists(&pending).map_err(TailnetLockError::Persistence)? {
            let metadata =
                std::fs::symlink_metadata(&pending).map_err(TailnetLockError::Persistence)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(TailnetLockError::Persistence(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Tailnet Lock pending path is not a real directory",
                )));
            }
            std::fs::remove_dir_all(&pending).map_err(TailnetLockError::Persistence)?;
            sync_parent(&pending).map_err(TailnetLockError::Persistence)?;
        }
        rustscale_atomicfile::ensure_private_dir(&pending)
            .map_err(TailnetLockError::Persistence)?;
        let pending_storage = FsChonk::open(&pending)
            .map_err(rustscale_tka::AuthorityError::from)
            .map_err(TailnetLockError::Authority)?;
        let pending_authority = Authority::bootstrap(&pending_storage, genesis.clone())?;
        let state_id = AuthorityStateId::from_authority(&pending_authority);
        let disallowed = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .disallowed_state_ids
            .contains(&state_id);
        drop(pending_authority);
        drop(pending_storage);
        if disallowed {
            std::fs::remove_dir_all(&pending).map_err(TailnetLockError::Persistence)?;
            sync_parent(&pending).map_err(TailnetLockError::Persistence)?;
            return Ok(PersistGenesisOutcome::LocallyDisabled(state_id));
        }

        if path_entry_exists(path).map_err(TailnetLockError::Persistence)? {
            let existing_storage = FsChonk::open(path)
                .map_err(rustscale_tka::AuthorityError::from)
                .map_err(TailnetLockError::Authority)?;
            let existing = Authority::open(&existing_storage)?;
            let existing_state = AuthorityStateId::from_authority(&existing);
            let existing_is_disallowed = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .disallowed_state_ids
                .contains(&existing_state);
            drop(existing);
            drop(existing_storage);
            if existing_is_disallowed {
                retire_authority_path(path).map_err(TailnetLockError::Persistence)?;
            } else {
                let _ = std::fs::remove_dir_all(&pending);
                return Err(TailnetLockError::AlreadyEnabled);
            }
        }

        std::fs::rename(&pending, path).map_err(TailnetLockError::Persistence)?;
        sync_parent(path).map_err(TailnetLockError::Persistence)?;
        let storage = Arc::new(
            FsChonk::open(path)
                .map_err(rustscale_tka::AuthorityError::from)
                .map_err(TailnetLockError::Authority)?,
        );
        let authority = Authority::open(storage.as_ref())?;
        Ok(PersistGenesisOutcome::Installed(
            Box::new(authority),
            storage,
        ))
    }

    async fn sync_with_control(&self, session: &TkaSession) -> Result<(), TailnetLockError> {
        let (authority, storage) = self
            .authority_snapshot()
            .ok_or(TailnetLockError::StateUnavailable)?;
        let offer = authority
            .sync_offer(storage.as_ref())
            .map_err(|error| TailnetLockError::Sync(error.to_string()))?;
        let (head, ancestors) = offer.to_strings();
        let request = TKASyncOfferRequest {
            Version: self.params.capability_version,
            NodeKey: self.node_public(),
            Head: head,
            Ancestors: ancestors,
        };
        let response = session.sync_offer(&request).await?;
        let remote = rustscale_tka::SyncOffer::from_strings(&response.Head, &response.Ancestors)
            .map_err(TailnetLockError::Sync)?;
        if remote.head == offer.head {
            return Ok(());
        }
        let to_send = authority
            .missing_aums(storage.as_ref(), &remote)
            .map_err(|error| TailnetLockError::Sync(error.to_string()))?;
        if response.MissingAUMs.len() > MAX_SYNC_AUMS || to_send.len() > MAX_SYNC_AUMS {
            return Err(TailnetLockError::Sync(
                "authority update exchange exceeded its bound".into(),
            ));
        }

        let mut updated = authority;
        if !response.MissingAUMs.is_empty() {
            let updates = response
                .MissingAUMs
                .iter()
                .map(|encoded| {
                    Aum::decode(encoded).map_err(|_| {
                        TailnetLockError::Sync(
                            "control returned a malformed authority update".into(),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            updated.inform(storage.as_ref(), &updates)?;
        }
        let send = TKASyncSendRequest {
            Version: self.params.capability_version,
            NodeKey: self.node_public(),
            Head: updated.head().to_string(),
            MissingAUMs: to_send.iter().map(Aum::encode).collect(),
            Interactive: false,
        };
        let response = session.sync_send(&send).await?;
        let remote_head = response
            .Head
            .parse::<rustscale_tka::AumHash>()
            .map_err(|_| TailnetLockError::Sync("control returned an invalid final head".into()))?;
        if remote_head != updated.head() {
            return Err(TailnetLockError::Sync(
                "control did not converge on the verified local head".into(),
            ));
        }
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .authority = Some(updated);
        Ok(())
    }

    async fn disable_from_control(&self) -> Result<(), TailnetLockError> {
        let (authority, _) = self
            .authority_snapshot()
            .ok_or(TailnetLockError::NotEnabled)?;
        let request = TKABootstrapRequest {
            Version: self.params.capability_version,
            NodeKey: self.node_public(),
            Head: authority.head().to_string(),
        };
        let control = self.control();
        let response = TkaClient::new(&control).bootstrap(&request).await?;
        if response.DisablementSecret.len() > MAX_DISABLEMENT_SECRET
            || !authority.valid_disablement(&response.DisablementSecret)
        {
            return Err(TailnetLockError::Sync(
                "control returned an invalid disablement proof".into(),
            ));
        }
        self.remove_durable_state()?;
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.authority = None;
        inner.storage = None;
        inner.locally_disabled_state = None;
        inner.locally_disabled_head = None;
        inner.local_disable_cleanup_pending = false;
        Ok(())
    }

    fn remove_durable_state(&self) -> Result<(), TailnetLockError> {
        let path = self
            .path
            .as_ref()
            .ok_or(TailnetLockError::NoStateDirectory)?;
        retire_authority_path(path).map_err(TailnetLockError::Persistence)?;
        if let Some(parent) = path.parent() {
            let empty = std::fs::read_dir(parent)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false);
            if empty && std::fs::remove_dir(parent).is_ok() {
                let _ = sync_parent(parent);
            }
        }
        Ok(())
    }

    /// Admit one lifecycle-retained LocalAPI initialization flight. The
    /// request body is fingerprinted so concurrent retries can join only the
    /// exact same transaction; a disconnected waiter never owns cancellation
    /// of authority withdrawal or local commit.
    pub(crate) async fn start_init(
        self: &Arc<Self>,
        request: InitRequest,
    ) -> Result<InitFlight, TailnetLockError> {
        let encoded = serde_json::to_vec(&request).map_err(|error| {
            TailnetLockError::InvalidRequest(format!(
                "initialization request could not be encoded: {error}"
            ))
        })?;
        let request_hash: [u8; 32] = Sha256::digest(encoded).into();
        let mut retained = self.init_flight.lock().await;
        if let Some(flight) = retained.as_mut() {
            if !flight.task.is_finished() {
                if flight.request_hash != request_hash {
                    return Err(TailnetLockError::InvalidRequest(
                        "another Tailnet Lock initialization request is already running".into(),
                    ));
                }
                return Ok(InitFlight {
                    result: flight.result.clone(),
                });
            }

            // A finished Tokio task still owns resources until its completion
            // has been observed. Join it in place before admitting another
            // generation; cancellation leaves the same handle retained here.
            let _ = (&mut flight.task).await;
            *retained = None;
        }

        let (result_tx, result) = tokio::sync::watch::channel(None);
        let lock = self.clone();
        let task = tokio::spawn(async move {
            let result = Arc::new(lock.init(request).await);
            result_tx.send_replace(Some(result));
        });
        *retained = Some(InitFlightState {
            request_hash,
            result: result.clone(),
            task,
        });
        Ok(InitFlight { result })
    }

    /// Join a retained initialization during close/logout before tearing down
    /// the peer-authority runtime it still owns. The handle is cleared only
    /// after completion is observed; cancelling shutdown leaves that same task
    /// available for the next close/logout retry.
    pub(crate) async fn join_init_flight(&self) {
        let mut retained = self.init_flight.lock().await;
        if let Some(flight) = retained.as_mut() {
            let _ = (&mut flight.task).await;
            *retained = None;
        }
    }

    #[cfg(test)]
    pub(crate) async fn init_flight_retained(&self) -> bool {
        self.init_flight.lock().await.is_some()
    }

    /// Admit or join the one lifecycle-retained local-disable transaction.
    /// Once the denylist write commits, socket EOF, handler cancellation, and
    /// shutdown retries cannot abandon traffic withdrawal or local teardown.
    pub(crate) async fn start_force_local_disable(
        self: &Arc<Self>,
    ) -> Result<LocalDisableFlight, TailnetLockError> {
        let mut retained = self.local_disable_flight.lock().await;
        if let Some(flight) = retained.as_mut() {
            if !flight.task.is_finished() {
                return Ok(LocalDisableFlight {
                    result: flight.result.clone(),
                });
            }
            let _ = (&mut flight.task).await;
            *retained = None;
        }

        let (result_tx, result) = tokio::sync::watch::channel(None);
        let lock = self.clone();
        let task = tokio::spawn(async move {
            let result = Arc::new(lock.force_local_disable().await);
            result_tx.send_replace(Some(result));
        });
        *retained = Some(LocalDisableFlightState {
            result: result.clone(),
            task,
        });
        Ok(LocalDisableFlight { result })
    }

    /// Observe completion before the peer-authority runtime can be torn down.
    /// Cancellation leaves the same handle retained for a shutdown retry.
    pub(crate) async fn join_local_disable_flight(&self) {
        let mut retained = self.local_disable_flight.lock().await;
        if let Some(flight) = retained.as_mut() {
            let _ = (&mut flight.task).await;
            *retained = None;
        }
    }

    #[cfg(all(test, unix))]
    pub(crate) async fn local_disable_flight_retained(&self) -> bool {
        self.local_disable_flight.lock().await.is_some()
    }

    /// Persist the complete disablement receipt before contacting control,
    /// then perform both irreversible phases on one authenticated session.
    /// The receipt intentionally survives success until an operator retrieves
    /// it, so a dropped LocalAPI/control response cannot destroy the secrets.
    async fn init(&self, request: InitRequest) -> Result<Vec<Vec<u8>>, TailnetLockError> {
        let _operation = self.operation().await;
        if self.path.is_none() {
            return Err(TailnetLockError::NoStateDirectory);
        }

        let mut receipt = if request.resume {
            self.load_init_receipt()?.ok_or_else(|| {
                TailnetLockError::InvalidRequest(
                    "there is no durable initialization transaction to resume".into(),
                )
            })?
        } else {
            if self.authority_snapshot().is_some() {
                return Err(TailnetLockError::AlreadyEnabled);
            }
            if self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .required
            {
                return Err(TailnetLockError::InvalidRequest(
                    "Tailnet Lock control state is enabled or unconfirmed; local-disable must not be replaced by initialization"
                        .into(),
                ));
            }
            if self.load_init_receipt()?.is_some() {
                return Err(TailnetLockError::InvalidRequest(
                    "an initialization receipt already exists; resume it instead of generating replacement secrets".into(),
                ));
            }
            if !request.support_disablement.is_empty() && request.support_disablement.len() != 32 {
                return Err(TailnetLockError::InvalidRequest(
                    "support disablement secret must be empty or 32 bytes".into(),
                ));
            }
            if request.disablement_secrets.len() != request.disablement_values.len()
                || request.disablement_secrets.is_empty()
                || request
                    .disablement_secrets
                    .iter()
                    .zip(&request.disablement_values)
                    .any(|(secret, value)| rustscale_tka::disablement_kdf(secret) != *value)
            {
                return Err(TailnetLockError::InvalidRequest(
                    "disablement secrets must correspond exactly to their verification values"
                        .into(),
                ));
            }
            let local_id = self.params.signing_key.public().raw32();
            if !request
                .keys
                .iter()
                .any(|key| key.id().is_ok_and(|id| id == local_id))
            {
                return Err(TailnetLockError::InvalidRequest(
                    "the current node's signing key must be trusted".into(),
                ));
            }
            let mut entropy = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut entropy);
            let state = State {
                last_aum_hash: None,
                disablement_values: request.disablement_values.clone(),
                keys: request.keys.clone(),
                state_id1: u64::from_le_bytes(entropy[..8].try_into().unwrap()),
                state_id2: u64::from_le_bytes(entropy[8..].try_into().unwrap()),
            };
            state
                .validate_checkpoint()
                .map_err(TailnetLockError::InvalidRequest)?;
            let memory = MemChonk::new();
            let signer = NlSigner(&self.params.signing_key);
            let (_, genesis) = Authority::create(&memory, state, &signer)?;
            let mut transaction_id = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut transaction_id);
            let receipt = InitReceipt {
                version: 1,
                transaction_id: hex::encode(transaction_id),
                created_unix: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_secs()),
                phase: InitReceiptPhase::Prepared,
                keys: request.keys,
                disablement_values: request.disablement_values,
                disablement_secrets: request.disablement_secrets,
                support_disablement: request.support_disablement,
                genesis_aum: genesis.encode(),
            };
            // This durable write is the precondition for the first RPC.
            self.save_init_receipt(&receipt)?;
            receipt
        };

        // From this point initialization is locally valid and may commit at
        // control. Close enforcement before the first RPC, drain every peer
        // publication generation, and keep map commits behind the operation
        // lock until the outcome is known. Only a later fresh map carrying a
        // successfully validated enabled head may set ready again.
        {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.required = true;
            inner.ready = false;
        }
        self.peer_authority()?.withdraw().await;

        if self.authority_snapshot().is_some() {
            receipt.phase = InitReceiptPhase::LocalCommitted;
            self.save_init_receipt(&receipt)?;
            return Ok(receipt.disablement_secrets);
        }
        let genesis = Aum::decode(&receipt.genesis_aum).map_err(|_| {
            TailnetLockError::InvalidRequest("receipt contains malformed genesis state".into())
        })?;
        let control = self.control();
        let session = TkaClient::new(&control).connect().await?;

        // A prior finish response may have been dropped after control commit.
        // Confirm the exact genesis instead of issuing replacement init RPCs.
        if request.resume {
            if let Ok(bootstrap) = session
                .bootstrap(&TKABootstrapRequest {
                    Version: self.params.capability_version,
                    NodeKey: self.node_public(),
                    Head: String::new(),
                })
                .await
            {
                if bootstrap.GenesisAUM == receipt.genesis_aum {
                    let (authority, storage) = match self.persist_genesis(&genesis)? {
                        PersistGenesisOutcome::Installed(authority, storage) => {
                            (*authority, storage)
                        }
                        PersistGenesisOutcome::LocallyDisabled(_) => {
                            return Err(TailnetLockError::InvalidRequest(
                                "initialization authority state is locally denylisted".into(),
                            ));
                        }
                    };
                    let mut inner = self
                        .inner
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    inner.authority = Some(authority);
                    inner.storage = Some(storage);
                    inner.locally_disabled_state = None;
                    inner.locally_disabled_head = None;
                    inner.required = true;
                    inner.ready = false;
                    drop(inner);
                    receipt.phase = InitReceiptPhase::LocalCommitted;
                    self.save_init_receipt(&receipt)?;
                    return Ok(receipt.disablement_secrets);
                }
            }
        }

        let begin = session
            .init_begin(&TKAInitBeginRequest {
                Version: self.params.capability_version,
                NodeKey: self.node_public(),
                GenesisAUM: receipt.genesis_aum.clone(),
            })
            .await?;
        receipt.phase = InitReceiptPhase::BeginAccepted;
        self.save_init_receipt(&receipt)?;
        if begin.NeedSignatures.len() > MAX_INIT_NODES {
            return Err(TailnetLockError::InvalidRequest(
                "control requested too many initial node signatures".into(),
            ));
        }
        let mut signatures = BTreeMap::new();
        for node in begin.NeedSignatures {
            if !node.RotationPubkey.is_empty() && node.RotationPubkey.len() != 32 {
                return Err(TailnetLockError::InvalidRequest(
                    "control supplied an invalid rotation key".into(),
                ));
            }
            signatures.insert(
                node.NodeID,
                self.make_node_signature(&node.NodePublic, &node.RotationPubkey)?,
            );
        }
        if session
            .init_finish(&TKAInitFinishRequest {
                Version: self.params.capability_version,
                NodeKey: self.node_public(),
                Signatures: signatures,
                SupportDisablement: receipt.support_disablement.clone(),
            })
            .await
            .is_err()
        {
            receipt.phase = InitReceiptPhase::Ambiguous;
            self.save_init_receipt(&receipt)?;
            return Err(TailnetLockError::InitAmbiguous);
        }
        receipt.phase = InitReceiptPhase::ControlCommitted;
        self.save_init_receipt(&receipt)?;

        let (authority, storage) = match self.persist_genesis(&genesis)? {
            PersistGenesisOutcome::Installed(authority, storage) => (*authority, storage),
            PersistGenesisOutcome::LocallyDisabled(_) => {
                return Err(TailnetLockError::InvalidRequest(
                    "initialization authority state is locally denylisted".into(),
                ));
            }
        };
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.authority = Some(authority);
        inner.storage = Some(storage);
        inner.locally_disabled_state = None;
        inner.locally_disabled_head = None;
        inner.required = true;
        inner.ready = false;
        drop(inner);
        receipt.phase = InitReceiptPhase::LocalCommitted;
        self.save_init_receipt(&receipt)?;
        Ok(receipt.disablement_secrets)
    }

    pub(crate) async fn acknowledge_init_receipt(
        &self,
        request: InitReceiptAck,
    ) -> Result<(), TailnetLockError> {
        let _operation = self.operation.lock().await;
        let receipt = self.load_init_receipt()?.ok_or_else(|| {
            TailnetLockError::InvalidRequest("initialization receipt does not exist".into())
        })?;
        if receipt.transaction_id != request.transaction_id
            || !matches!(receipt.phase, InitReceiptPhase::LocalCommitted)
        {
            return Err(TailnetLockError::InvalidRequest(
                "initialization receipt is not committed or does not match".into(),
            ));
        }
        rustscale_atomicfile::remove_private(&self.receipt_path()?)
            .map_err(TailnetLockError::Persistence)
    }

    pub(crate) async fn sign(&self, request: SignRequest) -> Result<(), TailnetLockError> {
        let _operation = self.operation.lock().await;
        if !request.rotation_public.is_empty() && request.rotation_public.len() != 32 {
            return Err(TailnetLockError::InvalidRequest(
                "rotation public key must be empty or 32 bytes".into(),
            ));
        }
        let (authority, _) = self
            .authority_snapshot()
            .ok_or(TailnetLockError::NotEnabled)?;
        let key_id = self.params.signing_key.public().raw32();
        if !authority.key_trusted(&key_id) {
            return Err(TailnetLockError::SigningKeyNotTrusted);
        }
        let signature = self.make_node_signature(&request.node_key, &request.rotation_public)?;
        let control = self.control();
        TkaClient::new(&control)
            .submit_signature(&TKASubmitSignatureRequest {
                Version: self.params.capability_version,
                NodeKey: self.node_public(),
                Signature: signature,
            })
            .await?;
        Ok(())
    }

    fn make_node_signature(
        &self,
        node_key: &NodePublic,
        rotation_public: &[u8],
    ) -> Result<Vec<u8>, TailnetLockError> {
        let mut signature = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(node_key.raw32().to_vec()),
            key_id: Some(self.params.signing_key.public().raw32().to_vec()),
            signature: None,
            nested: None,
            wrapping_pubkey: (!rotation_public.is_empty()).then(|| rotation_public.to_vec()),
        };
        signature.signature = Some(
            self.params
                .signing_key
                .sign(&signature.sig_hash())
                .map_err(|_| TailnetLockError::StateUnavailable)?,
        );
        Ok(signature.encode())
    }

    /// Ask control to disable the tailnet. Local enforcement remains active
    /// until a later map update carries a matching disablement proof.
    pub(crate) async fn disable(&self, secret: Vec<u8>) -> Result<(), TailnetLockError> {
        let _operation = self.operation().await;
        if secret.len() > MAX_DISABLEMENT_SECRET {
            return Err(TailnetLockError::InvalidRequest(
                "disablement secret is too large".into(),
            ));
        }
        let (authority, _) = self
            .authority_snapshot()
            .ok_or(TailnetLockError::NotEnabled)?;
        if !authority.valid_disablement(&secret) {
            return Err(TailnetLockError::InvalidRequest(
                "disablement secret is invalid".into(),
            ));
        }
        // Join the same commit/revocation barrier used by map transitions.
        // Local enforcement remains closed under the existing authority until
        // a later map supplies and validates the disablement proof.
        self.peer_authority()?.synchronize().await;
        let control = self.control();
        TkaClient::new(&control)
            .disable(&TKADisableRequest {
                Version: self.params.capability_version,
                NodeKey: self.node_public(),
                Head: authority.head().to_string(),
                DisablementSecret: secret,
            })
            .await?;
        Ok(())
    }

    /// Disable Tailnet Lock enforcement for this profile/control namespace.
    ///
    /// This follows pinned Tailscale v1.100.0
    /// `ipn/ipnlocal.NetworkLockForceLocalDisable` and
    /// `persist.DisallowedTKAStateIDs`, adapted to RustScale's already-scoped
    /// owner-only state directory.
    ///
    /// This is an explicit recovery escape hatch, not a tailnet-wide change.
    /// The verified authority state ID is atomically denylisted before the
    /// active peer generation is withdrawn. A fresh authenticated bootstrap
    /// must prove that control still advertises that exact state ID before an
    /// unfiltered peer generation can be published again.
    async fn force_local_disable(&self) -> Result<(), TailnetLockError> {
        let _operation = self.operation().await;

        let already_disabled = {
            let inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.locally_disabled_state
        };
        if already_disabled.is_some() {
            let cleanup = self.remove_durable_state();
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.local_disable_cleanup_pending = cleanup.is_err();
            return cleanup.map_err(|_| TailnetLockError::LocalDisableCommitted);
        }

        // Resolve every fallible precondition before the durable commit. In
        // particular, never write a denylist that no attached runtime can
        // enforce in this process.
        let peer_authority = self.peer_authority()?;
        let (state_id, mut denylist) = {
            let inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let authority = inner
                .authority
                .as_ref()
                .ok_or(TailnetLockError::NotEnabled)?;
            (
                AuthorityStateId::from_authority(authority),
                inner.disallowed_state_ids.clone(),
            )
        };
        denylist.insert(state_id);
        save_local_disable_denylist(self.params.state_dir.as_deref(), &denylist)?;

        {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.disallowed_state_ids = denylist;
            inner.required = true;
            inner.ready = false;
        }

        // This await is retained independently of the LocalAPI socket. It
        // drains every packet/publication reader before authority state is
        // removed, so no traffic can straddle the local-disable boundary.
        peer_authority.withdraw().await;
        {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.authority = None;
            inner.storage = None;
            inner.locally_disabled_state = Some(state_id);
            inner.locally_disabled_head = None;
            inner.required = true;
            inner.ready = false;
            inner.filtered.clear();
        }

        let cleanup = self.remove_durable_state();
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.local_disable_cleanup_pending = cleanup.is_err();
        cleanup.map_err(|_| TailnetLockError::LocalDisableCommitted)
    }

    /// Filter an entire reconstructed peer set. This runs after deltas and
    /// patches are applied, so a key/signature split across partial updates is
    /// rejected rather than accidentally paired with stale state.
    pub(crate) fn filter_peers(&self, peers: &mut Vec<Node>) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let enforcement = inner.required || inner.authority.is_some();
        if !enforcement {
            inner.filtered.clear();
            return;
        }
        if inner.locally_disabled_state.is_some() && inner.ready {
            let mut filtered = Vec::new();
            peers.retain(|peer| {
                if peer.UnsignedPeerAPIOnly {
                    // Local disable relaxes TKA signature enforcement, not the
                    // control-provided PeerAPI-only confinement. RustScale
                    // cannot yet carry that confinement through every data-
                    // plane consumer, so keep dropping these peers rather than
                    // promoting them to ordinary network access.
                    filtered.push(filtered_peer(peer, "unsigned PeerAPI-only unsupported"));
                    false
                } else {
                    true
                }
            });
            inner.filtered = filtered;
            return;
        }
        let authority = inner.authority.clone();
        let ready = inner.ready;
        let mut filtered = Vec::new();
        let mut rotations = Vec::new();
        peers.retain(|peer| {
            if peer.UnsignedPeerAPIOnly {
                // RustScale does not yet carry upstream's PeerAPI-only
                // restriction through every data-plane consumer. Dropping the
                // node is safer than accidentally granting normal network use.
                filtered.push(filtered_peer(peer, "unsigned PeerAPI-only unsupported"));
                return false;
            }
            let Some(signature) = peer.KeySignature.as_deref() else {
                filtered.push(filtered_peer(peer, "missing signature"));
                return false;
            };
            let Some(authority) = authority.as_ref().filter(|_| ready) else {
                filtered.push(filtered_peer(peer, "authority unavailable"));
                return false;
            };
            if let Ok(details) = authority.node_key_authorized(&peer.Key.raw32(), signature) {
                if let Some(details) = details {
                    rotations.push((peer.Key.raw32(), details));
                }
                true
            } else {
                filtered.push(filtered_peer(peer, "invalid signature"));
                false
            }
        });

        let mut obsolete = HashSet::new();
        let mut by_wrapper: HashMap<Vec<u8>, Vec<([u8; 32], usize)>> = HashMap::new();
        for (node_key, details) in rotations {
            obsolete.extend(
                details
                    .prev_node_keys
                    .iter()
                    .filter_map(|key| <[u8; 32]>::try_from(key.as_slice()).ok()),
            );
            if let Some(initial) = details.initial_sig {
                if initial.sig_kind == SigKind::Direct {
                    if let Some(wrapper) = initial.wrapping_pubkey {
                        by_wrapper
                            .entry(wrapper)
                            .or_default()
                            .push((node_key, details.prev_node_keys.len()));
                    }
                }
            }
        }
        for chains in by_wrapper.values_mut() {
            chains.retain(|(key, _)| !obsolete.contains(key));
            chains.sort_by_key(|(_, depth)| std::cmp::Reverse(*depth));
            if chains.len() > 1 && chains[0].1 == chains[1].1 {
                obsolete.extend(chains.iter().map(|(key, _)| *key));
            } else {
                obsolete.extend(chains.iter().skip(1).map(|(key, _)| *key));
            }
        }
        peers.retain(|peer| {
            if obsolete.contains(&peer.Key.raw32()) {
                filtered.push(filtered_peer(peer, "obsolete rotation"));
                false
            } else {
                true
            }
        });
        inner.filtered = filtered;
    }

    pub(crate) fn set_self_node(&self, node: Option<Node>) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .self_node = node;
    }

    pub(crate) fn status_json(&self) -> serde_json::Value {
        let receipt = self.load_init_receipt().ok().flatten().map(|receipt| {
            serde_json::json!({
                "TransactionID": receipt.transaction_id,
                "Phase": format!("{:?}", receipt.phase),
                "CreatedUnix": receipt.created_unix,
                "ResumeCommand": "rustscale lock init --resume --confirm",
            })
        });
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let public = self.params.signing_key.public();
        let node_public = self.node_public();
        let enabled = inner.authority.is_some();
        let trusted = inner
            .authority
            .as_ref()
            .map(|authority| {
                authority
                    .keys()
                    .into_iter()
                    .map(|key| {
                        serde_json::json!({
                            "Kind": format!("{:?}", key.kind),
                            "Key": key.id().ok().and_then(|id| <[u8; 32]>::try_from(id).ok()).map(|id| rustscale_key::NLPublic::from_raw32(id).cli_string()),
                            "Votes": key.votes,
                            "Metadata": key.meta,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let self_signed = inner.authority.as_ref().is_some_and(|authority| {
            inner.ready
                && inner.self_node.as_ref().is_some_and(|node| {
                    node.KeySignature.as_deref().is_some_and(|signature| {
                        authority
                            .node_key_authorized(&node.Key.raw32(), signature)
                            .is_ok()
                    })
                })
        });
        let local_disable_pending = inner.authority.is_none()
            && inner.locally_disabled_state.is_none()
            && !inner.disallowed_state_ids.is_empty()
            && inner.required;
        serde_json::json!({
            "Enabled": enabled,
            "LocalDisabled": inner.locally_disabled_state.is_some(),
            "LocalDisablePending": local_disable_pending,
            "LocalDisableStateID": inner.locally_disabled_state.map(AuthorityStateId::display),
            "LocalDisableCleanupPending": inner.local_disable_cleanup_pending,
            "DisallowedStateIDs": inner.disallowed_state_ids.iter().copied().map(AuthorityStateId::display).collect::<Vec<_>>(),
            "StateConsistent": !inner.required || inner.ready,
            "Head": inner.authority.as_ref().map(|authority| authority.head().to_string()),
            "PublicKey": public.cli_string(),
            "NodeKey": node_public.to_string(),
            "NodeKeySigned": self_signed,
            "TrustedKeys": trusted,
            "FilteredPeers": inner.filtered,
            "InitReceipt": receipt,
        })
    }
}

fn filtered_peer(peer: &Node, reason: &'static str) -> FilteredPeer {
    FilteredPeer {
        name: peer.Name.clone(),
        id: peer.ID,
        stable_id: peer.StableID.clone(),
        node_key: peer.Key.clone(),
        tailscale_ips: peer.Addresses.clone(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::{MachinePrivate, NLPrivate, NodePrivate};

    fn unlocked_runtime() -> Arc<TailnetLock> {
        TailnetLock::open(TailnetLockParams {
            control_url: "http://127.0.0.1:1".into(),
            machine_key: MachinePrivate::generate(),
            server_pub_key: MachinePrivate::generate().public(),
            node_key: NodePrivate::generate(),
            signing_key: NLPrivate::generate(),
            capability_version: 141,
            protocol_version: 141,
            state_dir: None,
            extra_root_certs: None,
        })
        .unwrap()
    }

    #[test]
    fn local_disable_denylist_rejects_duplicates_and_excess() {
        let duplicate = LocalDisableDenylist {
            version: LOCAL_DISABLE_DENYLIST_VERSION,
            state_ids: vec![
                AuthorityStateId { id1: 1, id2: 2 },
                AuthorityStateId { id1: 1, id2: 2 },
            ],
        };
        assert!(validate_local_disable_denylist(duplicate).is_err());
        let excessive = LocalDisableDenylist {
            version: LOCAL_DISABLE_DENYLIST_VERSION,
            state_ids: (0..=MAX_LOCAL_DISABLED_STATES)
                .map(|id| AuthorityStateId {
                    id1: id as u64,
                    id2: 0,
                })
                .collect(),
        };
        assert!(validate_local_disable_denylist(excessive).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn malformed_local_disable_denylist_fails_closed_on_open() {
        let state = tempfile::tempdir().unwrap();
        rustscale_atomicfile::write_private(
            &local_disable_denylist_path(state.path()),
            br#"{"version":1,"state_ids":[{"id1":"bad","id2":2}]}"#,
        )
        .unwrap();
        let error = TailnetLock::open(TailnetLockParams {
            control_url: "http://127.0.0.1:1".into(),
            machine_key: MachinePrivate::generate(),
            server_pub_key: MachinePrivate::generate().public(),
            node_key: NodePrivate::generate(),
            signing_key: NLPrivate::generate(),
            capability_version: 141,
            protocol_version: 141,
            state_dir: Some(state.path().into()),
            extra_root_certs: None,
        })
        .err()
        .expect("malformed denylist must reject startup");
        assert!(matches!(error, TailnetLockError::InvalidRequest(_)));
    }

    #[cfg(unix)]
    #[test]
    fn denylist_matches_exact_state_id_but_does_not_disable_a_new_authority() {
        let state = tempfile::tempdir().unwrap();
        let denied = AuthorityStateId { id1: 10, id2: 20 };
        save_local_disable_denylist(
            Some(state.path()),
            &std::iter::once(denied).collect::<BTreeSet<_>>(),
        )
        .unwrap();
        let signing_key = NLPrivate::generate();
        let lock = TailnetLock::open(TailnetLockParams {
            control_url: "http://127.0.0.1:1".into(),
            machine_key: MachinePrivate::generate(),
            server_pub_key: MachinePrivate::generate().public(),
            node_key: NodePrivate::generate(),
            signing_key: signing_key.clone(),
            capability_version: 141,
            protocol_version: 141,
            state_dir: Some(state.path().into()),
            extra_root_certs: None,
        })
        .unwrap();
        assert_eq!(lock.status_json()["LocalDisablePending"], true);
        let make_genesis = |state_id: AuthorityStateId| {
            let storage = MemChonk::new();
            Authority::create(
                &storage,
                State {
                    last_aum_hash: None,
                    disablement_values: vec![rustscale_tka::disablement_kdf(b"exact-state")],
                    keys: vec![Key {
                        kind: rustscale_tka::KeyKind::Key25519,
                        votes: 1,
                        public: signing_key.public().raw32().to_vec(),
                        meta: None,
                    }],
                    state_id1: state_id.id1,
                    state_id2: state_id.id2,
                },
                &NlSigner(&signing_key),
            )
            .unwrap()
            .1
        };

        assert!(matches!(
            lock.persist_genesis(&make_genesis(denied)).unwrap(),
            PersistGenesisOutcome::LocallyDisabled(state_id) if state_id == denied
        ));
        let replacement = AuthorityStateId { id1: 10, id2: 21 };
        match lock.persist_genesis(&make_genesis(replacement)).unwrap() {
            PersistGenesisOutcome::Installed(authority, _) => {
                assert_eq!(authority.state_ids(), (replacement.id1, replacement.id2));
            }
            PersistGenesisOutcome::LocallyDisabled(_) => {
                panic!("a distinct authority state ID inherited local-disable")
            }
        }
    }

    #[test]
    fn local_disable_never_promotes_unsigned_peerapi_only_to_network_access() {
        let lock = unlocked_runtime();
        let state_id = AuthorityStateId { id1: 5, id2: 6 };
        {
            let mut inner = lock.inner.lock().unwrap();
            inner.disallowed_state_ids.insert(state_id);
            inner.locally_disabled_state = Some(state_id);
            inner.locally_disabled_head = Some(rustscale_tka::AumHash([2; 32]));
            inner.required = true;
            inner.ready = true;
        }
        let ordinary = Node {
            ID: 1,
            StableID: "ordinary".into(),
            Key: NodePrivate::generate().public(),
            ..Default::default()
        };
        let restricted = Node {
            ID: 2,
            StableID: "peerapi-only".into(),
            Key: NodePrivate::generate().public(),
            UnsignedPeerAPIOnly: true,
            ..Default::default()
        };
        let mut peers = vec![ordinary.clone(), restricted];
        lock.filter_peers(&mut peers);
        assert_eq!(peers, vec![ordinary]);
        assert_eq!(
            lock.status_json()["FilteredPeers"][0]["Reason"],
            "unsigned PeerAPI-only unsupported"
        );
    }

    #[tokio::test]
    async fn malformed_head_withdraws_a_ready_local_disable_generation() {
        let lock = unlocked_runtime();
        let state_id = AuthorityStateId { id1: 7, id2: 9 };
        {
            let mut inner = lock.inner.lock().unwrap();
            inner.disallowed_state_ids.insert(state_id);
            inner.locally_disabled_state = Some(state_id);
            inner.locally_disabled_head = Some(rustscale_tka::AumHash([3; 32]));
            inner.required = true;
            inner.ready = true;
        }
        let mut peers = vec![Node {
            ID: 1,
            Key: NodePrivate::generate().public(),
            ..Default::default()
        }];
        lock.filter_peers(&mut peers);
        assert_eq!(peers.len(), 1);

        let malformed = TKAInfo {
            Head: "not-an-aum-hash".into(),
            Disabled: false,
        };
        assert!(lock
            .operation()
            .await
            .control_change_requires_revocation(Some(&malformed), false));
        assert!(lock
            .apply_control_info(Some(&malformed), false)
            .await
            .is_err());
        assert!(!lock.authorization_ready());
        lock.filter_peers(&mut peers);
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn control_change_revocation_predicate_is_fail_closed_without_churn() {
        let lock = unlocked_runtime();
        let operation = lock.operation().await;
        assert!(!operation.control_change_requires_revocation(None, false));
        assert!(!operation.control_change_requires_revocation(None, true));
        assert!(!operation.control_change_requires_revocation(
            Some(&TKAInfo {
                Disabled: true,
                ..Default::default()
            }),
            false,
        ));
        assert!(operation.control_change_requires_revocation(
            Some(&TKAInfo {
                Head: "malformed-new-head".into(),
                Disabled: false,
            }),
            false,
        ));
        drop(operation);

        lock.require_fresh_control_state();
        assert!(lock.operation().await.control_change_requires_revocation(
            Some(&TKAInfo {
                Disabled: true,
                ..Default::default()
            }),
            false,
        ));
    }
}
