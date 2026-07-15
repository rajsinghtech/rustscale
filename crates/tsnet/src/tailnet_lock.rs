//! Scoped Tailnet Lock runtime: durable authority state, bounded control sync,
//! LocalAPI operations, and fail-closed peer authorization.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
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
    /// Control has advertised enabled state. This is set before attempting
    /// bootstrap/sync so failed or partial state can never open the peer set.
    required: bool,
    /// The authority reached the control head during the latest operation.
    ready: bool,
    filtered: Vec<FilteredPeer>,
    self_node: Option<Node>,
}

pub(crate) struct TailnetLock {
    current_node_key: Mutex<NodePrivate>,
    params: TailnetLockParams,
    path: Option<PathBuf>,
    operation: tokio::sync::Mutex<()>,
    init_flight: Mutex<Option<InitFlightState>>,
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

impl TailnetLock {
    pub(crate) fn open(params: TailnetLockParams) -> Result<Arc<Self>, TailnetLockError> {
        let path = params.state_dir.as_ref().map(|dir| {
            dir.join("tailnet-lock")
                .join(hex::encode(params.signing_key.public().raw32()))
        });
        if let Some(existing) = path.as_ref().filter(|path| path.exists()) {
            rustscale_atomicfile::ensure_private_dir(existing)
                .map_err(TailnetLockError::Persistence)?;
        }
        let (authority, storage) = match path.as_ref().filter(|path| path.is_dir()) {
            Some(path) => {
                let storage = Arc::new(
                    FsChonk::open(path)
                        .map_err(rustscale_tka::AuthorityError::from)
                        .map_err(TailnetLockError::Authority)?,
                );
                let authority = Authority::open(storage.as_ref())?;
                (Some(authority), Some(storage))
            }
            None => (None, None),
        };
        let enabled = authority.is_some();
        let current_node_key = Mutex::new(params.node_key.clone());
        Ok(Arc::new(Self {
            current_node_key,
            params,
            path,
            operation: tokio::sync::Mutex::new(()),
            init_flight: Mutex::new(None),
            peer_authority: Mutex::new(None),
            inner: Mutex::new(Inner {
                authority,
                storage,
                required: enabled,
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
                inner.authority.as_ref().map(Authority::head) != Some(wanted)
            }
            Some(_) => inner.required || inner.authority.is_some(),
            None if initial => inner.required || inner.authority.is_some(),
            None => false,
        }
    }

    pub(crate) fn authorization_ready(&self) -> bool {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                if inner.authority.as_ref().map(Authority::head) == Some(wanted) {
                    inner.ready = true;
                    return Ok(());
                }
            }

            let control = self.control();
            let session = TkaClient::new(&control).connect().await?;
            if self.authority_snapshot().is_none() {
                self.bootstrap_from_control(&session).await?;
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

    async fn bootstrap_from_control(&self, session: &TkaSession) -> Result<(), TailnetLockError> {
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
        let (authority, storage) = self.persist_genesis(&genesis)?;
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.authority = Some(authority);
        inner.storage = Some(storage);
        Ok(())
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

    fn persist_genesis(
        &self,
        genesis: &Aum,
    ) -> Result<(Authority, Arc<FsChonk>), TailnetLockError> {
        let path = self
            .path
            .as_ref()
            .ok_or(TailnetLockError::NoStateDirectory)?;
        let parent = path.parent().ok_or(TailnetLockError::NoStateDirectory)?;
        rustscale_atomicfile::ensure_private_dir(parent).map_err(TailnetLockError::Persistence)?;
        let pending = path.with_extension("pending");
        if pending.exists() {
            std::fs::remove_dir_all(&pending).map_err(TailnetLockError::Persistence)?;
        }
        if path.exists() {
            return Err(TailnetLockError::AlreadyEnabled);
        }
        rustscale_atomicfile::ensure_private_dir(&pending)
            .map_err(TailnetLockError::Persistence)?;
        let pending_storage = FsChonk::open(&pending)
            .map_err(rustscale_tka::AuthorityError::from)
            .map_err(TailnetLockError::Authority)?;
        Authority::bootstrap(&pending_storage, genesis.clone())?;
        drop(pending_storage);
        std::fs::rename(&pending, path).map_err(TailnetLockError::Persistence)?;
        let storage = Arc::new(
            FsChonk::open(path)
                .map_err(rustscale_tka::AuthorityError::from)
                .map_err(TailnetLockError::Authority)?,
        );
        let authority = Authority::open(storage.as_ref())?;
        Ok((authority, storage))
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
        Ok(())
    }

    fn remove_durable_state(&self) -> Result<(), TailnetLockError> {
        let path = self
            .path
            .as_ref()
            .ok_or(TailnetLockError::NoStateDirectory)?;
        if !path.exists() {
            return Ok(());
        }
        let tombstone = path.with_extension("deleting");
        if tombstone.exists() {
            std::fs::remove_dir_all(&tombstone).map_err(TailnetLockError::Persistence)?;
        }
        std::fs::rename(path, &tombstone).map_err(TailnetLockError::Persistence)?;
        std::fs::remove_dir_all(tombstone).map_err(TailnetLockError::Persistence)?;
        if let Some(parent) = path.parent() {
            let empty = std::fs::read_dir(parent)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false);
            if empty {
                let _ = std::fs::remove_dir(parent);
            }
        }
        Ok(())
    }

    /// Admit one lifecycle-retained LocalAPI initialization flight. The
    /// request body is fingerprinted so concurrent retries can join only the
    /// exact same transaction; a disconnected waiter never owns cancellation
    /// of authority withdrawal or local commit.
    pub(crate) fn start_init(
        self: &Arc<Self>,
        request: InitRequest,
    ) -> Result<InitFlight, TailnetLockError> {
        let encoded = serde_json::to_vec(&request).map_err(|error| {
            TailnetLockError::InvalidRequest(format!(
                "initialization request could not be encoded: {error}"
            ))
        })?;
        let request_hash: [u8; 32] = Sha256::digest(encoded).into();
        let mut retained = self
            .init_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(flight) = retained
            .as_ref()
            .filter(|flight| !flight.task.is_finished())
        {
            if flight.request_hash != request_hash {
                return Err(TailnetLockError::InvalidRequest(
                    "another Tailnet Lock initialization request is already running".into(),
                ));
            }
            return Ok(InitFlight {
                result: flight.result.clone(),
            });
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
    /// the peer-authority runtime it still owns. If this join future itself is
    /// dropped, Tokio retains the spawned operation and it still completes.
    pub(crate) async fn join_init_flight(&self) {
        let flight = self
            .init_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(flight) = flight {
            let _ = flight.task.await;
        }
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
                    let (authority, storage) = self.persist_genesis(&genesis)?;
                    let mut inner = self
                        .inner
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    inner.authority = Some(authority);
                    inner.storage = Some(storage);
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

        let (authority, storage) = self.persist_genesis(&genesis)?;
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.authority = Some(authority);
        inner.storage = Some(storage);
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
        serde_json::json!({
            "Enabled": enabled,
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
