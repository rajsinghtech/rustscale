use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use cap_fs_ext::{DirExt, FileTypeExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsSyncExt};
use cap_std::fs::{Dir, File, OpenOptions};
use rand_core::{OsRng, RngCore};
use tokio::sync::mpsc as tokio_mpsc;
use tokio_util::sync::CancellationToken;

use crate::auth::{AuthenticatedPeer, Permission};
use crate::config::{ConfigStore, Limits, ShareRoot, Snapshot};
use crate::path::{href_for_components, parse_request_path, ParsedPath};

const ALLOW: &str = "OPTIONS, GET, HEAD, PROPFIND, PUT, MKCOL, DELETE, MOVE, COPY";
const QUARANTINE_DIRECTORY: &str = ".rustscale-taildrive-quarantine";

pub type HeaderMap = BTreeMap<String, String>;

/// Bounded producer/consumer pair for a streamed request body. The receiver is
/// consumed only on Taildrive's blocking filesystem pool; the async producer
/// applies backpressure through the bounded channel.
pub struct StreamingBody {
    receiver: tokio_mpsc::Receiver<Vec<u8>>,
    expected_length: usize,
}

pub fn streaming_body_channel(
    expected_length: usize,
    capacity: usize,
) -> (tokio_mpsc::Sender<Vec<u8>>, StreamingBody) {
    let (sender, receiver) = tokio_mpsc::channel(capacity.max(1));
    (
        sender,
        StreamingBody {
            receiver,
            expected_length,
        },
    )
}

/// A bounded request supplied by an HTTP/PeerAPI adapter.
#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Request {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            headers: HeaderMap::new(),
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.into().to_ascii_lowercase(), value.into());
        self
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Response {
    fn new(status: u16) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: Vec::new(),
        }
    }

    fn text(status: u16, message: &'static str) -> Self {
        let mut response = Self::new(status);
        response
            .headers
            .insert("content-type".into(), "text/plain; charset=utf-8".into());
        response.body = message.as_bytes().to_vec();
        response
    }

    fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }
}

/// Shared linearization barrier for configuration and signed grant epochs.
struct CommitBarrier {
    gate: RwLock<()>,
    epoch: AtomicU64,
    cancellation: Mutex<CancellationToken>,
}

impl CommitBarrier {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            gate: RwLock::new(()),
            epoch: AtomicU64::new(0),
            cancellation: Mutex::new(CancellationToken::new()),
        })
    }

    fn authority(self: &Arc<Self>) -> RequestAuthority {
        let _gate = self
            .gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let epoch = self.epoch.load(Ordering::Acquire);
        let cancellation = self
            .cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .child_token();
        RequestAuthority {
            barrier: self.clone(),
            epoch,
            cancellation,
        }
    }

    /// Cancel staging work, drain any short publication critical section, and
    /// advance the authority epoch before returning.
    fn revoke(&self) {
        self.cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cancel();
        let _gate = self
            .gate
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.epoch.fetch_add(1, Ordering::AcqRel);
        *self
            .cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = CancellationToken::new();
    }
}

/// Request-scoped authority captured while the signed grant/config epoch is
/// stable. Mutations can publish only while this epoch is still current.
#[derive(Clone)]
pub struct RequestAuthority {
    barrier: Arc<CommitBarrier>,
    epoch: u64,
    cancellation: CancellationToken,
}

impl RequestAuthority {
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

/// Per-request cancellation, deadline, and publication authority supplied by
/// the connection adapter.
#[derive(Clone)]
pub struct RequestControl {
    authority: RequestAuthority,
    deadline: Instant,
    #[cfg(test)]
    after_sync: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    before_commit: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    after_transaction: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    before_isolation: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl RequestControl {
    pub fn new(authority: RequestAuthority, deadline: Instant) -> Self {
        Self {
            authority,
            deadline,
            #[cfg(test)]
            after_sync: None,
            #[cfg(test)]
            before_commit: None,
            #[cfg(test)]
            after_transaction: None,
            #[cfg(test)]
            before_isolation: None,
        }
    }

    fn check(&self) -> Result<(), Interrupted> {
        if self.authority.cancellation.is_cancelled() {
            Err(Interrupted::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(Interrupted::Deadline)
        } else {
            Ok(())
        }
    }

    fn wait_slice(&self) -> Duration {
        self.deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(10))
    }

    fn commit<T>(
        &self,
        action: impl FnOnce() -> Result<T, OperationError>,
    ) -> Result<T, OperationError> {
        self.check()?;
        #[cfg(test)]
        if let Some(hook) = &self.before_commit {
            hook();
        }
        let _gate = self
            .authority
            .barrier
            .gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.check()?;
        if self.authority.epoch != self.authority.barrier.epoch.load(Ordering::Acquire) {
            return Err(OperationError::Interrupted(Interrupted::Cancelled));
        }
        action()
    }

    #[cfg(test)]
    fn with_after_sync(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.after_sync = Some(hook);
        self
    }

    #[cfg(test)]
    fn with_before_commit(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.before_commit = Some(hook);
        self
    }

    #[cfg(test)]
    fn with_after_transaction(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.after_transaction = Some(hook);
        self
    }

    #[cfg(test)]
    fn notify_after_transaction(&self) {
        if let Some(hook) = &self.after_transaction {
            hook();
        }
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    fn notify_after_transaction(&self) {}

    #[cfg(test)]
    fn with_before_isolation(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.before_isolation = Some(hook);
        self
    }

    #[cfg(test)]
    fn notify_before_isolation(&self) {
        if let Some(hook) = &self.before_isolation {
            hook();
        }
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    fn notify_before_isolation(&self) {}

    #[cfg(test)]
    fn notify_after_sync(&self) {
        if let Some(hook) = &self.after_sync {
            hook();
        }
    }
}

impl std::fmt::Debug for RequestControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestControl")
            .field("cancelled", &self.authority.cancellation.is_cancelled())
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

type Job = Box<dyn FnOnce() + Send + 'static>;

struct WorkerPool {
    sender: SyncSender<Job>,
}

impl WorkerPool {
    fn new(worker_count: usize, queue_capacity: usize) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<Job>(queue_capacity.max(1));
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..worker_count.max(1) {
            let receiver = receiver.clone();
            std::thread::Builder::new()
                .name(format!("taildrive-fs-{index}"))
                .spawn(move || loop {
                    let job = match receiver.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(poisoned) => poisoned.into_inner().recv(),
                    };
                    match job {
                        Ok(job) => job(),
                        Err(_) => break,
                    }
                })
                .expect("failed to start bounded Taildrive filesystem worker");
        }
        Self { sender }
    }

    fn try_execute(&self, job: Job) -> Result<(), TrySendError<Job>> {
        self.sender.try_send(job)
    }
}

#[derive(Clone)]
pub struct Server {
    config: Arc<ConfigStore>,
    workers: Arc<WorkerPool>,
    commits: Arc<CommitBarrier>,
}

impl Server {
    pub fn new(config: Arc<ConfigStore>) -> Self {
        let workers = Arc::new(WorkerPool::new(
            config.limits().filesystem_workers,
            config.limits().filesystem_queue,
        ));
        Self {
            config,
            workers,
            commits: CommitBarrier::new(),
        }
    }

    /// Capture the current configuration/grant authority for one request.
    pub fn request_authority(&self) -> RequestAuthority {
        self.commits.authority()
    }

    /// Revoke the old epoch and wait for any publication already linearized
    /// under it to leave its short commit section.
    pub fn revoke_authority(&self) {
        self.commits.revoke();
    }

    /// Authorize method, path, share, and destination without touching a
    /// request body or filesystem object. PeerAPI adapters call this before
    /// accepting upload bytes; [`Self::handle`] repeats all checks.
    pub fn preflight(&self, peer: &AuthenticatedPeer, request: &Request) -> Result<(), Response> {
        let limits = self.config.limits();
        let snapshot = self.config.snapshot();
        if !snapshot.enabled() {
            return Err(Response::text(404, "taildrive not enabled"));
        }
        let parsed = parse_request_path(&request.path, limits.max_path_bytes)
            .map_err(|_| Response::text(400, "invalid WebDAV path"))?;
        if !matches!(
            request.method.as_str(),
            "OPTIONS" | "PROPFIND" | "GET" | "HEAD" | "PUT" | "MKCOL" | "DELETE" | "MOVE" | "COPY"
        ) {
            return Err(Response::text(405, "method not allowed").header("allow", ALLOW));
        }
        if request.method == "OPTIONS" {
            return Ok(());
        }
        let Some(share_name) = parsed.share.as_deref() else {
            return if request.method == "PROPFIND" {
                Ok(())
            } else {
                Err(Response::text(405, "method not allowed").header("allow", ALLOW))
            };
        };
        let permission = peer.permissions().for_share(share_name);
        if permission == Permission::None {
            return Err(Response::text(404, "not found"));
        }
        if required_permission(&request.method) == Permission::ReadWrite
            && permission != Permission::ReadWrite
        {
            return Err(Response::text(403, "permission denied"));
        }
        if !snapshot.shares.contains_key(share_name) {
            return Err(Response::text(404, "not found"));
        }
        if matches!(request.method.as_str(), "MOVE" | "COPY") {
            let destination = request
                .header("destination")
                .ok_or_else(|| Response::text(400, "bad WebDAV request"))?;
            let destination = parse_request_path(destination, limits.max_path_bytes)
                .map_err(|_| Response::text(400, "bad WebDAV request"))?;
            let destination_share = destination
                .share
                .as_deref()
                .ok_or_else(|| Response::text(400, "bad WebDAV request"))?;
            if destination_share != share_name {
                return Err(Response::text(502, "cross-share operation is forbidden"));
            }
            if peer.permissions().for_share(destination_share) != Permission::ReadWrite {
                return Err(Response::text(403, "permission denied"));
            }
        }
        Ok(())
    }

    /// Handle one request using one immutable configuration snapshot.
    pub fn handle(
        &self,
        peer: &AuthenticatedPeer,
        request: Request,
        control: &RequestControl,
    ) -> Response {
        self.handle_with_stream(peer, request, None, control)
    }

    /// Handle a PUT whose body arrives through a bounded channel.
    pub fn handle_streaming_put(
        &self,
        peer: &AuthenticatedPeer,
        request: Request,
        body: StreamingBody,
        control: &RequestControl,
    ) -> Response {
        if request.method != "PUT" {
            return Response::text(400, "streaming body is only valid for PUT");
        }
        self.handle_with_stream(peer, request, Some(body), control)
    }

    fn handle_with_stream(
        &self,
        peer: &AuthenticatedPeer,
        request: Request,
        streaming_body: Option<StreamingBody>,
        control: &RequestControl,
    ) -> Response {
        if !Arc::ptr_eq(&control.authority.barrier, &self.commits) {
            return Response::text(403, "invalid request authority");
        }
        if let Err(interrupted) = control.check() {
            return interrupted.response();
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let server = self.clone();
        let peer = peer.clone();
        let worker_control = control.clone();
        let job = Box::new(move || {
            let response = server.handle_on_worker(&peer, request, streaming_body, &worker_control);
            let _ = sender.send(response);
        });
        match self.workers.try_execute(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Response::text(503, "filesystem workers are busy")
            }
            Err(TrySendError::Disconnected(_)) => {
                return Response::text(503, "filesystem workers unavailable")
            }
        }
        loop {
            if let Err(interrupted) = control.check() {
                return interrupted.response();
            }
            match receiver.recv_timeout(control.wait_slice()) {
                Ok(response) => return response,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Response::text(500, "filesystem worker failed")
                }
            }
        }
    }

    fn handle_on_worker(
        &self,
        peer: &AuthenticatedPeer,
        request: Request,
        streaming_body: Option<StreamingBody>,
        control: &RequestControl,
    ) -> Response {
        if let Err(interrupted) = control.check() {
            return interrupted.response();
        }
        let limits = self.config.limits();
        if request.body.len() > limits.max_request_body
            || streaming_body
                .as_ref()
                .is_some_and(|body| body.expected_length > limits.max_request_body)
        {
            return Response::text(413, "request body too large");
        }
        let snapshot = self.config.snapshot();
        if !snapshot.enabled() {
            return Response::text(404, "taildrive not enabled");
        }
        let parsed = match parse_request_path(&request.path, limits.max_path_bytes) {
            Ok(parsed) => parsed,
            Err(_) => return Response::text(400, "invalid WebDAV path"),
        };

        if request.method == "OPTIONS" {
            return Response::new(200)
                .header("allow", ALLOW)
                .header("dav", "1")
                .header("content-length", "0");
        }
        if request.method == "PROPFIND" {
            return self.propfind(peer, &snapshot, &request, &parsed, control);
        }

        let Some(share_name) = parsed.share.as_deref() else {
            return Response::text(405, "method not allowed").header("allow", ALLOW);
        };
        let permission = peer.permissions().for_share(share_name);
        let required = required_permission(&request.method);
        if permission == Permission::None {
            // Do not reveal whether an ungranted share exists.
            return Response::text(404, "not found");
        }
        if required == Permission::ReadWrite && permission != Permission::ReadWrite {
            return Response::text(403, "permission denied");
        }
        let Some(root) = snapshot.shares.get(share_name) else {
            return Response::text(404, "not found");
        };

        let result = match request.method.as_str() {
            "GET" => self.get(root, &parsed, false, control),
            "HEAD" => self.get(root, &parsed, true, control),
            "PUT" => match streaming_body {
                Some(body) => Self::put_streaming(root, &parsed, body, control),
                None => Self::put(root, &parsed, &request.body, control),
            },
            "MKCOL" => Self::mkcol(root, &parsed, &request.body, control),
            "DELETE" => Self::delete(root, &parsed, control),
            "MOVE" => self.move_or_copy(peer, &snapshot, root, &parsed, &request, false, control),
            "COPY" => self.move_or_copy(peer, &snapshot, root, &parsed, &request, true, control),
            _ => return Response::text(405, "method not allowed").header("allow", ALLOW),
        };
        match result {
            Ok(response) => response,
            Err(error) => error.response(),
        }
    }

    fn get(
        &self,
        root: &ShareRoot,
        parsed: &ParsedPath,
        head_only: bool,
        control: &RequestControl,
    ) -> Result<Response, OperationError> {
        let (mut file, metadata) = open_regular_nofollow_nonblocking(&root.dir, &parsed.relative)?;
        let length =
            usize::try_from(metadata.len()).map_err(|_| OperationError::ResponseTooLarge)?;
        if length > self.config.limits().max_response_body {
            return Err(OperationError::ResponseTooLarge);
        }
        let mut response = Response::new(200)
            .header("content-length", length.to_string())
            .header("content-type", "application/octet-stream")
            .header("accept-ranges", "bytes");
        if !head_only {
            let mut body = Vec::with_capacity(length);
            let mut chunk = vec![0u8; 64 * 1024].into_boxed_slice();
            loop {
                control.check()?;
                let count = file.read(&mut chunk)?;
                if count == 0 {
                    break;
                }
                if body.len().saturating_add(count) > self.config.limits().max_response_body {
                    return Err(OperationError::ResponseTooLarge);
                }
                body.extend_from_slice(&chunk[..count]);
            }
            response.body = body;
        }
        Ok(response)
    }

    fn put(
        root: &ShareRoot,
        parsed: &ParsedPath,
        body: &[u8],
        control: &RequestControl,
    ) -> Result<Response, OperationError> {
        if parsed.relative.as_os_str().is_empty() {
            return Err(OperationError::MethodNotAllowed);
        }
        let (parent, leaf) = open_parent_nofollow(&root.dir, &parsed.relative)?;
        let existed = match parent.symlink_metadata(&leaf) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        atomic_write(&parent, &leaf, body, control)?;
        Ok(Response::new(if existed { 204 } else { 201 }).header("content-length", "0"))
    }

    fn put_streaming(
        root: &ShareRoot,
        parsed: &ParsedPath,
        body: StreamingBody,
        control: &RequestControl,
    ) -> Result<Response, OperationError> {
        if parsed.relative.as_os_str().is_empty() {
            return Err(OperationError::MethodNotAllowed);
        }
        let (parent, leaf) = open_parent_nofollow(&root.dir, &parsed.relative)?;
        let existed = match parent.symlink_metadata(&leaf) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        atomic_write_streaming(&parent, &leaf, body, control)?;
        Ok(Response::new(if existed { 204 } else { 201 }).header("content-length", "0"))
    }

    fn mkcol(
        root: &ShareRoot,
        parsed: &ParsedPath,
        body: &[u8],
        control: &RequestControl,
    ) -> Result<Response, OperationError> {
        if parsed.relative.as_os_str().is_empty() {
            return Err(OperationError::MethodNotAllowed);
        }
        if !body.is_empty() {
            return Err(OperationError::UnsupportedMediaType);
        }
        let (parent, leaf) = open_parent_nofollow(&root.dir, &parsed.relative)?;
        control.commit(|| {
            parent.create_dir(&leaf)?;
            Ok(())
        })?;
        Ok(Response::new(201).header("content-length", "0"))
    }

    fn delete(
        root: &ShareRoot,
        parsed: &ParsedPath,
        control: &RequestControl,
    ) -> Result<Response, OperationError> {
        if parsed.relative.as_os_str().is_empty() {
            return Err(OperationError::Forbidden);
        }
        let (parent, leaf) = open_parent_nofollow(&root.dir, &parsed.relative)?;
        control.commit(|| transactional_delete(&parent, &leaf, control))?;
        Ok(Response::new(204).header("content-length", "0"))
    }

    fn move_or_copy(
        &self,
        peer: &AuthenticatedPeer,
        snapshot: &Snapshot,
        source_root: &ShareRoot,
        source: &ParsedPath,
        request: &Request,
        copy: bool,
        control: &RequestControl,
    ) -> Result<Response, OperationError> {
        if source.relative.as_os_str().is_empty() {
            return Err(OperationError::Forbidden);
        }
        let destination = request
            .header("destination")
            .ok_or(OperationError::BadRequest)?;
        // Absolute Destination URIs can redirect a privileged daemon into
        // acting as an HTTP/filesystem deputy. Only local origin paths work.
        let destination = parse_request_path(destination, self.config.limits().max_path_bytes)
            .map_err(|_| OperationError::BadRequest)?;
        let destination_share = destination
            .share
            .as_deref()
            .ok_or(OperationError::BadRequest)?;
        if destination_share != source.share.as_deref().unwrap_or_default() {
            return Err(OperationError::CrossShare);
        }
        if peer.permissions().for_share(destination_share) != Permission::ReadWrite {
            return Err(OperationError::Forbidden);
        }
        let destination_root = snapshot
            .shares
            .get(destination_share)
            .ok_or(OperationError::NotFound)?;
        if destination.relative.as_os_str().is_empty() {
            return Err(OperationError::Forbidden);
        }
        let (source_parent, source_leaf) =
            open_parent_nofollow(&source_root.dir, &source.relative)?;
        let (destination_parent, destination_leaf) =
            open_parent_nofollow(&destination_root.dir, &destination.relative)?;
        if !copy {
            if source.relative == destination.relative {
                return Ok(Response::new(204).header("content-length", "0"));
            }
            if request.header("overwrite") == Some("F")
                && destination_parent
                    .symlink_metadata(&destination_leaf)
                    .is_ok()
            {
                return Err(OperationError::PreconditionFailed);
            }
            let overwritten = control.commit(|| {
                transactional_move(
                    &source_parent,
                    &source_leaf,
                    &destination_parent,
                    &destination_leaf,
                    request.header("overwrite") != Some("F"),
                    control,
                )
            })?;
            return Ok(
                Response::new(if overwritten { 204 } else { 201 }).header("content-length", "0")
            );
        }

        let source_kind = supported_object_kind(&source_parent.symlink_metadata(&source_leaf)?)?;
        if source_kind != SupportedObjectKind::RegularFile {
            return Err(OperationError::UnsupportedFileType);
        }
        let destination_kind =
            optional_supported_object_kind(&destination_parent, &destination_leaf)?;
        if destination_kind.is_some_and(|kind| kind != SupportedObjectKind::RegularFile) {
            return Err(OperationError::UnsupportedFileType);
        }
        let destination_exists = destination_kind.is_some();
        if destination_exists && request.header("overwrite") == Some("F") {
            return Err(OperationError::PreconditionFailed);
        }
        let (mut source_file, metadata) =
            open_regular_at_nofollow_nonblocking(&source_parent, &source_leaf)?;
        let size = usize::try_from(metadata.len()).map_err(|_| OperationError::ResponseTooLarge)?;
        if size > self.config.limits().max_response_body {
            return Err(OperationError::ResponseTooLarge);
        }
        let mut bytes = Vec::with_capacity(size);
        let mut chunk = vec![0u8; 64 * 1024].into_boxed_slice();
        loop {
            control.check()?;
            let count = source_file.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            if bytes.len().saturating_add(count) > self.config.limits().max_response_body {
                return Err(OperationError::ResponseTooLarge);
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        atomic_write(&destination_parent, &destination_leaf, &bytes, control)?;
        Ok(Response::new(if destination_exists { 204 } else { 201 }).header("content-length", "0"))
    }

    fn propfind(
        &self,
        peer: &AuthenticatedPeer,
        snapshot: &Snapshot,
        request: &Request,
        parsed: &ParsedPath,
        control: &RequestControl,
    ) -> Response {
        let depth = request.header("depth").unwrap_or("infinity");
        if !matches!(depth, "0" | "1") {
            return Response::text(403, "PROPFIND depth must be 0 or 1");
        }
        let result = if let Some(share_name) = parsed.share.as_deref() {
            if peer.permissions().for_share(share_name) == Permission::None {
                Err(OperationError::NotFound)
            } else if let Some(root) = snapshot.shares.get(share_name) {
                propfind_share(root, parsed, depth == "1", self.config.limits(), control)
            } else {
                Err(OperationError::NotFound)
            }
        } else {
            propfind_root(peer, snapshot, depth == "1", self.config.limits(), control)
        };
        match result {
            Ok(body) => Response::new(207)
                .header("content-type", "application/xml; charset=utf-8")
                .header("content-length", body.len().to_string())
                .header("dav", "1")
                .with_body(body),
            Err(error) => error.response(),
        }
    }
}

impl Response {
    fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
}

fn required_permission(method: &str) -> Permission {
    match method {
        "GET" | "HEAD" | "PROPFIND" | "OPTIONS" => Permission::ReadOnly,
        _ => Permission::ReadWrite,
    }
}

fn open_parent_nofollow(dir: &Dir, relative: &Path) -> Result<(Dir, OsString), OperationError> {
    let leaf = relative
        .file_name()
        .ok_or(OperationError::BadRequest)?
        .to_os_string();
    let mut parent = dir.try_clone()?;
    if let Some(parent_path) = relative.parent() {
        for component in parent_path.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(OperationError::BadRequest);
            };
            parent = parent.open_dir_nofollow(name)?;
        }
    }
    Ok((parent, leaf))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SupportedObjectKind {
    RegularFile,
    Directory,
}

fn supported_object_kind(
    metadata: &cap_std::fs::Metadata,
) -> Result<SupportedObjectKind, OperationError> {
    let file_type = metadata.file_type();
    if file_type.is_symlink()
        || file_type.is_fifo()
        || file_type.is_socket()
        || file_type.is_block_device()
        || file_type.is_char_device()
    {
        return Err(OperationError::UnsupportedFileType);
    }
    if metadata.is_file() {
        Ok(SupportedObjectKind::RegularFile)
    } else if metadata.is_dir() {
        Ok(SupportedObjectKind::Directory)
    } else {
        Err(OperationError::UnsupportedFileType)
    }
}

fn optional_supported_object_kind(
    parent: &Dir,
    leaf: &OsStr,
) -> Result<Option<SupportedObjectKind>, OperationError> {
    match parent.symlink_metadata(leaf) {
        Ok(metadata) => supported_object_kind(&metadata).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn random_internal_name(label: &str) -> OsString {
    let mut random = [0u8; 16];
    OsRng.fill_bytes(&mut random);
    let mut name = format!(".rustscale-taildrive-{label}-");
    for byte in random {
        use std::fmt::Write as _;
        let _ = write!(name, "{byte:02x}");
    }
    name.into()
}

fn create_staging_file(parent: &Dir, label: &str) -> Result<(OsString, File), OperationError> {
    for _ in 0..8 {
        let name = random_internal_name(label);
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        match parent.open_with(&name, &options) {
            Ok(file) => return Ok((name, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(OperationError::RepairRequired)
}

#[cfg(unix)]
struct PinnedObject {
    kind: SupportedObjectKind,
    dev: u64,
    ino: u64,
    _file: Option<File>,
    _directory: Option<Dir>,
}

#[cfg(unix)]
fn pin_supported_object(parent: &Dir, leaf: &OsStr) -> Result<PinnedObject, OperationError> {
    use cap_std::fs::MetadataExt as _;

    let metadata = parent.symlink_metadata(leaf)?;
    match supported_object_kind(&metadata)? {
        SupportedObjectKind::RegularFile => {
            let (file, metadata) = open_regular_at_nofollow_nonblocking(parent, leaf)?;
            Ok(PinnedObject {
                kind: SupportedObjectKind::RegularFile,
                dev: metadata.dev(),
                ino: metadata.ino(),
                _file: Some(file),
                _directory: None,
            })
        }
        SupportedObjectKind::Directory => {
            let directory = parent.open_dir_nofollow(leaf)?;
            let metadata = directory.dir_metadata()?;
            if supported_object_kind(&metadata)? != SupportedObjectKind::Directory {
                return Err(OperationError::UnsupportedFileType);
            }
            Ok(PinnedObject {
                kind: SupportedObjectKind::Directory,
                dev: metadata.dev(),
                ino: metadata.ino(),
                _file: None,
                _directory: Some(directory),
            })
        }
    }
}

#[cfg(unix)]
fn name_matches_pinned(
    parent: &Dir,
    leaf: &OsStr,
    pinned: &PinnedObject,
) -> Result<bool, OperationError> {
    use cap_std::fs::MetadataExt as _;

    let metadata = parent.symlink_metadata(leaf)?;
    Ok(supported_object_kind(&metadata)? == pinned.kind
        && metadata.dev() == pinned.dev
        && metadata.ino() == pinned.ino)
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn rename_noreplace(
    source_parent: &Dir,
    source: &OsStr,
    destination_parent: &Dir,
    destination: &OsStr,
) -> Result<(), OperationError> {
    rustix::fs::renameat_with(
        source_parent,
        source,
        destination_parent,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| OperationError::Io(error.into()))
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn rename_exchange(
    left_parent: &Dir,
    left: &OsStr,
    right_parent: &Dir,
    right: &OsStr,
) -> Result<(), OperationError> {
    rustix::fs::renameat_with(
        left_parent,
        left,
        right_parent,
        right,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|error| OperationError::Io(error.into()))
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn rename_noreplace(
    _source_parent: &Dir,
    _source: &OsStr,
    _destination_parent: &Dir,
    _destination: &OsStr,
) -> Result<(), OperationError> {
    Err(OperationError::TransactionalUnavailable)
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn rename_exchange(
    _left_parent: &Dir,
    _left: &OsStr,
    _right_parent: &Dir,
    _right: &OsStr,
) -> Result<(), OperationError> {
    Err(OperationError::TransactionalUnavailable)
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn owner_quarantine(parent: &Dir) -> Result<Dir, OperationError> {
    match parent.create_dir(QUARANTINE_DIRECTORY) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let directory = parent.open_dir_nofollow(QUARANTINE_DIRECTORY)?;
    use cap_std::fs::MetadataExt as _;
    if directory.dir_metadata()?.uid() != rustix::process::geteuid().as_raw() {
        return Err(OperationError::RepairRequired);
    }
    rustix::fs::fchmod(&directory, rustix::fs::Mode::RWXU)
        .map_err(|error| OperationError::Io(error.into()))?;
    Ok(directory)
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn owner_quarantine(_parent: &Dir) -> Result<Dir, OperationError> {
    Err(OperationError::TransactionalUnavailable)
}

fn rename_to_random_stage(
    source_parent: &Dir,
    source: &OsStr,
    destination_parent: &Dir,
    label: &str,
) -> Result<OsString, OperationError> {
    for _ in 0..8 {
        let staging = random_internal_name(label);
        match rename_noreplace(source_parent, source, destination_parent, &staging) {
            Ok(()) => return Ok(staging),
            Err(OperationError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(OperationError::RepairRequired)
}

fn quarantine_entry(parent: &Dir, entry: &OsStr, quarantine: &Dir) -> Result<(), OperationError> {
    rename_to_random_stage(parent, entry, quarantine, "repair")
        .map(drop)
        .map_err(|_| OperationError::RepairRequired)
}

fn restore_or_quarantine(
    staging_parent: &Dir,
    staging: &OsStr,
    original_parent: &Dir,
    original: &OsStr,
    quarantine: &Dir,
    restored_error: OperationError,
) -> OperationError {
    if rename_noreplace(staging_parent, staging, original_parent, original).is_ok() {
        restored_error
    } else {
        let _ = quarantine_entry(staging_parent, staging, quarantine);
        OperationError::RepairRequired
    }
}

#[cfg(unix)]
fn remove_pinned(
    parent: &Dir,
    leaf: &OsStr,
    pinned: &PinnedObject,
    quarantine: &Dir,
    control: Option<&RequestControl>,
) -> Result<(), OperationError> {
    // Atomically take the pathname out of the peer-writable share before the
    // final identity check. If a racer substituted anything, that object is
    // retained in the owner-only quarantine rather than unlinked.
    if let Some(control) = control {
        control.notify_before_isolation();
    }
    let isolated = rename_to_random_stage(parent, leaf, quarantine, "discard")?;
    if !matches!(name_matches_pinned(quarantine, &isolated, pinned), Ok(true)) {
        return Err(OperationError::RepairRequired);
    }
    let result = match pinned.kind {
        SupportedObjectKind::RegularFile => quarantine.remove_file(&isolated),
        SupportedObjectKind::Directory => quarantine.remove_dir(&isolated),
    };
    result.map_err(|_| OperationError::RepairRequired)
}

#[cfg(unix)]
fn safe_cleanup_regular(parent: &Dir, leaf: &OsStr) {
    if let (Ok(quarantine), Ok(pinned)) =
        (owner_quarantine(parent), pin_supported_object(parent, leaf))
    {
        if pinned.kind == SupportedObjectKind::RegularFile {
            let _ = remove_pinned(parent, leaf, &pinned, &quarantine, None);
        }
    }
}

#[cfg(not(unix))]
fn safe_cleanup_regular(_parent: &Dir, _leaf: &OsStr) {}

#[cfg(unix)]
fn rollback_exchange_or_quarantine(
    parent: &Dir,
    staging: &OsStr,
    destination: &OsStr,
    published: &PinnedObject,
    quarantine: &Dir,
    restored_error: OperationError,
) -> OperationError {
    if matches!(
        name_matches_pinned(parent, destination, published),
        Ok(true)
    ) && rename_exchange(parent, staging, parent, destination).is_ok()
    {
        restored_error
    } else {
        let _ = quarantine_entry(parent, staging, quarantine);
        let _ = quarantine_entry(parent, destination, quarantine);
        OperationError::RepairRequired
    }
}

#[cfg(unix)]
fn publish_regular_staging(
    parent: &Dir,
    staging: &OsStr,
    destination: &OsStr,
    control: &RequestControl,
) -> Result<(), OperationError> {
    let quarantine = owner_quarantine(parent)?;
    let published = pin_supported_object(parent, staging)?;
    if published.kind != SupportedObjectKind::RegularFile {
        return Err(OperationError::UnsupportedFileType);
    }
    match parent.symlink_metadata(destination) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            rename_noreplace(parent, staging, parent, destination)?;
            control.notify_after_transaction();
            if matches!(
                name_matches_pinned(parent, destination, &published),
                Ok(true)
            ) {
                Ok(())
            } else {
                let _ = quarantine_entry(parent, destination, &quarantine);
                Err(OperationError::RepairRequired)
            }
        }
        Err(error) => Err(error.into()),
        Ok(_) => {
            rename_exchange(parent, staging, parent, destination)?;
            control.notify_after_transaction();
            if !matches!(
                name_matches_pinned(parent, destination, &published),
                Ok(true)
            ) {
                let _ = quarantine_entry(parent, staging, &quarantine);
                let _ = quarantine_entry(parent, destination, &quarantine);
                return Err(OperationError::RepairRequired);
            }
            let displaced = match pin_supported_object(parent, staging) {
                Ok(pinned) if pinned.kind == SupportedObjectKind::RegularFile => pinned,
                Ok(_) => {
                    return Err(rollback_exchange_or_quarantine(
                        parent,
                        staging,
                        destination,
                        &published,
                        &quarantine,
                        OperationError::UnsupportedFileType,
                    ));
                }
                Err(error) => {
                    return Err(rollback_exchange_or_quarantine(
                        parent,
                        staging,
                        destination,
                        &published,
                        &quarantine,
                        error,
                    ));
                }
            };
            if let Err(error) =
                remove_pinned(parent, staging, &displaced, &quarantine, Some(control))
            {
                return Err(rollback_exchange_or_quarantine(
                    parent,
                    staging,
                    destination,
                    &published,
                    &quarantine,
                    error,
                ));
            }
            Ok(())
        }
    }
}

#[cfg(not(unix))]
fn publish_regular_staging(
    _parent: &Dir,
    _staging: &OsStr,
    _destination: &OsStr,
    _control: &RequestControl,
) -> Result<(), OperationError> {
    Err(OperationError::TransactionalUnavailable)
}

#[cfg(unix)]
fn transactional_delete(
    parent: &Dir,
    leaf: &OsStr,
    control: &RequestControl,
) -> Result<(), OperationError> {
    let quarantine = owner_quarantine(parent)?;
    let staging = rename_to_random_stage(parent, leaf, parent, "delete")?;
    control.notify_after_transaction();
    let pinned = match pin_supported_object(parent, &staging) {
        Ok(pinned) => pinned,
        Err(error) => {
            return Err(restore_or_quarantine(
                parent,
                &staging,
                parent,
                leaf,
                &quarantine,
                error,
            ));
        }
    };
    match remove_pinned(parent, &staging, &pinned, &quarantine, Some(control)) {
        Ok(()) => Ok(()),
        Err(OperationError::RepairRequired) => {
            let _ = quarantine_entry(parent, &staging, &quarantine);
            Err(OperationError::RepairRequired)
        }
        Err(error) => Err(restore_or_quarantine(
            parent,
            &staging,
            parent,
            leaf,
            &quarantine,
            error,
        )),
    }
}

#[cfg(not(unix))]
fn transactional_delete(
    _parent: &Dir,
    _leaf: &OsStr,
    _control: &RequestControl,
) -> Result<(), OperationError> {
    Err(OperationError::TransactionalUnavailable)
}

#[cfg(unix)]
fn transactional_move(
    source_parent: &Dir,
    source: &OsStr,
    destination_parent: &Dir,
    destination: &OsStr,
    allow_overwrite: bool,
    control: &RequestControl,
) -> Result<bool, OperationError> {
    let source_quarantine = owner_quarantine(source_parent)?;
    let destination_quarantine = owner_quarantine(destination_parent)?;

    // First isolate the exact source inode at an unpredictable internal name.
    // No destination path is touched until this inode is pinned and approved.
    let staging = rename_to_random_stage(source_parent, source, source_parent, "move")?;
    control.notify_after_transaction();
    let moved = match pin_supported_object(source_parent, &staging) {
        Ok(moved) => moved,
        Err(error) => {
            return Err(restore_or_quarantine(
                source_parent,
                &staging,
                source_parent,
                source,
                &source_quarantine,
                error,
            ));
        }
    };
    if source_parent.symlink_metadata(source).is_ok() {
        let _ = quarantine_entry(source_parent, &staging, &source_quarantine);
        return Err(OperationError::RepairRequired);
    }

    match destination_parent.symlink_metadata(destination) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Err(error) =
                rename_noreplace(source_parent, &staging, destination_parent, destination)
            {
                return Err(restore_or_quarantine(
                    source_parent,
                    &staging,
                    source_parent,
                    source,
                    &source_quarantine,
                    error,
                ));
            }
            if matches!(
                name_matches_pinned(destination_parent, destination, &moved),
                Ok(true)
            ) {
                Ok(false)
            } else {
                let _ = quarantine_entry(destination_parent, destination, &destination_quarantine);
                Err(OperationError::RepairRequired)
            }
        }
        Err(error) => Err(restore_or_quarantine(
            source_parent,
            &staging,
            source_parent,
            source,
            &source_quarantine,
            error.into(),
        )),
        Ok(_) if !allow_overwrite => Err(restore_or_quarantine(
            source_parent,
            &staging,
            source_parent,
            source,
            &source_quarantine,
            OperationError::PreconditionFailed,
        )),
        Ok(_) => {
            if let Err(error) =
                rename_exchange(source_parent, &staging, destination_parent, destination)
            {
                return Err(restore_or_quarantine(
                    source_parent,
                    &staging,
                    source_parent,
                    source,
                    &source_quarantine,
                    error,
                ));
            }
            if !matches!(
                name_matches_pinned(destination_parent, destination, &moved),
                Ok(true)
            ) {
                let _ = quarantine_entry(source_parent, &staging, &source_quarantine);
                let _ = quarantine_entry(destination_parent, destination, &destination_quarantine);
                return Err(OperationError::RepairRequired);
            }
            let displaced = match pin_supported_object(source_parent, &staging) {
                Ok(displaced) if displaced.kind == moved.kind => displaced,
                displaced => {
                    let error = displaced
                        .err()
                        .unwrap_or(OperationError::UnsupportedFileType);
                    if rename_exchange(source_parent, &staging, destination_parent, destination)
                        .is_err()
                    {
                        let _ = quarantine_entry(source_parent, &staging, &source_quarantine);
                        let _ = quarantine_entry(
                            destination_parent,
                            destination,
                            &destination_quarantine,
                        );
                        return Err(OperationError::RepairRequired);
                    }
                    return Err(restore_or_quarantine(
                        source_parent,
                        &staging,
                        source_parent,
                        source,
                        &source_quarantine,
                        error,
                    ));
                }
            };
            match remove_pinned(
                source_parent,
                &staging,
                &displaced,
                &source_quarantine,
                Some(control),
            ) {
                Ok(()) => Ok(true),
                Err(error) => {
                    if rename_exchange(source_parent, &staging, destination_parent, destination)
                        .is_err()
                    {
                        let _ = quarantine_entry(source_parent, &staging, &source_quarantine);
                        let _ = quarantine_entry(
                            destination_parent,
                            destination,
                            &destination_quarantine,
                        );
                        return Err(OperationError::RepairRequired);
                    }
                    Err(restore_or_quarantine(
                        source_parent,
                        &staging,
                        source_parent,
                        source,
                        &source_quarantine,
                        error,
                    ))
                }
            }
        }
    }
}

#[cfg(not(unix))]
fn transactional_move(
    _source_parent: &Dir,
    _source: &OsStr,
    _destination_parent: &Dir,
    _destination: &OsStr,
    _allow_overwrite: bool,
    _control: &RequestControl,
) -> Result<bool, OperationError> {
    Err(OperationError::TransactionalUnavailable)
}

fn open_regular_nofollow_nonblocking(
    dir: &Dir,
    relative: &Path,
) -> Result<(File, cap_std::fs::Metadata), OperationError> {
    let (parent, leaf) = open_parent_nofollow(dir, relative)?;
    open_regular_at_nofollow_nonblocking(&parent, &leaf)
}

fn open_regular_at_nofollow_nonblocking(
    parent: &Dir,
    leaf: &OsStr,
) -> Result<(File, cap_std::fs::Metadata), OperationError> {
    let before = parent.symlink_metadata(leaf)?;
    if before.file_type().is_symlink() {
        return Err(OperationError::Forbidden);
    }
    if !before.is_file() {
        return Err(OperationError::UnsupportedFileType);
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = parent.open_with(leaf, &options)?;
    let metadata = file.metadata()?;
    let file_type = metadata.file_type();
    if !metadata.is_file()
        || file_type.is_fifo()
        || file_type.is_socket()
        || file_type.is_block_device()
        || file_type.is_char_device()
        || file_type.is_symlink()
    {
        return Err(OperationError::UnsupportedFileType);
    }
    Ok((file, metadata))
}

fn atomic_write(
    parent: &Dir,
    destination: &OsStr,
    body: &[u8],
    control: &RequestControl,
) -> Result<(), OperationError> {
    let (temp, mut file) = create_staging_file(parent, "upload")?;
    let write_result = (|| {
        for chunk in body.chunks(64 * 1024) {
            control.check()?;
            file.write_all(chunk)?;
        }
        file.sync_all()?;
        #[cfg(test)]
        control.notify_after_sync();
        // Cancellation/deadline or epoch revocation after durable staging
        // must not publish the destination.
        drop(file);
        control.commit(|| publish_regular_staging(parent, &temp, destination, control))?;
        Ok(())
    })();
    if write_result.is_err() {
        safe_cleanup_regular(parent, &temp);
    }
    write_result
}

fn atomic_write_streaming(
    parent: &Dir,
    destination: &OsStr,
    mut body: StreamingBody,
    control: &RequestControl,
) -> Result<(), OperationError> {
    let (temp, mut file) = create_staging_file(parent, "stream")?;
    let write_result = (|| {
        let mut received = 0usize;
        while let Some(chunk) = body.receiver.blocking_recv() {
            control.check()?;
            received = received
                .checked_add(chunk.len())
                .ok_or(OperationError::RequestTooLarge)?;
            if received > body.expected_length {
                return Err(OperationError::RequestTooLarge);
            }
            file.write_all(&chunk)?;
        }
        if received != body.expected_length {
            return Err(OperationError::IncompleteBody);
        }
        file.sync_all()?;
        drop(file);
        control.commit(|| publish_regular_staging(parent, &temp, destination, control))?;
        Ok(())
    })();
    if write_result.is_err() {
        safe_cleanup_regular(parent, &temp);
    }
    write_result
}

#[derive(Clone)]
struct Property {
    href: String,
    display_name: String,
    directory: bool,
    length: u64,
}

fn propfind_root(
    peer: &AuthenticatedPeer,
    snapshot: &Snapshot,
    include_children: bool,
    limits: &Limits,
    control: &RequestControl,
) -> Result<Vec<u8>, OperationError> {
    let mut properties = vec![Property {
        href: "/".into(),
        display_name: String::new(),
        directory: true,
        length: 0,
    }];
    if include_children {
        for (name, root) in &snapshot.shares {
            control.check()?;
            if peer.permissions().for_share(name) == Permission::None {
                continue;
            }
            if properties.len() > limits.max_propfind_entries {
                return Err(OperationError::TooManyEntries);
            }
            properties.push(Property {
                href: href_for_components(std::slice::from_ref(name), true),
                display_name: root.share.name.clone(),
                directory: true,
                length: 0,
            });
        }
    }
    render_multistatus(&properties, limits)
}

fn propfind_share(
    root: &ShareRoot,
    parsed: &ParsedPath,
    include_children: bool,
    limits: &Limits,
    control: &RequestControl,
) -> Result<Vec<u8>, OperationError> {
    let (metadata, directory) = if parsed.relative.as_os_str().is_empty() {
        let directory = root.dir.try_clone()?;
        (directory.dir_metadata()?, Some(directory))
    } else {
        let (parent, leaf) = open_parent_nofollow(&root.dir, &parsed.relative)?;
        let metadata = parent.symlink_metadata(&leaf)?;
        if metadata.file_type().is_symlink() {
            return Err(OperationError::Forbidden);
        }
        if metadata.is_dir() {
            let directory = parent.open_dir_nofollow(&leaf)?;
            (directory.dir_metadata()?, Some(directory))
        } else {
            let (_, metadata) = open_regular_at_nofollow_nonblocking(&parent, &leaf)?;
            (metadata, None)
        }
    };
    let mut properties = vec![Property {
        href: href_for_components(&parsed.components, metadata.is_dir()),
        display_name: parsed.components.last().cloned().unwrap_or_default(),
        directory: metadata.is_dir(),
        length: metadata.len(),
    }];
    if include_children && metadata.is_dir() {
        let directory = directory.ok_or(OperationError::NotFound)?;
        for entry in directory.entries()? {
            control.check()?;
            if properties.len() > limits.max_propfind_entries {
                return Err(OperationError::TooManyEntries);
            }
            let entry = entry?;
            let file_type = entry.file_type()?;
            // Symlinks and non-UTF-8 names are deliberately invisible.
            if file_type.is_symlink() {
                continue;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if name.starts_with(".rustscale-taildrive-") {
                continue;
            }
            let metadata = entry.metadata()?;
            if !metadata.is_dir() && !metadata.is_file() {
                continue;
            }
            let mut components = parsed.components.clone();
            components.push(name.clone());
            properties.push(Property {
                href: href_for_components(&components, metadata.is_dir()),
                display_name: name,
                directory: metadata.is_dir(),
                length: metadata.len(),
            });
        }
    }
    render_multistatus(&properties, limits)
}

fn render_multistatus(properties: &[Property], limits: &Limits) -> Result<Vec<u8>, OperationError> {
    let mut xml =
        String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\">");
    for property in properties {
        use std::fmt::Write;
        let resource_type = if property.directory {
            "<D:collection/>"
        } else {
            ""
        };
        let _ = write!(
            xml,
            "<D:response><D:href>{}</D:href><D:propstat><D:prop><D:displayname>{}</D:displayname><D:resourcetype>{resource_type}</D:resourcetype><D:getcontentlength>{}</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
            xml_escape(&property.href),
            xml_escape(&property.display_name),
            property.length,
        );
        if xml.len() > limits.max_response_body {
            return Err(OperationError::ResponseTooLarge);
        }
    }
    xml.push_str("</D:multistatus>");
    Ok(xml.into_bytes())
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Debug)]
enum Interrupted {
    Cancelled,
    Deadline,
}

impl Interrupted {
    fn response(self) -> Response {
        match self {
            Self::Cancelled => Response::text(408, "request cancelled"),
            Self::Deadline => Response::text(408, "request deadline exceeded"),
        }
    }
}

#[derive(Debug)]
enum OperationError {
    Io(io::Error),
    Interrupted(Interrupted),
    BadRequest,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    UnsupportedFileType,
    #[cfg_attr(
        any(target_os = "linux", target_os = "android", target_vendor = "apple"),
        allow(dead_code)
    )]
    TransactionalUnavailable,
    RepairRequired,
    UnsupportedMediaType,
    PreconditionFailed,
    CrossShare,
    RequestTooLarge,
    IncompleteBody,
    ResponseTooLarge,
    TooManyEntries,
}

impl From<io::Error> for OperationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<Interrupted> for OperationError {
    fn from(error: Interrupted) -> Self {
        Self::Interrupted(error)
    }
}

impl OperationError {
    fn response(self) -> Response {
        match self {
            Self::Interrupted(interrupted) => interrupted.response(),
            Self::BadRequest => Response::text(400, "bad WebDAV request"),
            Self::Forbidden => Response::text(403, "permission denied"),
            Self::NotFound => Response::text(404, "not found"),
            Self::MethodNotAllowed => {
                Response::text(405, "method not allowed").header("allow", ALLOW)
            }
            Self::UnsupportedFileType => Response::text(403, "unsupported filesystem object"),
            Self::TransactionalUnavailable => Response::text(
                501,
                "safe conditional filesystem mutation is unavailable on this platform",
            ),
            Self::RepairRequired => Response::text(
                500,
                "filesystem race quarantined an object; owner repair is required",
            ),
            Self::UnsupportedMediaType => Response::text(415, "MKCOL body is not supported"),
            Self::PreconditionFailed => Response::text(412, "destination exists"),
            Self::CrossShare => Response::text(502, "cross-share operation is forbidden"),
            Self::RequestTooLarge => Response::text(413, "request body too large"),
            Self::IncompleteBody => Response::text(400, "incomplete request body"),
            Self::ResponseTooLarge => Response::text(507, "response exceeds configured limit"),
            Self::TooManyEntries => Response::text(507, "directory contains too many entries"),
            Self::Io(error) => match error.kind() {
                io::ErrorKind::NotFound => Response::text(404, "not found"),
                io::ErrorKind::AlreadyExists => Response::text(405, "destination exists"),
                io::ErrorKind::PermissionDenied => Response::text(403, "permission denied"),
                io::ErrorKind::DirectoryNotEmpty => Response::text(409, "directory is not empty"),
                _ => Response::text(500, "filesystem operation failed"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Share, CAPABILITY_TAILDRIVE};

    struct Harness {
        #[cfg_attr(windows, allow(dead_code))]
        temp: tempfile::TempDir,
        root: PathBuf,
        server: Server,
        read_only: AuthenticatedPeer,
        read_write: AuthenticatedPeer,
    }

    impl Harness {
        fn new() -> Self {
            Self::with_limits(Limits::default())
        }

        fn with_limits(limits: Limits) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root_alias = temp.path().join("share");
            std::fs::create_dir(&root_alias).unwrap();
            let root = std::fs::canonicalize(&root_alias).unwrap();
            std::fs::write(root.join("hello.txt"), b"hello").unwrap();
            let store = Arc::new(ConfigStore::new(limits.clone()));
            store
                .replace(true, vec![Share::new("docs", &root)])
                .unwrap();
            let read_only = AuthenticatedPeer::from_capability_grants(
                "nodekey:reader",
                &[br#"{"shares":["docs"],"access":"ro"}"#.to_vec()],
                &limits,
            )
            .unwrap();
            let read_write = AuthenticatedPeer::from_capability_grants(
                "nodekey:writer",
                &[br#"{"shares":["docs"],"access":"rw"}"#.to_vec()],
                &limits,
            )
            .unwrap();
            let _ = CAPABILITY_TAILDRIVE;
            Self {
                temp,
                root,
                server: Server::new(store),
                read_only,
                read_write,
            }
        }

        fn request(&self, peer: &AuthenticatedPeer, request: Request) -> Response {
            self.server.handle(
                peer,
                request,
                &RequestControl::new(
                    self.server.request_authority(),
                    Instant::now() + self.server.config.limits().request_timeout,
                ),
            )
        }
    }

    #[test]
    fn hermetic_webdav_client_server_round_trip() {
        let harness = Harness::new();
        let options = harness.request(&harness.read_only, Request::new("OPTIONS", "/"));
        assert_eq!(options.status, 200);
        assert_eq!(options.headers.get("dav").map(String::as_str), Some("1"));

        let listing = harness.request(
            &harness.read_only,
            Request::new("PROPFIND", "/docs/").with_header("Depth", "1"),
        );
        assert_eq!(listing.status, 207);
        let xml = String::from_utf8(listing.body).unwrap();
        assert!(xml.contains("/docs/hello.txt"));

        let get = harness.request(&harness.read_only, Request::new("GET", "/docs/hello.txt"));
        assert_eq!(get.status, 200);
        assert_eq!(get.body, b"hello");

        let put = harness.request(
            &harness.read_write,
            Request::new("PUT", "/docs/new.txt").with_body(b"new contents"),
        );
        assert_eq!(put.status, 201);
        assert_eq!(
            std::fs::read(harness.root.join("new.txt")).unwrap(),
            b"new contents"
        );

        let moved = harness.request(
            &harness.read_write,
            Request::new("MOVE", "/docs/new.txt").with_header("Destination", "/docs/renamed.txt"),
        );
        assert_eq!(moved.status, 201);
        assert!(!harness.root.join("new.txt").exists());
        assert!(harness.root.join("renamed.txt").exists());

        let deleted = harness.request(
            &harness.read_write,
            Request::new("DELETE", "/docs/renamed.txt"),
        );
        assert_eq!(deleted.status, 204);
        assert!(!harness.root.join("renamed.txt").exists());
    }

    #[test]
    fn permissions_and_share_existence_fail_closed() {
        let harness = Harness::new();
        let denied = harness.request(
            &harness.read_only,
            Request::new("PUT", "/docs/no.txt").with_body(b"no"),
        );
        assert_eq!(denied.status, 403);
        let ungranted = AuthenticatedPeer::from_capability_grants(
            "nodekey:none",
            &[],
            harness.server.config.limits(),
        )
        .unwrap();
        assert_eq!(
            harness
                .request(&ungranted, Request::new("GET", "/docs/hello.txt"))
                .status,
            404
        );
        assert_eq!(
            harness
                .request(&harness.read_write, Request::new("GET", "/missing/file"))
                .status,
            404
        );
    }

    #[cfg(unix)]
    #[test]
    fn traversal_and_symlink_escape_are_blocked() {
        use std::os::unix::fs::symlink;
        let harness = Harness::new();
        let outside = harness.temp.path().join("outside.txt");
        std::fs::write(&outside, b"secret").unwrap();
        symlink(&outside, harness.root.join("escape")).unwrap();
        for path in [
            "/docs/../outside.txt",
            "/docs/%2e%2e/outside.txt",
            "/docs/%2Fetc/passwd",
            "/docs/escape",
        ] {
            let response = harness.request(&harness.read_only, Request::new("GET", path));
            assert!(
                matches!(response.status, 400 | 403),
                "{path}: {}",
                response.status
            );
            assert_ne!(response.body, b"secret");
        }
        let listing = harness.request(
            &harness.read_only,
            Request::new("PROPFIND", "/docs/").with_header("Depth", "1"),
        );
        assert!(!String::from_utf8(listing.body).unwrap().contains("escape"));
    }

    #[test]
    fn oversized_cancelled_and_expired_requests_do_not_write() {
        let harness = Harness::new();
        let oversized = harness.request(
            &harness.read_write,
            Request::new("PUT", "/docs/large").with_body(vec![
                0;
                harness
                    .server
                    .config
                    .limits()
                    .max_request_body
                    + 1
            ]),
        );
        assert_eq!(oversized.status, 413);

        let authority = harness.server.request_authority();
        authority.cancellation().cancel();
        let cancelled = harness.server.handle(
            &harness.read_write,
            Request::new("PUT", "/docs/cancelled").with_body(b"no"),
            &RequestControl::new(
                authority,
                Instant::now() + std::time::Duration::from_secs(1),
            ),
        );
        assert_eq!(cancelled.status, 408);
        assert!(!harness.root.join("cancelled").exists());

        let expired = harness.server.handle(
            &harness.read_write,
            Request::new("PUT", "/docs/expired").with_body(b"no"),
            &RequestControl::new(harness.server.request_authority(), Instant::now()),
        );
        assert_eq!(expired.status, 408);
        assert!(!harness.root.join("expired").exists());
    }

    #[test]
    fn cancellation_after_sync_never_publishes_temp_file() {
        let harness = Harness::new();
        let authority = harness.server.request_authority();
        let hook_cancellation = authority.cancellation();
        let control = RequestControl::new(authority, Instant::now() + Duration::from_secs(2))
            .with_after_sync(Arc::new(move || hook_cancellation.cancel()));
        let response = harness.server.handle(
            &harness.read_write,
            Request::new("PUT", "/docs/not-published").with_body(b"durable temp only"),
            &control,
        );
        assert_eq!(response.status, 408);
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let entries = std::fs::read_dir(&harness.root)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            if !entries.iter().any(|name| {
                let name = name.to_string_lossy();
                name.starts_with(".rustscale-taildrive-") && name != QUARANTINE_DIRECTORY
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "temporary upload was not cleaned"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let quarantine = harness.root.join(QUARANTINE_DIRECTORY);
        if quarantine.exists() {
            assert!(std::fs::read_dir(quarantine).unwrap().next().is_none());
        }
        assert!(!harness.root.join("not-published").exists());
    }

    #[cfg(unix)]
    #[test]
    fn fifo_and_socket_sources_are_rejected_without_blocking_workers() {
        use std::os::unix::net::UnixListener;
        use std::process::Command;

        let harness = Harness::new();
        let fifo = harness.root.join("pipe");
        let status = Command::new("mkfifo").arg(&fifo).status().unwrap();
        assert!(status.success());
        let _socket = UnixListener::bind(harness.root.join("socket")).unwrap();

        for name in ["pipe", "socket"] {
            let started = Instant::now();
            let get = harness.request(
                &harness.read_only,
                Request::new("GET", format!("/docs/{name}")),
            );
            assert_eq!(get.status, 403);
            assert!(started.elapsed() < Duration::from_secs(1));
            let copy = harness.request(
                &harness.read_write,
                Request::new("COPY", format!("/docs/{name}"))
                    .with_header("Destination", format!("/docs/{name}-copy")),
            );
            assert_eq!(copy.status, 403);
            let put = harness.request(
                &harness.read_write,
                Request::new("PUT", format!("/docs/{name}")).with_body(b"replacement"),
            );
            assert_eq!(put.status, 403);
            let delete = harness.request(
                &harness.read_write,
                Request::new("DELETE", format!("/docs/{name}")),
            );
            assert_eq!(delete.status, 403);
            let move_source = harness.request(
                &harness.read_write,
                Request::new("MOVE", format!("/docs/{name}"))
                    .with_header("Destination", format!("/docs/{name}-moved")),
            );
            assert_eq!(move_source.status, 403);
            let move_destination = harness.request(
                &harness.read_write,
                Request::new("MOVE", "/docs/hello.txt")
                    .with_header("Destination", format!("/docs/{name}")),
            );
            assert_eq!(move_destination.status, 403);
            assert!(harness.root.join(name).exists());
            assert!(harness.root.join("hello.txt").exists());
            assert!(!harness.root.join(format!("{name}-copy")).exists());
            assert!(!harness.root.join(format!("{name}-moved")).exists());
            assert!(started.elapsed() < Duration::from_secs(1));
        }
    }

    #[cfg(unix)]
    #[test]
    fn special_object_swaps_at_publication_are_rejected_untouched() {
        use std::os::unix::net::UnixListener;

        let harness = Harness::new();
        let swap_to_socket = |name: &'static str| {
            let path = harness.root.join(name);
            std::fs::write(&path, b"ordinary").unwrap();
            let held = Arc::new(Mutex::new(None));
            let hook_held = held.clone();
            let hook_path = path.clone();
            let control = RequestControl::new(
                harness.server.request_authority(),
                Instant::now() + Duration::from_secs(2),
            )
            .with_before_commit(Arc::new(move || {
                std::fs::remove_file(&hook_path).unwrap();
                *hook_held.lock().unwrap() = Some(UnixListener::bind(&hook_path).unwrap());
            }));
            (path, held, control)
        };

        let (put_path, put_socket, put_control) = swap_to_socket("race-put");
        let put = harness.server.handle(
            &harness.read_write,
            Request::new("PUT", "/docs/race-put").with_body(b"replacement"),
            &put_control,
        );
        assert_eq!(put.status, 403);
        assert!(put_socket.lock().unwrap().is_some());
        assert!(put_path.exists());

        let (delete_path, delete_socket, delete_control) = swap_to_socket("race-delete");
        let delete = harness.server.handle(
            &harness.read_write,
            Request::new("DELETE", "/docs/race-delete"),
            &delete_control,
        );
        assert_eq!(delete.status, 403);
        assert!(delete_socket.lock().unwrap().is_some());
        assert!(delete_path.exists());

        std::fs::write(harness.root.join("race-move-source"), b"source").unwrap();
        let (destination_path, destination_socket, destination_control) =
            swap_to_socket("race-move-destination");
        let move_destination = harness.server.handle(
            &harness.read_write,
            Request::new("MOVE", "/docs/race-move-source")
                .with_header("Destination", "/docs/race-move-destination"),
            &destination_control,
        );
        assert_eq!(move_destination.status, 403);
        assert!(destination_socket.lock().unwrap().is_some());
        assert!(destination_path.exists());
        assert!(harness.root.join("race-move-source").exists());

        let (source_path, source_socket, source_control) = swap_to_socket("race-source-swap");
        let move_source = harness.server.handle(
            &harness.read_write,
            Request::new("MOVE", "/docs/race-source-swap")
                .with_header("Destination", "/docs/race-source-destination"),
            &source_control,
        );
        assert_eq!(move_source.status, 403);
        assert!(source_socket.lock().unwrap().is_some());
        assert!(source_path.exists());
        assert!(!harness.root.join("race-source-destination").exists());
    }

    #[cfg(unix)]
    #[test]
    fn exact_post_rename_special_swap_is_restored_without_unlink() {
        use std::os::unix::fs::MetadataExt as _;
        use std::process::Command;

        let harness = Harness::new();
        std::fs::write(harness.root.join("exact-race"), b"regular").unwrap();
        let raced = Arc::new(Mutex::new(None));
        let hook_raced = raced.clone();
        let hook_root = harness.root.clone();
        let control = RequestControl::new(
            harness.server.request_authority(),
            Instant::now() + Duration::from_secs(2),
        )
        .with_after_transaction(Arc::new(move || {
            let staging = std::fs::read_dir(&hook_root)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".rustscale-taildrive-delete-")
                })
                .unwrap();
            std::fs::remove_file(&staging).unwrap();
            assert!(Command::new("mkfifo")
                .arg(&staging)
                .status()
                .unwrap()
                .success());
            let inode = std::fs::symlink_metadata(&staging).unwrap().ino();
            *hook_raced.lock().unwrap() = Some(inode);
        }));

        let response = harness.server.handle(
            &harness.read_write,
            Request::new("DELETE", "/docs/exact-race"),
            &control,
        );
        assert_eq!(response.status, 403);
        let victim = harness.root.join("exact-race");
        let metadata = std::fs::symlink_metadata(&victim).unwrap();
        assert!(metadata.file_type().is_fifo());
        assert_eq!(metadata.ino(), raced.lock().unwrap().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn exact_post_inspection_swap_is_quarantined_without_unlink() {
        use std::os::unix::fs::MetadataExt as _;
        use std::process::Command;

        let harness = Harness::new();
        std::fs::write(harness.root.join("isolation-race"), b"regular").unwrap();
        let raced_inode = Arc::new(Mutex::new(None));
        let hook_inode = raced_inode.clone();
        let hook_root = harness.root.clone();
        let control = RequestControl::new(
            harness.server.request_authority(),
            Instant::now() + Duration::from_secs(2),
        )
        .with_before_isolation(Arc::new(move || {
            let staging = std::fs::read_dir(&hook_root)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".rustscale-taildrive-delete-")
                })
                .unwrap();
            std::fs::remove_file(&staging).unwrap();
            assert!(Command::new("mkfifo")
                .arg(&staging)
                .status()
                .unwrap()
                .success());
            *hook_inode.lock().unwrap() = Some(std::fs::symlink_metadata(staging).unwrap().ino());
        }));

        let response = harness.server.handle(
            &harness.read_write,
            Request::new("DELETE", "/docs/isolation-race"),
            &control,
        );
        assert_eq!(response.status, 500);
        assert!(!harness.root.join("isolation-race").exists());
        let entries = std::fs::read_dir(harness.root.join(QUARANTINE_DIRECTORY))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        let metadata = std::fs::symlink_metadata(&entries[0]).unwrap();
        assert!(metadata.file_type().is_fifo());
        assert_eq!(metadata.ino(), raced_inode.lock().unwrap().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn unrestorable_special_object_is_retained_in_owner_quarantine() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        use std::os::unix::net::UnixListener;

        let harness = Harness::new();
        let victim = harness.root.join("quarantine-race");
        let original = UnixListener::bind(&victim).unwrap();
        let original_inode = std::fs::symlink_metadata(&victim).unwrap().ino();
        let replacement = Arc::new(Mutex::new(None));
        let hook_replacement = replacement.clone();
        let hook_victim = victim.clone();
        let control = RequestControl::new(
            harness.server.request_authority(),
            Instant::now() + Duration::from_secs(2),
        )
        .with_after_transaction(Arc::new(move || {
            *hook_replacement.lock().unwrap() = Some(UnixListener::bind(&hook_victim).unwrap());
        }));

        let response = harness.server.handle(
            &harness.read_write,
            Request::new("DELETE", "/docs/quarantine-race"),
            &control,
        );
        assert_eq!(response.status, 500);
        assert!(String::from_utf8_lossy(&response.body).contains("owner repair"));
        assert!(replacement.lock().unwrap().is_some());
        assert!(victim.exists(), "raced-in replacement was altered");

        let quarantine = harness.root.join(QUARANTINE_DIRECTORY);
        assert_eq!(
            std::fs::metadata(&quarantine).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let entries = std::fs::read_dir(&quarantine)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        let quarantined = std::fs::symlink_metadata(&entries[0]).unwrap();
        assert_eq!(quarantined.ino(), original_inode);
        assert!(quarantined.file_type().is_socket());
        drop(original);
    }

    fn paused_before_commit(
        server: &Server,
    ) -> (
        RequestControl,
        std::sync::mpsc::Receiver<()>,
        Arc<(Mutex<bool>, std::sync::Condvar)>,
    ) {
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let entered_tx = Mutex::new(Some(entered_tx));
        let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let hook_release = release.clone();
        let control = RequestControl::new(
            server.request_authority(),
            Instant::now() + Duration::from_secs(5),
        )
        .with_before_commit(Arc::new(move || {
            if let Some(sender) = entered_tx.lock().unwrap().take() {
                sender.send(()).unwrap();
            }
            let (lock, condition) = &*hook_release;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = condition.wait(released).unwrap();
            }
        }));
        (control, entered_rx, release)
    }

    fn revoke_then_release(
        server: &Server,
        entered: std::sync::mpsc::Receiver<()>,
        release: &Arc<(Mutex<bool>, std::sync::Condvar)>,
    ) {
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        server.revoke_authority();
        let (lock, condition) = &**release;
        *lock.lock().unwrap() = true;
        condition.notify_all();
    }

    #[test]
    fn revocation_linearizes_every_webdav_publication() {
        let harness = Harness::new();

        // Buffered PUT stages fully, but its old epoch cannot rename.
        let (control, entered, release) = paused_before_commit(&harness.server);
        let server = harness.server.clone();
        let peer = harness.read_write.clone();
        let worker = std::thread::spawn(move || {
            server.handle(
                &peer,
                Request::new("PUT", "/docs/blocked-put").with_body(b"old"),
                &control,
            )
        });
        revoke_then_release(&harness.server, entered, &release);
        assert_eq!(worker.join().unwrap().status, 408);
        assert!(!harness.root.join("blocked-put").exists());
        assert_eq!(
            harness
                .request(
                    &harness.read_write,
                    Request::new("PUT", "/docs/blocked-put").with_body(b"new"),
                )
                .status,
            201
        );

        // Streaming PUT has the same guarded publication after bounded staging.
        let (control, entered, release) = paused_before_commit(&harness.server);
        let (sender, body) = streaming_body_channel(3, 1);
        sender.try_send(b"old".to_vec()).unwrap();
        drop(sender);
        let server = harness.server.clone();
        let peer = harness.read_write.clone();
        let worker = std::thread::spawn(move || {
            server.handle_streaming_put(
                &peer,
                Request::new("PUT", "/docs/blocked-stream"),
                body,
                &control,
            )
        });
        revoke_then_release(&harness.server, entered, &release);
        assert_eq!(worker.join().unwrap().status, 408);
        assert!(!harness.root.join("blocked-stream").exists());
        let (sender, body) = streaming_body_channel(3, 1);
        sender.try_send(b"new".to_vec()).unwrap();
        drop(sender);
        let response = harness.server.handle_streaming_put(
            &harness.read_write,
            Request::new("PUT", "/docs/blocked-stream"),
            body,
            &RequestControl::new(
                harness.server.request_authority(),
                Instant::now() + Duration::from_secs(2),
            ),
        );
        assert_eq!(response.status, 201);

        // MKCOL cannot create after the old epoch is revoked.
        let (control, entered, release) = paused_before_commit(&harness.server);
        let server = harness.server.clone();
        let peer = harness.read_write.clone();
        let worker = std::thread::spawn(move || {
            server.handle(&peer, Request::new("MKCOL", "/docs/blocked-dir"), &control)
        });
        revoke_then_release(&harness.server, entered, &release);
        assert_eq!(worker.join().unwrap().status, 408);
        assert!(!harness.root.join("blocked-dir").exists());
        assert_eq!(
            harness
                .request(
                    &harness.read_write,
                    Request::new("MKCOL", "/docs/blocked-dir"),
                )
                .status,
            201
        );

        // DELETE cannot remove the pre-opened object after revocation.
        std::fs::write(harness.root.join("blocked-delete"), b"keep").unwrap();
        let (control, entered, release) = paused_before_commit(&harness.server);
        let server = harness.server.clone();
        let peer = harness.read_write.clone();
        let worker = std::thread::spawn(move || {
            server.handle(
                &peer,
                Request::new("DELETE", "/docs/blocked-delete"),
                &control,
            )
        });
        revoke_then_release(&harness.server, entered, &release);
        assert_eq!(worker.join().unwrap().status, 408);
        assert!(harness.root.join("blocked-delete").exists());
        assert_eq!(
            harness
                .request(
                    &harness.read_write,
                    Request::new("DELETE", "/docs/blocked-delete"),
                )
                .status,
            204
        );

        // MOVE cannot publish the destination or remove the source.
        std::fs::write(harness.root.join("blocked-move-src"), b"move").unwrap();
        let move_request = Request::new("MOVE", "/docs/blocked-move-src")
            .with_header("Destination", "/docs/blocked-move-dst");
        let (control, entered, release) = paused_before_commit(&harness.server);
        let server = harness.server.clone();
        let peer = harness.read_write.clone();
        let old_move = move_request.clone();
        let worker = std::thread::spawn(move || server.handle(&peer, old_move, &control));
        revoke_then_release(&harness.server, entered, &release);
        assert_eq!(worker.join().unwrap().status, 408);
        assert!(harness.root.join("blocked-move-src").exists());
        assert!(!harness.root.join("blocked-move-dst").exists());
        assert_eq!(
            harness.request(&harness.read_write, move_request).status,
            201
        );

        // COPY staging cannot publish its destination after revocation.
        std::fs::write(harness.root.join("blocked-copy-src"), b"copy").unwrap();
        let copy_request = Request::new("COPY", "/docs/blocked-copy-src")
            .with_header("Destination", "/docs/blocked-copy-dst");
        let (control, entered, release) = paused_before_commit(&harness.server);
        let server = harness.server.clone();
        let peer = harness.read_write.clone();
        let old_copy = copy_request.clone();
        let worker = std::thread::spawn(move || server.handle(&peer, old_copy, &control));
        revoke_then_release(&harness.server, entered, &release);
        assert_eq!(worker.join().unwrap().status, 408);
        assert!(!harness.root.join("blocked-copy-dst").exists());
        assert_eq!(
            harness.request(&harness.read_write, copy_request).status,
            201
        );
        assert_eq!(
            std::fs::read(harness.root.join("blocked-copy-dst")).unwrap(),
            b"copy"
        );
        assert!(!std::fs::read_dir(&harness.root).unwrap().any(|entry| {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            name.starts_with(".rustscale-taildrive-") && name != QUARANTINE_DIRECTORY
        }));
        let quarantine = harness.root.join(QUARANTINE_DIRECTORY);
        if quarantine.exists() {
            assert!(std::fs::read_dir(quarantine).unwrap().next().is_none());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn many_max_sized_puts_stream_through_bounded_queues() {
        const REQUESTS: usize = 8;
        const BODY_SIZE: usize = 16 * 1024 * 1024;
        const CHUNK_SIZE: usize = 64 * 1024;

        let harness = Harness::new();
        let mut workers = Vec::new();
        let mut producers = Vec::new();
        for index in 0..REQUESTS {
            let (sender, body) = streaming_body_channel(BODY_SIZE, 2);
            let server = harness.server.clone();
            let peer = harness.read_write.clone();
            workers.push(tokio::task::spawn_blocking(move || {
                server.handle_streaming_put(
                    &peer,
                    Request::new("PUT", format!("/docs/stress-{index}.bin")),
                    body,
                    &RequestControl::new(
                        server.request_authority(),
                        Instant::now() + server.config.limits().request_timeout,
                    ),
                )
            }));
            producers.push(tokio::spawn(async move {
                for _ in 0..BODY_SIZE / CHUNK_SIZE {
                    if sender.send(vec![0x5a; CHUNK_SIZE]).await.is_err() {
                        break;
                    }
                }
            }));
        }
        for producer in producers {
            producer.await.unwrap();
        }
        for (index, worker) in workers.into_iter().enumerate() {
            assert_eq!(worker.await.unwrap().status, 201);
            assert_eq!(
                std::fs::metadata(harness.root.join(format!("stress-{index}.bin")))
                    .unwrap()
                    .len(),
                BODY_SIZE as u64
            );
        }
    }

    #[test]
    fn filesystem_worker_pool_has_a_hard_queue_bound() {
        let pool = WorkerPool::new(1, 1);
        let (started_sender, started_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        pool.try_execute(Box::new(move || {
            started_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
        }))
        .unwrap();
        started_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        pool.try_execute(Box::new(|| {})).unwrap();
        assert!(matches!(
            pool.try_execute(Box::new(|| {})),
            Err(TrySendError::Full(_))
        ));
        release_sender.send(()).unwrap();
    }

    #[test]
    fn destination_cannot_turn_server_into_deputy() {
        let harness = Harness::new();
        for destination in ["http://attacker.invalid/x", "/docs/../x", "/other/x"] {
            let response = harness.request(
                &harness.read_write,
                Request::new("COPY", "/docs/hello.txt").with_header("Destination", destination),
            );
            assert!(matches!(response.status, 400 | 502));
        }
    }
}
