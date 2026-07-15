use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cap_fs_ext::{DirExt, FileTypeExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsSyncExt};
use cap_std::fs::{Dir, File, OpenOptions};
use tokio_util::sync::CancellationToken;

use crate::auth::{AuthenticatedPeer, Permission};
use crate::config::{ConfigStore, Limits, ShareRoot, Snapshot};
use crate::path::{href_for_components, parse_request_path, ParsedPath};

const ALLOW: &str = "OPTIONS, GET, HEAD, PROPFIND, PUT, MKCOL, DELETE, MOVE, COPY";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub type HeaderMap = BTreeMap<String, String>;

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

/// Per-request cancellation and deadline supplied by the connection adapter.
#[derive(Clone)]
pub struct RequestControl {
    cancellation: CancellationToken,
    deadline: Instant,
    #[cfg(test)]
    after_sync: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl RequestControl {
    pub fn new(cancellation: CancellationToken, deadline: Instant) -> Self {
        Self {
            cancellation,
            deadline,
            #[cfg(test)]
            after_sync: None,
        }
    }

    pub fn for_limits(limits: &Limits) -> Self {
        Self {
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + limits.request_timeout,
            #[cfg(test)]
            after_sync: None,
        }
    }

    fn check(&self) -> Result<(), Interrupted> {
        if self.cancellation.is_cancelled() {
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

    #[cfg(test)]
    fn with_after_sync(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.after_sync = Some(hook);
        self
    }

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
            .field("cancelled", &self.cancellation.is_cancelled())
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
}

impl Server {
    pub fn new(config: Arc<ConfigStore>) -> Self {
        let workers = Arc::new(WorkerPool::new(
            config.limits().filesystem_workers,
            config.limits().filesystem_queue,
        ));
        Self { config, workers }
    }

    /// Handle one request using one immutable configuration snapshot.
    ///
    /// `peer` must have been produced from the authenticated connection's
    /// netmap node and capability values, never from HTTP request data.
    pub fn handle(
        &self,
        peer: &AuthenticatedPeer,
        request: Request,
        control: &RequestControl,
    ) -> Response {
        if let Err(interrupted) = control.check() {
            return interrupted.response();
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let server = self.clone();
        let peer = peer.clone();
        let worker_control = control.clone();
        let job = Box::new(move || {
            let response = server.handle_on_worker(&peer, request, &worker_control);
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
        control: &RequestControl,
    ) -> Response {
        if let Err(interrupted) = control.check() {
            return interrupted.response();
        }
        let limits = self.config.limits();
        if request.body.len() > limits.max_request_body {
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
            "PUT" => Self::put(root, &parsed, &request.body, control),
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
            Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_dir() => {
                return Err(OperationError::Forbidden)
            }
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        atomic_write(&parent, &leaf, body, control)?;
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
        control.check()?;
        parent.create_dir(&leaf)?;
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
        let metadata = parent.symlink_metadata(&leaf)?;
        if metadata.file_type().is_symlink() {
            return Err(OperationError::Forbidden);
        }
        control.check()?;
        if metadata.is_dir() {
            // Deliberately avoid recursive deletion in this bounded slice.
            parent.remove_dir(&leaf)?;
        } else {
            parent.remove_file(&leaf)?;
        }
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
        let source_metadata = source_parent.symlink_metadata(&source_leaf)?;
        if source_metadata.file_type().is_symlink() {
            return Err(OperationError::Forbidden);
        }
        let destination_exists = destination_parent
            .symlink_metadata(&destination_leaf)
            .map_or_else(
                |error| {
                    if error.kind() == io::ErrorKind::NotFound {
                        Ok(false)
                    } else {
                        Err(error.into())
                    }
                },
                |metadata| {
                    if metadata.file_type().is_symlink() {
                        Err(OperationError::Forbidden)
                    } else {
                        Ok(true)
                    }
                },
            )?;
        if destination_exists && request.header("overwrite") == Some("F") {
            return Err(OperationError::PreconditionFailed);
        }

        if copy {
            let (mut source_file, metadata) =
                open_regular_at_nofollow_nonblocking(&source_parent, &source_leaf)?;
            let size =
                usize::try_from(metadata.len()).map_err(|_| OperationError::ResponseTooLarge)?;
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
        } else {
            control.check()?;
            source_parent.rename(&source_leaf, &destination_parent, &destination_leaf)?;
        }
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
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = OsString::from(format!(
        ".rustscale-taildrive-{}-{sequence}.tmp",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut file = parent.open_with(&temp, &options)?;
    let write_result = (|| {
        for chunk in body.chunks(64 * 1024) {
            control.check()?;
            file.write_all(chunk)?;
        }
        file.sync_all()?;
        #[cfg(test)]
        control.notify_after_sync();
        // Cancellation/deadline after durable temp-file creation must not
        // publish the destination.
        control.check()?;
        drop(file);
        parent.rename(&temp, parent, destination)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = parent.remove_file(&temp);
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
    UnsupportedMediaType,
    PreconditionFailed,
    CrossShare,
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
            Self::UnsupportedMediaType => Response::text(415, "MKCOL body is not supported"),
            Self::PreconditionFailed => Response::text(412, "destination exists"),
            Self::CrossShare => Response::text(502, "cross-share operation is forbidden"),
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
                &RequestControl::for_limits(self.server.config.limits()),
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

        let token = CancellationToken::new();
        token.cancel();
        let cancelled = harness.server.handle(
            &harness.read_write,
            Request::new("PUT", "/docs/cancelled").with_body(b"no"),
            &RequestControl::new(token, Instant::now() + std::time::Duration::from_secs(1)),
        );
        assert_eq!(cancelled.status, 408);
        assert!(!harness.root.join("cancelled").exists());

        let expired = harness.server.handle(
            &harness.read_write,
            Request::new("PUT", "/docs/expired").with_body(b"no"),
            &RequestControl::new(CancellationToken::new(), Instant::now()),
        );
        assert_eq!(expired.status, 408);
        assert!(!harness.root.join("expired").exists());
    }

    #[test]
    fn cancellation_after_sync_never_publishes_temp_file() {
        let harness = Harness::new();
        let cancellation = CancellationToken::new();
        let hook_cancellation = cancellation.clone();
        let control = RequestControl::new(cancellation, Instant::now() + Duration::from_secs(2))
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
            if !entries
                .iter()
                .any(|name| name.to_string_lossy().starts_with(".rustscale-taildrive-"))
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "temporary upload was not cleaned"
            );
            std::thread::sleep(Duration::from_millis(5));
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
            assert!(started.elapsed() < Duration::from_secs(1));
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
