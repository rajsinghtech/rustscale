use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use cap_std::fs::{Dir, OpenOptions};
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
#[derive(Clone, Debug)]
pub struct RequestControl {
    cancellation: CancellationToken,
    deadline: Instant,
}

impl RequestControl {
    pub fn new(cancellation: CancellationToken, deadline: Instant) -> Self {
        Self {
            cancellation,
            deadline,
        }
    }

    pub fn for_limits(limits: &Limits) -> Self {
        Self {
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + limits.request_timeout,
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
}

#[derive(Clone)]
pub struct Server {
    config: Arc<ConfigStore>,
}

impl Server {
    pub fn new(config: Arc<ConfigStore>) -> Self {
        Self { config }
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
            "MKCOL" => Self::mkcol(root, &parsed, &request.body),
            "DELETE" => Self::delete(root, &parsed),
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
        ensure_no_symlinks(&root.dir, &parsed.relative, false)?;
        let mut file = root.dir.open(&parsed.relative)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(OperationError::MethodNotAllowed);
        }
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
        ensure_no_symlinks(&root.dir, &parsed.relative, true)?;
        let existed = match root.dir.symlink_metadata(&parsed.relative) {
            Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_dir() => {
                return Err(OperationError::Forbidden)
            }
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        atomic_write(&root.dir, &parsed.relative, body, control)?;
        Ok(Response::new(if existed { 204 } else { 201 }).header("content-length", "0"))
    }

    fn mkcol(
        root: &ShareRoot,
        parsed: &ParsedPath,
        body: &[u8],
    ) -> Result<Response, OperationError> {
        if parsed.relative.as_os_str().is_empty() {
            return Err(OperationError::MethodNotAllowed);
        }
        if !body.is_empty() {
            return Err(OperationError::UnsupportedMediaType);
        }
        ensure_no_symlinks(&root.dir, &parsed.relative, true)?;
        root.dir.create_dir(&parsed.relative)?;
        Ok(Response::new(201).header("content-length", "0"))
    }

    fn delete(root: &ShareRoot, parsed: &ParsedPath) -> Result<Response, OperationError> {
        if parsed.relative.as_os_str().is_empty() {
            return Err(OperationError::Forbidden);
        }
        ensure_no_symlinks(&root.dir, &parsed.relative, false)?;
        let metadata = root.dir.symlink_metadata(&parsed.relative)?;
        if metadata.file_type().is_symlink() {
            return Err(OperationError::Forbidden);
        }
        if metadata.is_dir() {
            // Deliberately avoid recursive deletion in this bounded slice.
            root.dir.remove_dir(&parsed.relative)?;
        } else {
            root.dir.remove_file(&parsed.relative)?;
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
        ensure_no_symlinks(&source_root.dir, &source.relative, false)?;
        ensure_no_symlinks(&destination_root.dir, &destination.relative, true)?;
        let destination_exists = destination_root
            .dir
            .symlink_metadata(&destination.relative)
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
            let metadata = source_root.dir.symlink_metadata(&source.relative)?;
            if !metadata.is_file() {
                return Err(OperationError::MethodNotAllowed);
            }
            let size =
                usize::try_from(metadata.len()).map_err(|_| OperationError::ResponseTooLarge)?;
            if size > self.config.limits().max_response_body {
                return Err(OperationError::ResponseTooLarge);
            }
            let mut source_file = source_root.dir.open(&source.relative)?;
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
            atomic_write(
                &destination_root.dir,
                &destination.relative,
                &bytes,
                control,
            )?;
        } else {
            source_root.dir.rename(
                &source.relative,
                &destination_root.dir,
                &destination.relative,
            )?;
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

fn ensure_no_symlinks(
    dir: &Dir,
    relative: &Path,
    allow_missing_leaf: bool,
) -> Result<(), OperationError> {
    let components = relative.components().collect::<Vec<_>>();
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        match dir.symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(OperationError::Forbidden);
                }
                if index + 1 < components.len() && !metadata.is_dir() {
                    return Err(OperationError::NotFound);
                }
            }
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && allow_missing_leaf
                    && index + 1 == components.len() =>
            {
                return Ok(())
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn atomic_write(
    dir: &Dir,
    destination: &Path,
    body: &[u8],
    control: &RequestControl,
) -> Result<(), OperationError> {
    let parent = destination.parent().unwrap_or_else(|| Path::new(""));
    let leaf = destination.file_name().ok_or(OperationError::BadRequest)?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp_name = format!(".rustscale-taildrive-{}-{sequence}.tmp", std::process::id());
    let temp = parent.join(temp_name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = dir.open_with(&temp, &options)?;
    let write_result = (|| {
        for chunk in body.chunks(64 * 1024) {
            control.check()?;
            file.write_all(chunk)?;
        }
        file.sync_all()?;
        drop(file);
        dir.rename(&temp, dir, destination)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = dir.remove_file(&temp);
    }
    // Keep the leaf binding explicit: destination must remain a single child
    // of its checked parent even on platforms with unusual path semantics.
    let _ = leaf;
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
    ensure_no_symlinks(&root.dir, &parsed.relative, false)?;
    let metadata = if parsed.relative.as_os_str().is_empty() {
        root.dir.dir_metadata()?
    } else {
        root.dir.symlink_metadata(&parsed.relative)?
    };
    if metadata.file_type().is_symlink() {
        return Err(OperationError::Forbidden);
    }
    let mut properties = vec![Property {
        href: href_for_components(&parsed.components, metadata.is_dir()),
        display_name: parsed.components.last().cloned().unwrap_or_default(),
        directory: metadata.is_dir(),
        length: metadata.len(),
    }];
    if include_children && metadata.is_dir() {
        let directory = if parsed.relative.as_os_str().is_empty() {
            root.dir.try_clone()?
        } else {
            root.dir.open_dir(&parsed.relative)?
        };
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
        temp: tempfile::TempDir,
        root: PathBuf,
        server: Server,
        read_only: AuthenticatedPeer,
        read_write: AuthenticatedPeer,
    }

    impl Harness {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("share");
            std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("hello.txt"), b"hello").unwrap();
            let limits = Limits::default();
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
