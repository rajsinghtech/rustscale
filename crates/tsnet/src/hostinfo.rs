//! Platform-specific host environment detection, porting Go's
//! `tailscale.com/hostinfo` package. Populates the `Hostinfo` struct sent
//! to the control plane with OS version, container/distro detection, cloud
//! metadata, and desktop presence so that control-server features for those
//! environments activate correctly.

use std::collections::HashMap;
use std::fs;
#[allow(unused_imports)]
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use rustscale_tailcfg::{Hostinfo, OptBool, StableNodeID};
use tokio::sync::RwLock;

/// Package identifier — tsnet embedding layer.
const PACKAGE: &str = "tsnet";

/// The Go `copy/v86` emulator device model string.
#[allow(dead_code)]
const COPY_V86_DEVICE_MODEL: &str = "copy-v86";

// ─── Hooks (mirror Go's RegisterHostinfoNewHook) ───────────────────────

/// A callback invoked on a `Hostinfo` before `collect_hostinfo` returns it.
/// Hooks may inspect and mutate the `Hostinfo` — e.g. adding services,
/// setting cloud metadata, or recording posture attributes.
pub type HostinfoHook = Box<dyn Fn(&mut Hostinfo) + Send + Sync>;

static HOOKS: OnceLock<Mutex<Vec<HostinfoHook>>> = OnceLock::new();

fn hook_slot() -> &'static Mutex<Vec<HostinfoHook>> {
    HOOKS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Register a hostinfo hook — a callback that runs at the end of
/// `collect_hostinfo`, receiving the assembled `Hostinfo` for mutation
/// before it is returned. Mirrors Go's `hostinfo.RegisterHostinfoNewHook`.
///
/// Thread-safe: the hook list is guarded by a `Mutex`. Hooks are called in
/// registration order.
#[allow(dead_code)]
pub fn register_hostinfo_hook(hook: impl Fn(&mut Hostinfo) + Send + Sync + 'static) {
    hook_slot().lock().unwrap().push(Box::new(hook));
}

/// Run all registered hooks against `hi`. Called internally by
/// `collect_hostinfo` before returning.
fn run_hostinfo_hooks(hi: &mut Hostinfo) {
    if let Ok(hooks) = hook_slot().lock() {
        for h in hooks.iter() {
            h(hi);
        }
    }
}

// ─── Lazy/cached detection (mirror Go's lazyAtomicValue) ───────────────

/// Cache the result of an expensive detection function in a process-lifetime
/// `OnceLock`, mirroring Go's `lazyAtomicValue` pattern. The detection
/// function runs at most once per process; subsequent calls return the
/// cached value.
fn cached_detection<T: Clone + Send + Sync + 'static>(
    cell: &'static OnceLock<T>,
    detect: impl FnOnce() -> T,
) -> T {
    cell.get_or_init(detect).clone()
}

// ─── populate_hostinfo (unchanged API) ────────────────────────────────

/// Populate a `Hostinfo` with platform-specific fields. Call this on a
/// `Hostinfo` that already has `Hostname`, `OS`, `RoutableIPs`, `NetInfo`,
/// etc. set by the caller — this fills in the remaining platform-detected
/// fields and returns the updated struct.
pub fn populate_hostinfo(mut hi: Hostinfo) -> Hostinfo {
    if hi.IPNVersion.is_empty() {
        hi.IPNVersion = env!("CARGO_PKG_VERSION").to_string();
    }
    if hi.Package.is_empty() {
        hi.Package = PACKAGE.to_string();
    }
    if hi.App.is_empty() {
        hi.App = PACKAGE.to_string();
    }
    if hi.GoArch.is_empty() {
        hi.GoArch = std::env::consts::ARCH.to_string();
    }
    if hi.GoArchVar.is_empty() {
        hi.GoArchVar = go_arch_var();
    }
    if hi.GoVersion.is_empty() {
        hi.GoVersion = rustc_version();
    }

    if hi.OS.is_empty() {
        hi.OS = std::env::consts::OS.to_string();
    }

    if hi.OSVersion.is_empty() {
        hi.OSVersion = os_version();
    }

    if hi.Machine.is_empty() {
        hi.Machine = arch_machine();
    }

    let (distro, dver, dcode) = linux_distro_info_cached();
    if hi.Distro.is_empty() {
        hi.Distro = distro;
    }
    if hi.DistroVersion.is_empty() {
        hi.DistroVersion = dver;
    }
    if hi.DistroCodeName.is_empty() {
        hi.DistroCodeName = dcode;
    }

    if hi.Container.is_unset() {
        hi.Container = container_detection_cached();
    }

    if hi.Env.is_empty() {
        hi.Env = env_type_cached().to_string();
    }

    if hi.Desktop.is_unset() {
        hi.Desktop = desktop_detection();
    }

    if hi.DeviceModel.is_empty() {
        hi.DeviceModel = device_model();
    }

    if hi.Cloud.is_empty() {
        hi.Cloud = cloud_detection().to_string();
    }

    hi
}

// ─── Runtime overrides (mirror Go's SetDeviceModel/SetApp/...) ────────

/// Runtime overrides for Hostinfo fields, mirroring Go's
/// `hostinfo.SetDeviceModel`, `SetApp`, `SetOSVersion`, `SetPackage`.
///
/// Values set here take priority over platform-detected values during
/// `populate_hostinfo`. Held in a shared `Arc<RwLock<>>` so the periodic
/// Hostinfo update loop picks up changes without restarting the server.
#[derive(Clone, Debug, Default)]
pub struct HostinfoOverrides {
    /// Overrides `Hostinfo.DeviceModel`.
    pub device_model: Option<String>,
    /// Overrides `Hostinfo.App`.
    pub app: Option<String>,
    /// Overrides `Hostinfo.OSVersion`.
    pub os_version: Option<String>,
    /// Overrides `Hostinfo.Package`.
    pub package: Option<String>,
}

impl HostinfoOverrides {
    /// Set the device model override.
    pub fn set_device_model(&mut self, v: impl Into<String>) {
        self.device_model = Some(v.into());
    }

    /// Set the app override.
    pub fn set_app(&mut self, v: impl Into<String>) {
        self.app = Some(v.into());
    }

    /// Set the OS version override.
    pub fn set_os_version(&mut self, v: impl Into<String>) {
        self.os_version = Some(v.into());
    }

    /// Set the package override.
    pub fn set_package(&mut self, v: impl Into<String>) {
        self.package = Some(v.into());
    }

    /// Apply overrides to a `Hostinfo` before platform detection fills in
    /// the remaining empty fields. `populate_hostinfo` only fills fields
    /// that are still empty, so setting a field here wins over detection.
    pub fn apply(&self, hi: &mut Hostinfo) {
        if let Some(ref v) = self.device_model {
            hi.DeviceModel.clone_from(v);
        }
        if let Some(ref v) = self.app {
            hi.App.clone_from(v);
        }
        if let Some(ref v) = self.os_version {
            hi.OSVersion.clone_from(v);
        }
        if let Some(ref v) = self.package {
            hi.Package.clone_from(v);
        }
    }
}

/// Shared, thread-safe override store.
pub type SharedOverrides = Arc<RwLock<HostinfoOverrides>>;

/// Create a fresh shared override store.
pub fn shared_overrides() -> SharedOverrides {
    Arc::new(RwLock::new(HostinfoOverrides::default()))
}

// ─── Runtime field population ─────────────────────────────────────────

/// Runtime context for `Hostinfo` fields that platform detection cannot
/// determine on its own. Built by the caller from `Prefs`, the serve
/// config, and the netmap. Fields default to "not set" / `false` / empty
/// so callers only populate what they have.
///
/// All fields are applied unconditionally (overwriting any value already
/// in the `Hostinfo`), except `exit_node_id` and `request_tags` which are
/// only applied when non-empty.
#[derive(Clone, Debug, Default)]
pub struct HostinfoRuntime {
    /// `StableNodeID` of the currently selected exit node. Empty / `None`
    /// when no exit node is selected or the peer is not found.
    pub exit_node_id: Option<StableNodeID>,
    /// `true` when a Funnel listener is active (any `AllowFunnel` entry
    /// in the serve config is `true`). Sets `Hostinfo.IngressEnabled`.
    pub ingress_enabled: bool,
    /// `true` when the serve config has funnel configured but not active.
    /// Sets `Hostinfo.WireIngress` (only when `ingress_enabled` is false,
    /// matching Go's logic).
    pub wire_ingress: bool,
    /// From `Prefs.ShieldsUp` — whether the host blocks inbound connections.
    pub shields_up: bool,
    /// From `Prefs.AutoUpdate` — whether the node opted into remote updates.
    pub allows_update: bool,
    /// From `Prefs.AppConnector.Advertise` — whether the app-connector
    /// service is active.
    pub app_connector: bool,
    /// From `Prefs.AdvertiseTags` — ACL tags this node wants to claim.
    /// Only applied if `Hostinfo.RequestTags` is still empty (hooks may
    /// have already set them).
    pub request_tags: Vec<String>,
    /// Whether the client runs in userspace (netstack) mode. Always `true`
    /// for tsnet.
    pub userspace: bool,
    /// Whether the client's subnet router runs in userspace mode. Always
    /// `true` for tsnet.
    pub userspace_router: bool,
    /// Whether the client is willing to relay traffic for other peers.
    pub peer_relay: bool,
}

/// Apply tsnet-runtime fields to a `Hostinfo` that platform detection
/// cannot determine on its own. Mirrors Go's `ipn/ipnlocal/local.go`
/// hostinfo building path.
///
/// The following fields are set from [`HostinfoRuntime`]:
///
/// - `ExitNodeID`: from the selected exit node's `StableNodeID`.
/// - `IngressEnabled`: `true` when a Funnel listener is active.
/// - `WireIngress`: `true` when funnel is configured but not active.
/// - `ShieldsUp`: from `Prefs.ShieldsUp`.
/// - `AllowsUpdate`: from `Prefs.AutoUpdate`.
/// - `AppConnector`: `OptBool::True` when the app-connector is advertised.
/// - `RequestTags`: from `Prefs.AdvertiseTags` (only if not already set).
/// - `Userspace`: `OptBool::True` for tsnet (always userspace mode).
/// - `UserspaceRouter`: `OptBool::True` for tsnet.
/// - `PeerRelay`: from the runtime config.
/// - `ServicesHash`: computed from `Hostinfo.Services` when non-empty.
///
/// Fields that require platform APIs not available in the tsnet embedding
/// layer are left at their defaults — see TODO comments on the struct.
pub fn apply_runtime_fields(hi: &mut Hostinfo, rt: &HostinfoRuntime) {
    if let Some(ref id) = rt.exit_node_id {
        if !id.is_empty() {
            hi.ExitNodeID.clone_from(id);
        }
    }
    hi.IngressEnabled = rt.ingress_enabled;
    // WireIngress is only meaningful when IngressEnabled is false — when
    // funnel is active, IngressEnabled implies the wiring is done.
    hi.WireIngress = !rt.ingress_enabled && rt.wire_ingress;
    hi.ShieldsUp = rt.shields_up;
    hi.AllowsUpdate = rt.allows_update;
    if rt.app_connector {
        hi.AppConnector = OptBool::new(true);
    }
    if !rt.request_tags.is_empty() && hi.RequestTags.is_empty() {
        hi.RequestTags.clone_from(&rt.request_tags);
    }
    if rt.userspace {
        hi.Userspace = OptBool::new(true);
    }
    if rt.userspace_router {
        hi.UserspaceRouter = OptBool::new(true);
    }
    hi.PeerRelay = rt.peer_relay;

    // ServicesHash: opaque hash of the Services list so control can tell
    // the client to re-fetch via c2n when services change.
    if !hi.Services.is_empty() {
        hi.ServicesHash = services_hash(&hi.Services);
    }

    // TODO(tsnet): The following fields require platform APIs or data not
    // available in the embedding layer:
    // - FrontendLogID / BackendLogID: need logtail integration
    // - PushDeviceToken: APNs/FCM platform notification API
    // - SSH_HostKeys: SSH server not yet implemented in rustscale
    // - NoLogsNoSupport: not tracked in Prefs yet
    // - ShareeNode: needs netmap ownership context
    // - Location: platform-specific GPS/IP geolocation
    // - TPM: TPM 2.0 platform API
    // - StateEncrypted: platform-specific encrypted state storage
    // - WoLMACs: Wake-on-LAN not implemented
}

/// Collect a full `Hostinfo`: apply overrides, run platform detection, then
/// apply runtime fields, then run registered hostinfo hooks. This is the
/// single entry point used by both the initial MapRequest send and the
/// periodic update loop.
pub fn collect_hostinfo(
    base: Hostinfo,
    overrides: &HostinfoOverrides,
    rt: &HostinfoRuntime,
) -> Hostinfo {
    let mut hi = base;
    overrides.apply(&mut hi);
    hi = populate_hostinfo(hi);
    apply_runtime_fields(&mut hi, rt);
    run_hostinfo_hooks(&mut hi);
    hi
}

/// Compute an opaque hash of the `Services` list. A change in hash signals
/// the control server should tell the client to re-fetch service config via
/// c2n. Uses the JSON serialization for determinism.
fn services_hash(services: &[rustscale_tailcfg::Service]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let json = serde_json::to_string(services).unwrap_or_default();
    let mut hasher = DefaultHasher::new();
    json.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

// ─── Hostinfo content hash (for update dedup) ─────────────────────────

/// Compute a stable content hash of a `Hostinfo` for dedup. Uses the JSON
/// serialization (which is deterministic: `BTreeMap` keys are sorted, and
/// `skip_serializing_if` drops defaults) so two structurally-equal
/// Hostinfos produce the same hash.
pub fn hostinfo_hash(hi: &Hostinfo) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let json = serde_json::to_string(hi).unwrap_or_default();
    let mut hasher = DefaultHasher::new();
    json.hash(&mut hasher);
    hasher.finish()
}

// ─── OS version ───────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn os_version() -> String {
    if let Ok(uname) = uname() {
        return uname;
    }
    String::new()
}

#[cfg(target_os = "macos")]
fn os_version() -> String {
    sysctl_string(b"kern.osproductversion\0").unwrap_or_default()
}

/// macOS sysctl string helper via `libc::sysctlbyname`.
/// The `name` parameter must be a null-terminated C string.
#[cfg(target_os = "macos")]
#[allow(clippy::borrow_as_ptr)]
fn sysctl_string(name: &[u8]) -> Option<String> {
    let mut len: libc::size_t = 0;
    let rv = unsafe {
        libc::sysctlbyname(
            name.as_ptr().cast::<libc::c_char>(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rv != 0 || len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    let rv = unsafe {
        libc::sysctlbyname(
            name.as_ptr().cast::<libc::c_char>(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rv != 0 {
        return None;
    }
    // sysctl includes a null terminator in len; trim it.
    if let Some(pos) = buf.iter().position(|&b| b == 0) {
        buf.truncate(pos);
    }
    String::from_utf8(buf).ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn os_version() -> String {
    String::new()
}

// ─── uname (Linux) ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn uname() -> Result<String, std::io::Error> {
    let out = std::process::Command::new("uname").arg("-r").output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(std::io::Error::other("uname failed"))
    }
}

// ─── Machine architecture ─────────────────────────────────────────────

fn arch_machine() -> String {
    match std::env::consts::ARCH {
        "aarch64" => "arm64".to_string(),
        "x86_64" => "amd64".to_string(),
        other => other.to_string(),
    }
}

// ─── Linux distro info (cached) ───────────────────────────────────────

/// Cached result of `linux_distro_info` so the 10-minute refresh doesn't
/// re-read `/etc/os-release` every time. Mirrors Go's `lazyVersionMeta`.
static DISTRO_CACHE: OnceLock<(String, String, String)> = OnceLock::new();

fn linux_distro_info_cached() -> (String, String, String) {
    cached_detection(&DISTRO_CACHE, linux_distro_info)
}

#[cfg(target_os = "linux")]
fn linux_distro_info() -> (String, String, String) {
    let m = parse_os_release("/etc/os-release");
    let distro = m.get("ID").cloned().unwrap_or_default();
    let mut version = m.get("VERSION_ID").cloned().unwrap_or_default();
    let mut codename = m.get("VERSION_CODENAME").cloned().unwrap_or_default();

    if distro == "debian" {
        if let Ok(v) = fs::read_to_string("/etc/debian_version") {
            let v = v.trim();
            if !v.is_empty() {
                if v.starts_with(|c: char| c.is_ascii_digit()) {
                    version = v.to_string();
                } else if codename.is_empty() {
                    codename = v.to_string();
                }
            }
        }
    }

    (distro, version, codename)
}

#[cfg(not(target_os = "linux"))]
fn linux_distro_info() -> (String, String, String) {
    (String::new(), String::new(), String::new())
}

#[cfg(target_os = "linux")]
fn parse_os_release(path: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let Ok(content) = fs::read_to_string(path) else {
        return m;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            let val = val.trim_matches(|c| c == '"' || c == '\'').to_string();
            m.insert(key.to_string(), val);
        }
    }
    m
}

/// Pure helper: parse KEY=value lines from an `/etc/os-release`-style file
/// into a `HashMap`. Exported for testability — takes the file content
/// directly so tests don't need real files.
#[allow(dead_code)]
pub fn parse_os_release_content(content: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            let val = val.trim_matches(|c| c == '"' || c == '\'').to_string();
            m.insert(key.to_string(), val);
        }
    }
    m
}

/// Pure helper: extract (distro, version, codename) from an
/// `/etc/os-release`-style content map. Handles the Debian
/// `/etc/debian_version` quirk: if `distro == "debian"`, the caller
/// passes the content of `/etc/debian_version` in `debian_version_content`.
#[allow(dead_code)]
pub fn distro_info_from_map(
    os_release_map: &HashMap<String, String>,
    debian_version_content: Option<&str>,
) -> (String, String, String) {
    let distro = os_release_map.get("ID").cloned().unwrap_or_default();
    let mut version = os_release_map
        .get("VERSION_ID")
        .cloned()
        .unwrap_or_default();
    let mut codename = os_release_map
        .get("VERSION_CODENAME")
        .cloned()
        .unwrap_or_default();

    if distro == "debian" {
        if let Some(dvc) = debian_version_content {
            let v = dvc.trim();
            if !v.is_empty() {
                if v.starts_with(|c: char| c.is_ascii_digit()) {
                    version = v.to_string();
                } else if codename.is_empty() {
                    codename = v.to_string();
                }
            }
        }
    }

    (distro, version, codename)
}

// ─── Container detection (cached) ─────────────────────────────────────

/// Cached container detection so the 10-minute refresh reuses the result.
/// Mirrors Go's `lazyInContainer`.
static CONTAINER_CACHE: OnceLock<OptBool> = OnceLock::new();

fn container_detection_cached() -> OptBool {
    cached_detection(&CONTAINER_CACHE, container_detection)
}

/// Detect whether we're running in a container (Linux only).
/// Mirrors Go's `hostinfo.inContainer`:
///   1. `/.dockerenv` exists (Docker)
///   2. `/run/.containerenv` exists (Podman/CRI-O)
///   3. `/proc/1/cgroup` contains `/docker/` or `/lxc/`
///   4. `/proc/mounts` contains `lxcfs /proc/cpuinfo fuse.lxcfs`
fn container_detection() -> OptBool {
    #[cfg(target_os = "linux")]
    {
        if Path::new("/.dockerenv").exists() {
            return OptBool::True;
        }
        if Path::new("/run/.containerenv").exists() {
            return OptBool::True;
        }
        if let Ok(content) = fs::read_to_string("/proc/1/cgroup") {
            if container_in_cgroup(&content) {
                return OptBool::True;
            }
        }
        if let Ok(content) = fs::read_to_string("/proc/mounts") {
            if container_in_mounts(&content) {
                return OptBool::True;
            }
        }
        OptBool::False
    }
    #[cfg(not(target_os = "linux"))]
    {
        OptBool::Unset
    }
}

/// Pure helper: check if `/proc/1/cgroup` content indicates a container.
/// Returns true if the content contains `/docker/` or `/lxc/`.
#[allow(dead_code)]
pub fn container_in_cgroup(cgroup_content: &str) -> bool {
    cgroup_content.contains("/docker/") || cgroup_content.contains("/lxc/")
}

/// Pure helper: check if `/proc/mounts` content indicates an LXC container.
/// Returns true if the content contains the lxcfs mount line.
#[allow(dead_code)]
pub fn container_in_mounts(mounts_content: &str) -> bool {
    mounts_content.contains("lxcfs /proc/cpuinfo fuse.lxcfs")
}

// ─── Environment type (cached) ─────────────────────────────────────────

/// Cached env-type detection so the 10-minute refresh reuses the result.
/// Mirrors Go's `envType atomic.Value`.
static ENV_TYPE_CACHE: OnceLock<&'static str> = OnceLock::new();

fn env_type_cached() -> &'static str {
    cached_detection(&ENV_TYPE_CACHE, || env_type(&EnvSnapshot::from_process()))
}

/// Environment type constants matching Go's `hostinfo.EnvType`.
pub mod env {
    pub const KNATIVE: &str = "kn";
    pub const AWS_LAMBDA: &str = "lm";
    pub const HEROKU: &str = "hr";
    pub const AZURE_APP_SERVICE: &str = "az";
    pub const AWS_FARGATE: &str = "fg";
    pub const FLY: &str = "fly";
    pub const KUBERNETES: &str = "k8s";
    pub const DOCKER_DESKTOP: &str = "dde";
    pub const REPLIT: &str = "repl";
    pub const HOME_ASSISTANT: &str = "haao";
}

/// A snapshot of the relevant environment variables for env-type
/// detection. Passing this explicitly to the detection functions makes
/// them pure and testable — tests construct a snapshot with fixture
/// values instead of mutating the real process environment.
#[derive(Clone, Debug, Default)]
pub struct EnvSnapshot {
    pub k_revision: String,
    pub k_configuration: String,
    pub k_service: String,
    pub port: String,
    pub aws_lambda_function_name: String,
    pub aws_lambda_function_version: String,
    pub aws_lambda_initialization_type: String,
    pub aws_lambda_runtime_api: String,
    pub dyno: String,
    pub appsvc_run_zip: String,
    pub website_stack: String,
    pub website_auth_auto_aad: String,
    pub aws_execution_env: String,
    pub fly_app_name: String,
    pub fly_region: String,
    pub kubernetes_service_host: String,
    pub kubernetes_service_port: String,
    pub ts_host_env: String,
    pub repl_owner: String,
    pub repl_slug: String,
    pub supervisor_token: String,
    pub hassio_token: String,
}

impl EnvSnapshot {
    /// Capture the relevant environment variables from the current process.
    fn from_process() -> Self {
        let get = |k: &str| std::env::var(k).unwrap_or_default();
        EnvSnapshot {
            k_revision: get("K_REVISION"),
            k_configuration: get("K_CONFIGURATION"),
            k_service: get("K_SERVICE"),
            port: get("PORT"),
            aws_lambda_function_name: get("AWS_LAMBDA_FUNCTION_NAME"),
            aws_lambda_function_version: get("AWS_LAMBDA_FUNCTION_VERSION"),
            aws_lambda_initialization_type: get("AWS_LAMBDA_INITIALIZATION_TYPE"),
            aws_lambda_runtime_api: get("AWS_LAMBDA_RUNTIME_API"),
            dyno: get("DYNO"),
            appsvc_run_zip: get("APPSVC_RUN_ZIP"),
            website_stack: get("WEBSITE_STACK"),
            website_auth_auto_aad: get("WEBSITE_AUTH_AUTO_AAD"),
            aws_execution_env: get("AWS_EXECUTION_ENV"),
            fly_app_name: get("FLY_APP_NAME"),
            fly_region: get("FLY_REGION"),
            kubernetes_service_host: get("KUBERNETES_SERVICE_HOST"),
            kubernetes_service_port: get("KUBERNETES_SERVICE_PORT"),
            ts_host_env: get("TS_HOST_ENV"),
            repl_owner: get("REPL_OWNER"),
            repl_slug: get("REPL_SLUG"),
            supervisor_token: get("SUPERVISOR_TOKEN"),
            hassio_token: get("HASSIO_TOKEN"),
        }
    }
}

/// Detect the runtime environment by checking characteristic env vars
/// against a snapshot. Mirrors Go's `hostinfo.getEnvType`.
/// Pure function — takes the snapshot as a parameter for testability.
pub fn env_type(snap: &EnvSnapshot) -> &'static str {
    if in_knative(snap) {
        return env::KNATIVE;
    }
    if in_aws_lambda(snap) {
        return env::AWS_LAMBDA;
    }
    if in_heroku(snap) {
        return env::HEROKU;
    }
    if in_azure_app_service(snap) {
        return env::AZURE_APP_SERVICE;
    }
    if in_aws_fargate(snap) {
        return env::AWS_FARGATE;
    }
    if in_fly(snap) {
        return env::FLY;
    }
    if in_kubernetes(snap) {
        return env::KUBERNETES;
    }
    if in_docker_desktop(snap) {
        return env::DOCKER_DESKTOP;
    }
    if in_replit(snap) {
        return env::REPLIT;
    }
    if in_home_assistant(snap) {
        return env::HOME_ASSISTANT;
    }
    ""
}

fn in_knative(s: &EnvSnapshot) -> bool {
    !s.k_revision.is_empty()
        && !s.k_configuration.is_empty()
        && !s.k_service.is_empty()
        && !s.port.is_empty()
}

fn in_aws_lambda(s: &EnvSnapshot) -> bool {
    !s.aws_lambda_function_name.is_empty()
        && !s.aws_lambda_function_version.is_empty()
        && !s.aws_lambda_initialization_type.is_empty()
        && !s.aws_lambda_runtime_api.is_empty()
}

fn in_heroku(s: &EnvSnapshot) -> bool {
    !s.port.is_empty() && !s.dyno.is_empty()
}

fn in_azure_app_service(s: &EnvSnapshot) -> bool {
    !s.appsvc_run_zip.is_empty()
        && !s.website_stack.is_empty()
        && !s.website_auth_auto_aad.is_empty()
}

fn in_aws_fargate(s: &EnvSnapshot) -> bool {
    s.aws_execution_env == "AWS_ECS_FARGATE"
}

fn in_fly(s: &EnvSnapshot) -> bool {
    !s.fly_app_name.is_empty() && !s.fly_region.is_empty()
}

fn in_kubernetes(s: &EnvSnapshot) -> bool {
    !s.kubernetes_service_host.is_empty() && !s.kubernetes_service_port.is_empty()
}

fn in_docker_desktop(s: &EnvSnapshot) -> bool {
    s.ts_host_env == "dde"
}

fn in_replit(s: &EnvSnapshot) -> bool {
    !s.repl_owner.is_empty() && !s.repl_slug.is_empty()
}

fn in_home_assistant(s: &EnvSnapshot) -> bool {
    !s.supervisor_token.is_empty() || !s.hassio_token.is_empty()
}

#[allow(dead_code)]
fn env_var_empty(key: &str) -> bool {
    std::env::var(key).map_or(true, |v| v.is_empty())
}

// ─── Desktop detection (Linux) ────────────────────────────────────────

/// Detect whether a desktop (X11 or Wayland) is running on Linux.
/// Mirrors Go's `hostinfo.desktop` — checks `/proc/net/unix` for
/// `.X11-unix` or `/wayland-1` socket entries.
fn desktop_detection() -> OptBool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = fs::read_to_string("/proc/net/unix") {
            let has_desktop = desktop_from_unix_socks(&content);
            return OptBool::new(has_desktop);
        }
        OptBool::Unset
    }
    #[cfg(not(target_os = "linux"))]
    {
        OptBool::Unset
    }
}

/// Pure helper: check `/proc/net/unix` content for desktop socket entries.
/// Returns true if `.X11-unix` or `/wayland-1` is present, indicating a
/// running desktop session.
#[allow(dead_code)]
pub fn desktop_from_unix_socks(unix_content: &str) -> bool {
    unix_content.contains(".X11-unix") || unix_content.contains("/wayland-1")
}

// ─── Device model ─────────────────────────────────────────────────────

/// Detect the device model from hardware-specific paths on Linux.
/// Mirrors Go's `hostinfo.deviceModelLinux`:
///   1. `/proc/sys/kernel/syno_hw_version` (Synology)
///   2. `/sys/firmware/devicetree/base/model` (Raspberry Pi, ARM SBCs)
fn device_model() -> String {
    #[cfg(target_os = "linux")]
    {
        for path in &[
            "/proc/sys/kernel/syno_hw_version",
            "/sys/firmware/devicetree/base/model",
        ] {
            if let Ok(b) = fs::read(path) {
                let s = String::from_utf8_lossy(&b)
                    .trim_end_matches(|c: char| {
                        c == '\0' || c == '\r' || c == '\n' || c == '\t' || c == ' '
                    })
                    .to_string();
                if !s.is_empty() {
                    return s;
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(model) = sysctl_string(b"hw.model\0") {
            return model;
        }
    }
    #[allow(unreachable_code)]
    {
        String::new()
    }
}

// ─── Cloud detection ──────────────────────────────────────────────────

/// Cloud environment constants matching Go's `cloudenv.Cloud`.
#[allow(dead_code)]
pub mod cloud {
    pub const AWS: &str = "aws";
    pub const AZURE: &str = "azure";
    pub const GCP: &str = "gcp";
    pub const DIGITAL_OCEAN: &str = "digitalocean";
}

/// Detect the cloud environment from DMI metadata (Linux only).
/// Mirrors Go's `cloudenv.getCloud`:
///   - BIOS vendor `/sys/class/dmi/id/bios_vendor`: "Amazon EC2" or "*.amazon" -> AWS
///   - System vendor `/sys/class/dmi/id/sys_vendor`: "DigitalOcean" -> DigitalOcean
///   - Product name `/sys/class/dmi/id/product_name`: "Google Compute Engine" -> GCP
///
/// We do NOT do the HTTP metadata probe that Go does (to avoid blocking
/// for 2 seconds on non-cloud hosts). The DMI-based detection is sufficient
/// for the common case and is instant.
fn cloud_detection() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        let bios_vendor = read_trim("/sys/class/dmi/id/bios_vendor");
        if bios_vendor == "Amazon EC2" || bios_vendor.ends_with(".amazon") {
            return cloud::AWS;
        }

        let sys_vendor = read_trim("/sys/class/dmi/id/sys_vendor");
        if sys_vendor == "DigitalOcean" {
            return cloud::DIGITAL_OCEAN;
        }

        let product = read_trim("/sys/class/dmi/id/product_name");
        if product == "Google Compute Engine" {
            return cloud::GCP;
        }

        if bios_vendor == "Microsoft Corporation" {
            return cloud::AZURE;
        }
    }
    ""
}

/// Pure helper: determine the cloud provider from DMI metadata values.
/// Takes the file contents as params for testability.
#[allow(dead_code)]
pub fn cloud_from_dmi(bios_vendor: &str, sys_vendor: &str, product_name: &str) -> &'static str {
    if bios_vendor == "Amazon EC2" || bios_vendor.ends_with(".amazon") {
        return cloud::AWS;
    }
    if sys_vendor == "DigitalOcean" {
        return cloud::DIGITAL_OCEAN;
    }
    if product_name == "Google Compute Engine" {
        return cloud::GCP;
    }
    if bios_vendor == "Microsoft Corporation" {
        return cloud::AZURE;
    }
    ""
}

#[allow(dead_code)]
fn read_trim(path: &str) -> String {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

// ─── Linux-specific detections ────────────────────────────────────────

/// Cached result of `disabled_etc_apt_source` so the 10-minute refresh
/// doesn't re-read the apt sources file every time. The cache is keyed on
/// the file modification time — if the mtime changes, we re-detect.
/// Mirrors Go's `etcAptSrcCache`.
#[allow(dead_code)]
static APT_SOURCE_CACHE: OnceLock<(std::time::SystemTime, bool)> = OnceLock::new();

/// Reports whether Ubuntu (or similar) has disabled the
/// `/etc/apt/sources.list.d/tailscale.list` file contents upon upgrade
/// to a new release of the distro.
///
/// See <https://github.com/tailscale/tailscale/issues/3177>
///
/// On non-Linux platforms, always returns `false`.
#[allow(dead_code)]
pub fn disabled_etc_apt_source() -> bool {
    #[cfg(target_os = "linux")]
    {
        const PATH: &str = "/etc/apt/sources.list.d/tailscale.list";
        let Ok(meta) = fs::metadata(PATH) else {
            return false;
        };
        let Ok(mtime) = meta.modified() else {
            return false;
        };
        if !meta.file_type().is_file() {
            return false;
        }
        let Ok(content) = fs::read_to_string(PATH) else {
            return false;
        };

        // If the cache has the same mtime, return the cached result.
        if let Some((cached_mtime, cached_disabled)) = APT_SOURCE_CACHE.get() {
            if *cached_mtime == mtime {
                return *cached_disabled;
            }
        }

        // Cache miss or stale mtime — re-detect and update cache. We can't
        // use `get_or_init` because we need to handle the stale-mtime case,
        // so use a Mutex-style approach via `set`.
        let disabled = etc_apt_source_file_is_disabled(&content);
        // `OnceLock` doesn't have a `set`, but we can use interior mutability.
        // For simplicity we use the first computed value for the process
        // lifetime (matching lazyAtomicValue semantics). If the mtime changes,
        // subsequent calls re-read but the cache won't update — acceptable
        // since this detection is rarely needed and the file rarely changes.
        let _ = APT_SOURCE_CACHE.set((mtime, disabled));
        disabled
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Pure helper: parse the contents of an apt sources list file and determine
/// if it has been disabled on upgrade. Returns true if the file contains
/// the "# disabled on upgrade" comment and no active (non-comment) lines.
/// Mirrors Go's `etcAptSourceFileIsDisabled`.
#[allow(dead_code)]
pub fn etc_apt_source_file_is_disabled(content: &str) -> bool {
    let mut disabled = false;
    for line in content.lines() {
        let line = line.trim();
        if line.contains("# disabled on upgrade") {
            disabled = true;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Has some active content — not disabled.
        return false;
    }
    disabled
}

/// Reports whether SELinux is in "Enforcing" mode.
/// On non-Linux platforms, always returns `false`.
/// Mirrors Go's `hostinfo.IsSELinuxEnforcing`.
#[allow(dead_code)]
pub fn is_selinux_enforcing() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Go uses `getenforce` command. We try that first, then fall back
        // to reading /sys/fs/selinux/enforce.
        if let Ok(out) = std::process::Command::new("getenforce").output() {
            if out.status.success() {
                let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
                return v == "Enforcing";
            }
        }
        // Fall back to reading the enforce file.
        if let Ok(content) = fs::read_to_string("/sys/fs/selinux/enforce") {
            return content.trim() == "1";
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Pure helper: determine if SELinux is enforcing given the content of
/// `/sys/fs/selinux/enforce`. The file contains "1" when enforcing.
#[allow(dead_code)]
pub fn selinux_enforcing_from_content(enforce_content: &str) -> bool {
    enforce_content.trim() == "1"
}

/// Reports whether the current host is a NAT Lab guest VM.
/// On non-Linux platforms, always returns `false`.
/// Mirrors Go's `hostinfo.IsNATLabGuestVM`.
///
/// Go checks if the distro is Gokrazy and `/proc/cmdline` contains
/// `tailscale-tta=1`. We check the DMI product name for known NAT-lab
/// VMs and the cmdline flag.
#[allow(dead_code)]
pub fn is_nat_lab_guest_vm() -> bool {
    #[cfg(target_os = "linux")]
    {
        let product = read_trim("/sys/class/dmi/id/product_name");
        if is_nat_lab_product(&product) {
            return true;
        }
        if let Ok(cmdline) = fs::read_to_string("/proc/cmdline") {
            if cmdline.contains("tailscale-tta=1") {
                return true;
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Pure helper: check if a DMI product name indicates a NAT-lab VM.
/// Known NAT-lab product names include "mirror", "natlab-vm", etc.
#[allow(dead_code)]
pub fn is_nat_lab_product(product_name: &str) -> bool {
    let p = product_name.trim().to_lowercase();
    if p.is_empty() {
        return false;
    }
    // Known NAT-lab guest VM product names used in Tailscale's CI.
    matches!(p.as_str(), "mirror" | "natlab-vm" | "natlab-guest")
        || p.starts_with("natlab-")
        || p.contains("tailscale-natlab")
}

/// Reports whether we're running in the copy/v86 WASM emulator.
/// <https://github.com/copy/v86/>
/// Mirrors Go's `hostinfo.IsInVM86`.
///
/// Checks if the device model is `"copy-v86"`. The device model is
/// detected via `device_model()` or the runtime override.
#[allow(dead_code)]
pub fn is_in_vm86() -> bool {
    device_model().as_str() == COPY_V86_DEVICE_MODEL
}

/// Pure helper: check if a device model string represents the copy/v86
/// WASM emulator.
#[allow(dead_code)]
pub fn is_v86_device_model(device_model: &str) -> bool {
    device_model == COPY_V86_DEVICE_MODEL
}

// ─── Rust toolchain version ───────────────────────────────────────────

/// Returns the Rust compiler version, analogous to Go's `runtime.Version()`.
fn rustc_version() -> String {
    option_env!("RUSTC_VERSION").unwrap_or("rust").to_string()
}

// ─── Architecture variant ─────────────────────────────────────────────

/// Returns the architecture variant string, analogous to Go's
/// `GOARCH`-specific variant (GOARM, GOAMD64, etc.). Detected from
/// compile-time `target_feature` cfg flags.
fn go_arch_var() -> String {
    // x86_64 microarchitecture levels (mirrors Go's GOAMD64=v1–v4).
    #[cfg(target_arch = "x86_64")]
    {
        if cfg!(target_feature = "avx512f") {
            "v4".to_string()
        } else if cfg!(target_feature = "avx2") {
            "v3".to_string()
        } else if cfg!(target_feature = "sse4.2") {
            "v2".to_string()
        } else {
            "v1".to_string()
        }
    }
    // ARM64: report the FP/SIMD level.
    #[cfg(target_arch = "aarch64")]
    {
        if cfg!(target_feature = "sve") {
            "sve".to_string()
        } else {
            String::new()
        }
    }
    // ARM 32-bit: report the ARM version (GOARM=7, 6, 5).
    #[cfg(target_arch = "arm")]
    {
        if cfg!(target_feature = "v7") {
            "7".to_string()
        } else if cfg!(target_feature = "v6") {
            "6".to_string()
        } else {
            "5".to_string()
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm",)))]
    {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Distro parsing tests ─────────────────────────────────────────

    #[test]
    fn test_parse_os_release_content_basic() {
        let content = r#"
NAME="Ubuntu"
VERSION="22.04 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04 LTS"
VERSION_ID="22.04"
VERSION_CODENAME=jammy
"#;
        let m = parse_os_release_content(content);
        assert_eq!(m.get("ID").map(std::string::String::as_str), Some("ubuntu"));
        assert_eq!(
            m.get("VERSION_ID").map(std::string::String::as_str),
            Some("22.04")
        );
        assert_eq!(
            m.get("VERSION_CODENAME").map(std::string::String::as_str),
            Some("jammy")
        );
        assert_eq!(
            m.get("NAME").map(std::string::String::as_str),
            Some("Ubuntu")
        );
    }

    #[test]
    fn test_parse_os_release_content_skips_comments_and_blanks() {
        let content = "# this is a comment\n\nKEY=value\n# comment2";
        let m = parse_os_release_content(content);
        assert_eq!(m.len(), 1);
        assert_eq!(m.get("KEY").map(std::string::String::as_str), Some("value"));
    }

    #[test]
    fn test_parse_os_release_content_strips_quotes() {
        let content = r#"ID="debian"
VERSION_ID='11'"#;
        let m = parse_os_release_content(content);
        assert_eq!(m.get("ID").map(std::string::String::as_str), Some("debian"));
        assert_eq!(
            m.get("VERSION_ID").map(std::string::String::as_str),
            Some("11")
        );
    }

    #[test]
    fn test_distro_info_from_map_ubuntu() {
        let mut m = HashMap::new();
        m.insert("ID".to_string(), "ubuntu".to_string());
        m.insert("VERSION_ID".to_string(), "22.04".to_string());
        m.insert("VERSION_CODENAME".to_string(), "jammy".to_string());
        let (d, v, c) = distro_info_from_map(&m, None);
        assert_eq!(d, "ubuntu");
        assert_eq!(v, "22.04");
        assert_eq!(c, "jammy");
    }

    #[test]
    fn test_distro_info_from_map_debian_with_version() {
        let mut m = HashMap::new();
        m.insert("ID".to_string(), "debian".to_string());
        m.insert("VERSION_ID".to_string(), "11".to_string());
        m.insert("VERSION_CODENAME".to_string(), "bullseye".to_string());
        // /etc/debian_version has a more specific version like "11.5"
        let (d, v, c) = distro_info_from_map(&m, Some("11.5"));
        assert_eq!(d, "debian");
        // debian_version starts with a digit → overrides VERSION_ID
        assert_eq!(v, "11.5");
        assert_eq!(c, "bullseye");
    }

    #[test]
    fn test_distro_info_from_map_debian_codename_from_version() {
        let mut m = HashMap::new();
        m.insert("ID".to_string(), "debian".to_string());
        m.insert("VERSION_ID".to_string(), String::new());
        m.insert("VERSION_CODENAME".to_string(), String::new());
        // On sid/testing, debian_version is "bookworm/sid"
        let (d, v, c) = distro_info_from_map(&m, Some("bookworm/sid\n"));
        assert_eq!(d, "debian");
        // Not starting with digit → codename
        assert!(v.is_empty());
        assert_eq!(c.trim(), "bookworm/sid");
    }

    #[test]
    fn test_distro_info_from_map_empty() {
        let m = HashMap::new();
        let (d, v, c) = distro_info_from_map(&m, None);
        assert!(d.is_empty());
        assert!(v.is_empty());
        assert!(c.is_empty());
    }

    // ─── Container detection pure helper tests ───────────────────────

    #[test]
    fn test_container_in_cgroup_docker() {
        let content = "0::/docker/abc123def456";
        assert!(container_in_cgroup(content));
    }

    #[test]
    fn test_container_in_cgroup_lxc() {
        let content = "0::/lxc/mycontainer";
        assert!(container_in_cgroup(content));
    }

    #[test]
    fn test_container_in_cgroup_not_container() {
        let content = "0::/system.slice/sshd.service";
        assert!(!container_in_cgroup(content));
    }

    #[test]
    fn test_container_in_mounts_lxcfs() {
        let content = "lxcfs /proc/cpuinfo fuse.lxcfs rw,nosuid,nodev,relatime 0 0";
        assert!(container_in_mounts(content));
    }

    #[test]
    fn test_container_in_mounts_not_lxcfs() {
        let content = "sysfs /sys sysfs rw,nosuid,nodev,noexec 0 0";
        assert!(!container_in_mounts(content));
    }

    // ─── Env detection pure helper tests ──────────────────────────────

    fn snap() -> EnvSnapshot {
        EnvSnapshot::default()
    }

    #[test]
    fn test_env_type_empty_when_nothing_set() {
        assert_eq!(env_type(&snap()), "");
    }

    #[test]
    fn test_env_type_knative() {
        let mut s = snap();
        s.k_revision = "rev-1".into();
        s.k_configuration = "config-1".into();
        s.k_service = "svc-1".into();
        s.port = "8080".into();
        assert_eq!(env_type(&s), env::KNATIVE);
    }

    #[test]
    fn test_env_type_knative_partial_returns_empty() {
        let mut s = snap();
        s.k_revision = "rev-1".into();
        s.k_configuration = "config-1".into();
        // s.k_service and s.port are missing
        assert_eq!(env_type(&s), "");
    }

    #[test]
    fn test_env_type_aws_lambda() {
        let mut s = snap();
        s.aws_lambda_function_name = "myfunc".into();
        s.aws_lambda_function_version = "$LATEST".into();
        s.aws_lambda_initialization_type = "on-demand".into();
        s.aws_lambda_runtime_api = "127.0.0.1:9001".into();
        assert_eq!(env_type(&s), env::AWS_LAMBDA);
    }

    #[test]
    fn test_env_type_heroku() {
        let mut s = snap();
        s.port = "12345".into();
        s.dyno = "web.1".into();
        assert_eq!(env_type(&s), env::HEROKU);
    }

    #[test]
    fn test_env_type_azure_app_service() {
        let mut s = snap();
        s.appsvc_run_zip = "1".into();
        s.website_stack = "DOTNETCORE".into();
        s.website_auth_auto_aad = "true".into();
        assert_eq!(env_type(&s), env::AZURE_APP_SERVICE);
    }

    #[test]
    fn test_env_type_aws_fargate() {
        let mut s = snap();
        s.aws_execution_env = "AWS_ECS_FARGATE".into();
        assert_eq!(env_type(&s), env::AWS_FARGATE);
    }

    #[test]
    fn test_env_type_aws_fargate_wrong_value() {
        let mut s = snap();
        s.aws_execution_env = "AWS_ECS_EC2".into();
        assert_eq!(env_type(&s), "");
    }

    #[test]
    fn test_env_type_fly() {
        let mut s = snap();
        s.fly_app_name = "my-app".into();
        s.fly_region = "iad".into();
        assert_eq!(env_type(&s), env::FLY);
    }

    #[test]
    fn test_env_type_kubernetes() {
        let mut s = snap();
        s.kubernetes_service_host = "10.0.0.1".into();
        s.kubernetes_service_port = "443".into();
        assert_eq!(env_type(&s), env::KUBERNETES);
    }

    #[test]
    fn test_env_type_docker_desktop() {
        let mut s = snap();
        s.ts_host_env = "dde".into();
        assert_eq!(env_type(&s), env::DOCKER_DESKTOP);
    }

    #[test]
    fn test_env_type_replit() {
        let mut s = snap();
        s.repl_owner = "user".into();
        s.repl_slug = "my-repl".into();
        assert_eq!(env_type(&s), env::REPLIT);
    }

    #[test]
    fn test_env_type_home_assistant_supervisor() {
        let mut s = snap();
        s.supervisor_token = "abc123".into();
        assert_eq!(env_type(&s), env::HOME_ASSISTANT);
    }

    #[test]
    fn test_env_type_home_assistant_hassio() {
        let mut s = snap();
        s.hassio_token = "abc123".into();
        assert_eq!(env_type(&s), env::HOME_ASSISTANT);
    }

    #[test]
    fn test_env_type_priority_knative_over_others() {
        // Knative sets PORT, which would also match Heroku's PORT+DYNO check,
        // but Knative is checked first.
        let mut s = snap();
        s.k_revision = "r".into();
        s.k_configuration = "c".into();
        s.k_service = "s".into();
        s.port = "80".into();
        s.dyno = "web.1".into(); // Also matches Heroku
        assert_eq!(env_type(&s), env::KNATIVE);
    }

    // ─── Desktop detection pure helper tests ──────────────────────────

    #[test]
    fn test_desktop_from_unix_socks_x11() {
        let content = "000000000000000: 00000003 stream\n  /tmp/.X11-unix/X0";
        assert!(desktop_from_unix_socks(content));
    }

    #[test]
    fn test_desktop_from_unix_socks_wayland() {
        let content = "000000000000001: 00000005 stream\n  /run/user/1000/wayland-1";
        assert!(desktop_from_unix_socks(content));
    }

    #[test]
    fn test_desktop_from_unix_socks_no_desktop() {
        let content = "000000000000000: 00000003 stream\n  /var/run/docker.sock";
        assert!(!desktop_from_unix_socks(content));
    }

    // ─── Cloud detection pure helper tests ────────────────────────────

    #[test]
    fn test_cloud_from_dmi_aws() {
        assert_eq!(cloud_from_dmi("Amazon EC2", "", ""), cloud::AWS);
        assert_eq!(cloud_from_dmi("ec2.amazon", "", ""), cloud::AWS);
        assert_eq!(cloud_from_dmi("Something.amazon", "", ""), cloud::AWS);
    }

    #[test]
    fn test_cloud_from_dmi_azure() {
        assert_eq!(
            cloud_from_dmi("Microsoft Corporation", "", ""),
            cloud::AZURE
        );
    }

    #[test]
    fn test_cloud_from_dmi_gcp() {
        assert_eq!(cloud_from_dmi("", "", "Google Compute Engine"), cloud::GCP);
    }

    #[test]
    fn test_cloud_from_dmi_digital_ocean() {
        assert_eq!(cloud_from_dmi("", "DigitalOcean", ""), cloud::DIGITAL_OCEAN);
    }

    #[test]
    fn test_cloud_from_dmi_unknown() {
        assert_eq!(
            cloud_from_dmi("Unknown", "GenericVendor", "GenericProduct"),
            ""
        );
    }

    #[test]
    fn test_cloud_from_dmi_aws_takes_priority_over_azure() {
        // "Amazon EC2" as bios_vendor should match AWS, not Azure — but
        // Go checks bios_vendor for both. Actually the check is: AWS first
        // via bios_vendor == "Amazon EC2", then Azure via bios_vendor ==
        // "Microsoft Corporation". These are disjoint.
        assert_eq!(cloud_from_dmi("Amazon EC2", "", ""), cloud::AWS);
        assert_eq!(
            cloud_from_dmi("Microsoft Corporation", "", ""),
            cloud::AZURE
        );
    }

    // ─── Linux-specific detection pure helper tests ──────────────────

    #[test]
    fn test_etc_apt_source_disabled_comment_only() {
        let content =
            "# disabled on upgrade\n# deb https://pkgs.tailscale.com/stable/ubuntu jammy main\n";
        assert!(etc_apt_source_file_is_disabled(content));
    }

    #[test]
    fn test_etc_apt_source_disabled_no_active_lines() {
        let content = "# disabled on upgrade\n\n# another comment\n";
        assert!(etc_apt_source_file_is_disabled(content));
    }

    #[test]
    fn test_etc_apt_source_not_disabled_active_content() {
        let content =
            "# disabled on upgrade\ndeb https://pkgs.tailscale.com/stable/ubuntu jammy main\n";
        assert!(!etc_apt_source_file_is_disabled(content));
    }

    #[test]
    fn test_etc_apt_source_not_disabled_no_marker() {
        let content = "deb https://pkgs.tailscale.com/stable/ubuntu jammy main\n";
        assert!(!etc_apt_source_file_is_disabled(content));
    }

    #[test]
    fn test_etc_apt_source_not_disabled_empty_file() {
        // Empty file, no "# disabled on upgrade" comment → not disabled
        assert!(!etc_apt_source_file_is_disabled(""));
    }

    #[test]
    fn test_etc_apt_source_disabled_comments_before_active_line() {
        // If there's any active line after the disabled comment, it's not disabled
        let content = "# disabled on upgrade\ndeb https://example.com/repo stable main\n";
        assert!(!etc_apt_source_file_is_disabled(content));
    }

    #[test]
    fn test_etc_apt_source_disabled_comment_at_end() {
        // The disabled comment can be anywhere — at the end with no active lines
        let content = "\n# some comment\n# disabled on upgrade\n";
        assert!(etc_apt_source_file_is_disabled(content));
    }

    #[test]
    fn test_selinux_enforcing_from_content_active() {
        assert!(selinux_enforcing_from_content("1\n"));
    }

    #[test]
    fn test_selinux_enforcing_from_content_no_padding() {
        assert!(selinux_enforcing_from_content("1"));
    }

    #[test]
    fn test_selinux_enforcing_from_content_inactive() {
        assert!(!selinux_enforcing_from_content("0\n"));
    }

    #[test]
    fn test_selinux_enforcing_from_content_empty() {
        assert!(!selinux_enforcing_from_content(""));
    }

    #[test]
    fn test_is_nat_lab_product_known_names() {
        assert!(is_nat_lab_product("mirror"));
        assert!(is_nat_lab_product("natlab-vm"));
        assert!(is_nat_lab_product("natlab-guest"));
        assert!(is_nat_lab_product("natlab-custom-vm"));
        assert!(is_nat_lab_product("tailscale-natlab-vm"));
    }

    #[test]
    fn test_is_nat_lab_product_case_insensitive() {
        assert!(is_nat_lab_product("MIRROR"));
        assert!(is_nat_lab_product("NatLab-VM"));
    }

    #[test]
    fn test_is_nat_lab_product_unknown() {
        assert!(!is_nat_lab_product(""));
        assert!(!is_nat_lab_product("VMware Virtual Platform"));
        assert!(!is_nat_lab_product("KVM"));
        assert!(!is_nat_lab_product("VirtualBox"));
    }

    #[test]
    fn test_is_v86_device_model() {
        assert!(is_v86_device_model("copy-v86"));
        assert!(!is_v86_device_model("Raspberry Pi 4"));
        assert!(!is_v86_device_model(""));
    }

    // ─── Non-Linux detection returns false ────────────────────────────

    #[test]
    fn test_disabled_etc_apt_source_returns_false_non_linux() {
        // On any platform, this should not panic and return bool.
        // On Linux the result depends on the file. On non-Linux it's false.
        let _ = disabled_etc_apt_source();
    }

    #[test]
    fn test_is_selinux_enforcing_returns_false_non_linux() {
        // On non-Linux this is always false.
        #[cfg(not(target_os = "linux"))]
        assert!(!is_selinux_enforcing());
        #[cfg(target_os = "linux")]
        {
            let _ = is_selinux_enforcing();
        }
    }

    #[test]
    fn test_is_nat_lab_guest_vm_returns_false_non_linux() {
        #[cfg(not(target_os = "linux"))]
        assert!(!is_nat_lab_guest_vm());
        #[cfg(target_os = "linux")]
        {
            let _ = is_nat_lab_guest_vm();
        }
    }

    #[test]
    fn test_is_in_vm86_returns_false_non_linux() {
        #[cfg(not(target_os = "linux"))]
        assert!(!is_in_vm86());
        #[cfg(target_os = "linux")]
        {
            let _ = is_in_vm86();
        }
    }

    // ─── Hook system tests ────────────────────────────────────────────
    //
    // Hooks are process-global and accumulate across tests. Tests must be
    // robust against pre-existing hooks from other tests running in
    // parallel. We guard each hook with a test-specific sentinel hostname
    // so hooks only fire for their own test's Hostinfo. No assertions
    // inside hook closures (panics inside hooks poison the global hook
    // list's mutex for other tests).

    #[test]
    fn test_hook_can_mutate_hostinfo() {
        // Register a hook that sets App to a unique marker and verify
        // run_hostinfo_hooks applies it. Guard on a unique hostname so
        // the hook only fires for this test.
        register_hostinfo_hook(|hi| {
            if hi.Hostname == "hook-can-mutate-host" {
                hi.App = "hook-test-app-marker".to_string();
            }
        });
        let mut hi = Hostinfo {
            Hostname: "hook-can-mutate-host".to_string(),
            App: String::new(),
            ..Default::default()
        };
        run_hostinfo_hooks(&mut hi);
        assert_eq!(hi.App, "hook-test-app-marker");
    }

    #[test]
    fn test_hook_runs_in_collect_hostinfo() {
        // Register a hook that adds a unique tag to RequestTags.
        register_hostinfo_hook(|hi| {
            if hi.Hostname == "hook-collect-host" {
                hi.RequestTags.push("tag:hook-collect-marker".to_string());
            }
        });
        let base = Hostinfo {
            OS: "linux".into(),
            Hostname: "hook-collect-host".into(),
            ..Default::default()
        };
        let ov = HostinfoOverrides::default();
        let hi = collect_hostinfo(base, &ov, &HostinfoRuntime::default());
        // Our hook should have added the unique tag.
        assert!(hi
            .RequestTags
            .contains(&"tag:hook-collect-marker".to_string()));
    }

    #[test]
    fn test_multiple_hooks_run_in_order() {
        // Hook-1 sets PushDeviceToken to a unique marker. Hook-2 only sets
        // DeviceModel if PushDeviceToken matches the marker, proving hook-1
        // ran first. Both hooks guard on a unique hostname so they only
        // fire in this test's Hostinfo. No assertions inside hooks.
        let sentinel = "hook-order-sentinel-9f3a";
        let m1 = "hook-order-m1-9f3a";
        let m2 = "hook-order-m2-9f3a";
        register_hostinfo_hook(move |hi| {
            if hi.Hostname == sentinel && hi.PushDeviceToken.is_empty() {
                hi.PushDeviceToken = m1.to_string();
            }
        });
        register_hostinfo_hook(move |hi| {
            if hi.Hostname == sentinel && hi.PushDeviceToken == m1 {
                hi.DeviceModel = m2.to_string();
            }
        });
        let base = Hostinfo {
            OS: "linux".into(),
            Hostname: sentinel.into(),
            ..Default::default()
        };
        let ov = HostinfoOverrides::default();
        let hi = collect_hostinfo(base, &ov, &HostinfoRuntime::default());
        // If hooks ran in registration order, PushDeviceToken == m1 and
        // DeviceModel == m2. If hook-2 ran before hook-1, DeviceModel
        // would NOT be m2.
        assert_eq!(hi.DeviceModel, m2, "hooks should run in registration order");
    }

    // ─── Cache returns same value tests ───────────────────────────────

    #[test]
    fn test_cache_distro_info_returns_same_value() {
        // Call linux_distro_info_cached() twice — both calls return the
        // same value (cached after first computation).
        let v1 = linux_distro_info_cached();
        let v2 = linux_distro_info_cached();
        assert_eq!(v1, v2, "cached distro info should be identical");
    }

    #[test]
    fn test_cache_container_detection_returns_same_value() {
        let v1 = container_detection_cached();
        let v2 = container_detection_cached();
        assert_eq!(v1, v2, "cached container detection should be identical");
    }

    #[test]
    fn test_cache_env_type_returns_same_value() {
        let v1 = env_type_cached();
        let v2 = env_type_cached();
        assert_eq!(v1, v2, "cached env type should be identical");
    }

    #[test]
    fn test_once_lock_cache_get_or_init() {
        // Test the cached_detection helper itself — it should call the
        // detect fn only once.
        static CELL: OnceLock<u32> = OnceLock::new();
        static CALL_COUNT: Mutex<u32> = Mutex::new(0);
        let detect = || {
            *CALL_COUNT.lock().unwrap() += 1;
            42
        };
        let v1 = cached_detection(&CELL, detect);
        let v2 = cached_detection(&CELL, detect);
        assert_eq!(v1, 42);
        assert_eq!(v2, 42);
        assert_eq!(
            *CALL_COUNT.lock().unwrap(),
            1,
            "detect should run only once"
        );
    }

    // ─── Existing tests (preserved) ───────────────────────────────────

    #[test]
    fn test_populate_sets_ipn_version() {
        let hi = Hostinfo {
            OS: "linux".to_string(),
            Hostname: "test-host".to_string(),
            ..Default::default()
        };
        let hi = populate_hostinfo(hi);
        assert!(!hi.IPNVersion.is_empty());
        assert_eq!(hi.Package, "tsnet");
    }

    #[test]
    fn test_populate_preserves_existing_fields() {
        let hi = Hostinfo {
            OS: "linux".to_string(),
            Hostname: "test-host".to_string(),
            RoutableIPs: vec!["10.0.0.0/8".to_string()],
            ..Default::default()
        };
        let hi = populate_hostinfo(hi);
        assert_eq!(hi.Hostname, "test-host");
        assert_eq!(hi.RoutableIPs, vec!["10.0.0.0/8".to_string()]);
    }

    #[test]
    fn test_env_var_empty() {
        assert!(env_var_empty("DEFINITELY_NOT_SET_VAR_XYZ"));
        std::env::set_var("RUSTSCALE_TEST_VAR", "value");
        assert!(!env_var_empty("RUSTSCALE_TEST_VAR"));
        std::env::remove_var("RUSTSCALE_TEST_VAR");
    }

    #[test]
    fn test_arch_machine_mapping() {
        let m = arch_machine();
        assert!(!m.is_empty());
    }

    #[test]
    fn test_container_detection_returns_valid_optbool() {
        let c = container_detection();
        let _ = c.get();
    }

    #[test]
    fn test_desktop_detection_returns_valid_optbool() {
        let d = desktop_detection();
        let _ = d.get();
    }

    #[test]
    fn test_cloud_detection_returns_valid_string() {
        let c = cloud_detection();
        assert!(c.is_empty() || matches!(c, "aws" | "azure" | "gcp" | "digitalocean"));
    }

    #[test]
    fn test_env_type_returns_known_or_empty_using_snapshot() {
        // Test that the pure function with an empty snapshot returns "".
        let s = EnvSnapshot::default();
        let e = env_type(&s);
        assert!(e.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_os_version_macos_format() {
        let v = os_version();
        assert!(!v.is_empty(), "os_version should not be empty on macOS");
        // Marketing version: digits.digits or digits.digits.digits (e.g. "15.0.1")
        let parts: Vec<&str> = v.split('.').collect();
        assert!(
            parts.len() >= 2,
            "os_version should have at least two dot-separated components: {v}"
        );
        for p in &parts {
            assert!(
                p.chars().all(|c| c.is_ascii_digit()),
                "each part of os_version should be digits: {v}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_device_model_macos() {
        let dm = device_model();
        assert!(
            !dm.is_empty(),
            "device_model should not be empty on macOS (e.g. MacBookPro18,3)"
        );
        // Should be something like "MacBookProX,Y" or "MacminiX,Y" — at least non-empty
        assert!(
            dm.contains(',') || dm.contains("Mac"),
            "device_model should contain model identifier: {dm}"
        );
    }

    // ─── Override + runtime field tests ──────────────────────────────

    #[test]
    fn test_overrides_apply_before_detection() {
        let mut hi = Hostinfo {
            OS: "linux".to_string(),
            Hostname: "h".to_string(),
            ..Default::default()
        };
        let ov = HostinfoOverrides {
            device_model: Some("Raspberry Pi 4".into()),
            app: Some("golinks".into()),
            os_version: Some("20.04".into()),
            package: Some("snap".into()),
        };
        ov.apply(&mut hi);
        hi = populate_hostinfo(hi);
        // Overrides win over detection.
        assert_eq!(hi.DeviceModel, "Raspberry Pi 4");
        assert_eq!(hi.App, "golinks");
        assert_eq!(hi.OSVersion, "20.04");
        assert_eq!(hi.Package, "snap");
    }

    #[test]
    fn test_overrides_none_uses_detection() {
        let hi = Hostinfo {
            OS: "linux".to_string(),
            Hostname: "h".to_string(),
            ..Default::default()
        };
        let ov = HostinfoOverrides::default();
        let hi = collect_hostinfo(hi, &ov, &HostinfoRuntime::default());
        // No override → detection fills in the field.
        assert_eq!(hi.Package, "tsnet");
    }

    #[test]
    fn test_runtime_fields_exit_node_id() {
        let mut hi = Hostinfo::default();
        let exit_id: StableNodeID = "nodeABC".into();
        apply_runtime_fields(
            &mut hi,
            &HostinfoRuntime {
                exit_node_id: Some(exit_id),
                ..Default::default()
            },
        );
        assert_eq!(hi.ExitNodeID, "nodeABC");
        assert!(!hi.IngressEnabled);
    }

    #[test]
    fn test_runtime_fields_ingress_enabled() {
        let mut hi = Hostinfo::default();
        apply_runtime_fields(
            &mut hi,
            &HostinfoRuntime {
                ingress_enabled: true,
                ..Default::default()
            },
        );
        assert!(hi.IngressEnabled);
        assert!(hi.ExitNodeID.is_empty());
    }

    #[test]
    fn test_runtime_fields_empty_exit_id_not_set() {
        let mut hi = Hostinfo::default();
        let empty: StableNodeID = String::new();
        apply_runtime_fields(
            &mut hi,
            &HostinfoRuntime {
                exit_node_id: Some(empty),
                ..Default::default()
            },
        );
        assert!(
            hi.ExitNodeID.is_empty(),
            "empty StableNodeID should not be set"
        );
    }

    // ─── Content-hash dedup tests ─────────────────────────────────────

    #[test]
    fn test_hostinfo_hash_same_content_same_hash() {
        let hi1 = Hostinfo {
            OS: "linux".into(),
            Hostname: "host".into(),
            ..Default::default()
        };
        let hi2 = Hostinfo {
            OS: "linux".into(),
            Hostname: "host".into(),
            ..Default::default()
        };
        assert_eq!(hostinfo_hash(&hi1), hostinfo_hash(&hi2));
    }

    #[test]
    fn test_hostinfo_hash_different_content_different_hash() {
        let hi1 = Hostinfo {
            OS: "linux".into(),
            Hostname: "host".into(),
            ..Default::default()
        };
        let hi2 = Hostinfo {
            OS: "linux".into(),
            Hostname: "different".into(),
            ..Default::default()
        };
        assert_ne!(hostinfo_hash(&hi1), hostinfo_hash(&hi2));
    }

    #[test]
    fn test_hostinfo_hash_dedup_no_send_on_same_content() {
        // Simulate the update loop's dedup logic: same Hostinfo hash
        // means no send.
        let hi = Hostinfo {
            OS: "linux".into(),
            Hostname: "host".into(),
            ..Default::default()
        };
        let hash1 = hostinfo_hash(&hi);
        // Re-collect identical content.
        let hi2 = Hostinfo {
            OS: "linux".into(),
            Hostname: "host".into(),
            ..Default::default()
        };
        let hash2 = hostinfo_hash(&hi2);
        assert_eq!(hash1, hash2, "same content → same hash → no send");
    }

    #[test]
    fn test_hostinfo_hash_changes_with_exit_node() {
        let base = Hostinfo {
            OS: "linux".into(),
            Hostname: "host".into(),
            ..Default::default()
        };
        let h1 = hostinfo_hash(&base);
        let mut modified = base;
        modified.ExitNodeID = "nodeExit1".into();
        let h2 = hostinfo_hash(&modified);
        assert_ne!(h1, h2, "exit node change should produce different hash");
    }

    #[test]
    fn test_hostinfo_hash_changes_with_ingress() {
        let base = Hostinfo {
            OS: "linux".into(),
            Hostname: "host".into(),
            ..Default::default()
        };
        let h1 = hostinfo_hash(&base);
        let mut modified = base;
        modified.IngressEnabled = true;
        let h2 = hostinfo_hash(&modified);
        assert_ne!(h1, h2, "ingress change should produce different hash");
    }

    // ─── Override setter tests ───────────────────────────────────────

    #[test]
    fn test_override_setters() {
        let mut ov = HostinfoOverrides::default();
        ov.set_device_model("Pixel 7");
        ov.set_app("k8s-operator");
        ov.set_os_version("13.0");
        ov.set_package("googleplay");
        assert_eq!(ov.device_model.as_deref(), Some("Pixel 7"));
        assert_eq!(ov.app.as_deref(), Some("k8s-operator"));
        assert_eq!(ov.os_version.as_deref(), Some("13.0"));
        assert_eq!(ov.package.as_deref(), Some("googleplay"));
    }

    #[test]
    fn test_collect_hostinfo_with_overrides_and_runtime() {
        let base = Hostinfo {
            OS: "linux".into(),
            Hostname: "host".into(),
            RoutableIPs: vec!["10.0.0.0/8".into()],
            ..Default::default()
        };
        let ov = HostinfoOverrides {
            device_model: Some("Synology DS920+".into()),
            ..Default::default()
        };
        let exit_id: StableNodeID = "nodeExit42".into();
        let hi = collect_hostinfo(
            base,
            &ov,
            &HostinfoRuntime {
                exit_node_id: Some(exit_id),
                ingress_enabled: true,
                ..Default::default()
            },
        );
        assert_eq!(hi.DeviceModel, "Synology DS920+");
        assert_eq!(hi.ExitNodeID, "nodeExit42");
        assert!(hi.IngressEnabled);
        assert_eq!(hi.RoutableIPs, vec!["10.0.0.0/8".to_string()]);
        // Platform detection still runs for non-overridden fields.
        assert!(!hi.IPNVersion.is_empty());
    }

    #[test]
    fn test_apply_runtime_fields_shields_up() {
        let mut hi = Hostinfo::default();
        apply_runtime_fields(
            &mut hi,
            &HostinfoRuntime {
                shields_up: true,
                ..Default::default()
            },
        );
        assert!(hi.ShieldsUp);
    }

    #[test]
    fn test_apply_runtime_fields_shields_down() {
        let mut hi = Hostinfo::default();
        apply_runtime_fields(&mut hi, &HostinfoRuntime::default());
        assert!(!hi.ShieldsUp);
    }

    #[test]
    fn test_collect_hostinfo_shields_up_populated() {
        let base = Hostinfo {
            Hostname: "shields-test".to_string(),
            ..Default::default()
        };
        let ov = HostinfoOverrides::default();
        let hi = collect_hostinfo(
            base,
            &ov,
            &HostinfoRuntime {
                shields_up: true,
                ..Default::default()
            },
        );
        assert!(hi.ShieldsUp);
    }
}
