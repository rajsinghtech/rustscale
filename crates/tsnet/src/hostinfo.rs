//! Platform-specific host environment detection, porting Go's
//! `tailscale.com/hostinfo` package. Populates the `Hostinfo` struct sent
//! to the control plane with OS version, container/distro detection, cloud
//! metadata, and desktop presence so that control-server features for those
//! environments activate correctly.

#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::fs;
#[allow(unused_imports)]
use std::path::Path;
use std::sync::Arc;

use rustscale_tailcfg::{Hostinfo, OptBool, StableNodeID};
use tokio::sync::RwLock;

/// Package identifier — tsnet embedding layer.
const PACKAGE: &str = "tsnet";

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
    if hi.GoArch.is_empty() {
        hi.GoArch = std::env::consts::ARCH.to_string();
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

    let (distro, dver, dcode) = linux_distro_info();
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
        hi.Container = container_detection();
    }

    if hi.Env.is_empty() {
        hi.Env = env_type().to_string();
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

/// Apply tsnet-runtime fields to a `Hostinfo` that platform detection
/// cannot determine on its own:
///
/// - `ExitNodeID`: the StableNodeID of the currently selected exit node,
///   looked up from the peer list by node key. Empty when no exit node is
///   selected or the peer is not found.
/// - `IngressEnabled`: `true` when a Funnel listener is active (any
///   `AllowFunnel` entry in the serve config is `true`).
///
/// Device-specific fields (`PushDeviceToken`, `TPM`, `StateEncrypted`) are
/// left at their defaults — they require platform APIs not available in the
/// tsnet embedding layer.
pub fn apply_runtime_fields(
    hi: &mut Hostinfo,
    exit_node_id: Option<&StableNodeID>,
    ingress_enabled: bool,
) {
    if let Some(id) = exit_node_id {
        if !id.is_empty() {
            hi.ExitNodeID.clone_from(id);
        }
    }
    hi.IngressEnabled = ingress_enabled;
}

/// Collect a full `Hostinfo`: apply overrides, run platform detection, then
/// apply runtime fields. This is the single entry point used by both the
/// initial MapRequest send and the periodic update loop.
pub fn collect_hostinfo(
    base: Hostinfo,
    overrides: &HostinfoOverrides,
    exit_node_id: Option<&StableNodeID>,
    ingress_enabled: bool,
) -> Hostinfo {
    let mut hi = base;
    overrides.apply(&mut hi);
    hi = populate_hostinfo(hi);
    apply_runtime_fields(&mut hi, exit_node_id, ingress_enabled);
    hi
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
    // Go uses sysctl("kern.osproductversion") on macOS. We shell out to
    // `sw_vers -productVersion` which returns the same marketing version.
    if let Ok(out) = std::process::Command::new("sw_vers")
        .args(["-productVersion"])
        .output()
    {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    if let Ok(out) = std::process::Command::new("uname").arg("-r").output() {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    String::new()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn os_version() -> String {
    String::new()
}

// ─── uname (Linux) ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn uname() -> Result<String, std::io::Error> {
    let out = std::process::Command::new("uname")
        .arg("-r")
        .output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "uname failed",
        ))
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

// ─── Linux distro info from /etc/os-release ───────────────────────────

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

// ─── Container detection ──────────────────────────────────────────────

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
            if content.contains("/docker/") || content.contains("/lxc/") {
                return OptBool::True;
            }
        }
        if let Ok(content) = fs::read_to_string("/proc/mounts") {
            if content.contains("lxcfs /proc/cpuinfo fuse.lxcfs") {
                return OptBool::True;
            }
        }
        return OptBool::False;
    }
    #[cfg(not(target_os = "linux"))]
    {
        OptBool::Unset
    }
}

// ─── Environment type ─────────────────────────────────────────────────

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

/// Detect the runtime environment by checking characteristic env vars.
/// Mirrors Go's `hostinfo.getEnvType`.
fn env_type() -> &'static str {
    if in_knative() {
        return env::KNATIVE;
    }
    if in_aws_lambda() {
        return env::AWS_LAMBDA;
    }
    if in_heroku() {
        return env::HEROKU;
    }
    if in_azure_app_service() {
        return env::AZURE_APP_SERVICE;
    }
    if in_aws_fargate() {
        return env::AWS_FARGATE;
    }
    if in_fly() {
        return env::FLY;
    }
    if in_kubernetes() {
        return env::KUBERNETES;
    }
    if in_docker_desktop() {
        return env::DOCKER_DESKTOP;
    }
    if in_replit() {
        return env::REPLIT;
    }
    if in_home_assistant() {
        return env::HOME_ASSISTANT;
    }
    ""
}

fn in_knative() -> bool {
    !env_var_empty("K_REVISION")
        && !env_var_empty("K_CONFIGURATION")
        && !env_var_empty("K_SERVICE")
        && !env_var_empty("PORT")
}

fn in_aws_lambda() -> bool {
    !env_var_empty("AWS_LAMBDA_FUNCTION_NAME")
        && !env_var_empty("AWS_LAMBDA_FUNCTION_VERSION")
        && !env_var_empty("AWS_LAMBDA_INITIALIZATION_TYPE")
        && !env_var_empty("AWS_LAMBDA_RUNTIME_API")
}

fn in_heroku() -> bool {
    !env_var_empty("PORT") && !env_var_empty("DYNO")
}

fn in_azure_app_service() -> bool {
    !env_var_empty("APPSVC_RUN_ZIP")
        && !env_var_empty("WEBSITE_STACK")
        && !env_var_empty("WEBSITE_AUTH_AUTO_AAD")
}

fn in_aws_fargate() -> bool {
    std::env::var("AWS_EXECUTION_ENV").as_deref() == Ok("AWS_ECS_FARGATE")
}

fn in_fly() -> bool {
    !env_var_empty("FLY_APP_NAME") && !env_var_empty("FLY_REGION")
}

fn in_kubernetes() -> bool {
    !env_var_empty("KUBERNETES_SERVICE_HOST") && !env_var_empty("KUBERNETES_SERVICE_PORT")
}

fn in_docker_desktop() -> bool {
    std::env::var("TS_HOST_ENV").as_deref() == Ok("dde")
}

fn in_replit() -> bool {
    !env_var_empty("REPL_OWNER") && !env_var_empty("REPL_SLUG")
}

fn in_home_assistant() -> bool {
    !env_var_empty("SUPERVISOR_TOKEN") || !env_var_empty("HASSIO_TOKEN")
}

fn env_var_empty(key: &str) -> bool {
    std::env::var(key).map(|v| v.is_empty()).unwrap_or(true)
}

// ─── Desktop detection (Linux) ────────────────────────────────────────

/// Detect whether a desktop (X11 or Wayland) is running on Linux.
/// Mirrors Go's `hostinfo.desktop` — checks `/proc/net/unix` for
/// `.X11-unix` or `/wayland-1` socket entries.
fn desktop_detection() -> OptBool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = fs::read_to_string("/proc/net/unix") {
            let has_desktop = content.contains(".X11-unix") || content.contains("/wayland-1");
            return OptBool::new(has_desktop);
        }
        return OptBool::Unset;
    }
    #[cfg(not(target_os = "linux"))]
    {
        OptBool::Unset
    }
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

#[allow(dead_code)]
fn read_trim(path: &str) -> String {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

// ─── Rust toolchain version ───────────────────────────────────────────

/// Returns the Rust compiler version, analogous to Go's `runtime.Version()`.
fn rustc_version() -> String {
    option_env!("RUSTC_VERSION")
        .unwrap_or("rust")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_env_type_returns_known_or_empty() {
        let e = env_type();
        assert!(
            e.is_empty()
                || matches!(
                    e,
                    "kn" | "lm" | "hr" | "az" | "fg" | "fly" | "k8s" | "dde" | "repl" | "haao"
                )
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_os_version_macos() {
        let v = os_version();
        assert!(!v.is_empty());
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
        let hi = collect_hostinfo(hi, &ov, None, false);
        // No override → detection fills in the field.
        assert_eq!(hi.Package, "tsnet");
    }

    #[test]
    fn test_runtime_fields_exit_node_id() {
        let mut hi = Hostinfo::default();
        let exit_id: StableNodeID = "nodeABC".into();
        apply_runtime_fields(&mut hi, Some(&exit_id), false);
        assert_eq!(hi.ExitNodeID, "nodeABC");
        assert!(!hi.IngressEnabled);
    }

    #[test]
    fn test_runtime_fields_ingress_enabled() {
        let mut hi = Hostinfo::default();
        apply_runtime_fields(&mut hi, None, true);
        assert!(hi.IngressEnabled);
        assert!(hi.ExitNodeID.is_empty());
    }

    #[test]
    fn test_runtime_fields_empty_exit_id_not_set() {
        let mut hi = Hostinfo::default();
        let empty: StableNodeID = String::new();
        apply_runtime_fields(&mut hi, Some(&empty), false);
        assert!(hi.ExitNodeID.is_empty(), "empty StableNodeID should not be set");
    }

    // ─── Content-hash dedup tests ────────────────────────────────────

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
        let hi = collect_hostinfo(base, &ov, Some(&exit_id), true);
        assert_eq!(hi.DeviceModel, "Synology DS920+");
        assert_eq!(hi.ExitNodeID, "nodeExit42");
        assert!(hi.IngressEnabled);
        assert_eq!(hi.RoutableIPs, vec!["10.0.0.0/8".to_string()]);
        // Platform detection still runs for non-overridden fields.
        assert!(!hi.IPNVersion.is_empty());
    }
}
