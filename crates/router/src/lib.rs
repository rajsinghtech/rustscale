//! OS route management for TUN mode.
//!
//! Phase 1 deliberately uses the platform `route`, `ifconfig`, and `ip`
//! commands behind [`Router`]. Phase 2 will replace those commands with native
//! PF_ROUTE and netlink implementations, including Linux table-52 policy
//! routing. `UpdateMagicsockPort` is intentionally not part of this phase.

#![forbid(unsafe_code)]

use std::{
    fmt,
    net::IpAddr,
    process::{Command, Stdio},
};

use rustscale_tsaddr::IpPrefix;

/// The subset of Tailscale's router configuration needed by rustscale.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouterConfig {
    /// Addresses configured on the TUN interface.
    pub local_addrs: Vec<IpAddr>,
    /// Prefixes that route through the TUN interface.
    pub routes: Vec<IpPrefix>,
    /// Prefixes that bypass the TUN interface (Linux throw routes in phase 1).
    pub local_routes: Vec<IpPrefix>,
    /// Whether default-route overrides for a selected exit node are installed.
    pub exit_node: bool,
}

/// Operations produced by the pure configuration diff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouterOperation {
    Up,
    Down,
    AddAddr(IpAddr),
    RemoveAddr(IpAddr),
    AddRoute(IpPrefix),
    RemoveRoute(IpPrefix),
    AddLocalRoute(IpPrefix),
    RemoveLocalRoute(IpPrefix),
    AddExitRoutes,
    RemoveExitRoutes,
}

/// The pure delta between two router configurations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouterDiff {
    pub remove_addrs: Vec<IpAddr>,
    pub add_addrs: Vec<IpAddr>,
    pub remove_routes: Vec<IpPrefix>,
    pub add_routes: Vec<IpPrefix>,
    pub remove_local_routes: Vec<IpPrefix>,
    pub add_local_routes: Vec<IpPrefix>,
    pub remove_exit_routes: bool,
    pub add_exit_routes: bool,
}

impl RouterDiff {
    /// Convert the delta to a stable sequence of operations.
    pub fn operations(&self) -> Vec<RouterOperation> {
        let mut operations = Vec::new();
        if self.remove_exit_routes {
            operations.push(RouterOperation::RemoveExitRoutes);
        }
        operations.extend(
            self.remove_routes
                .iter()
                .copied()
                .map(RouterOperation::RemoveRoute),
        );
        operations.extend(
            self.remove_local_routes
                .iter()
                .copied()
                .map(RouterOperation::RemoveLocalRoute),
        );
        operations.extend(
            self.remove_addrs
                .iter()
                .copied()
                .map(RouterOperation::RemoveAddr),
        );
        operations.extend(self.add_addrs.iter().copied().map(RouterOperation::AddAddr));
        operations.extend(
            self.add_routes
                .iter()
                .copied()
                .map(RouterOperation::AddRoute),
        );
        operations.extend(
            self.add_local_routes
                .iter()
                .copied()
                .map(RouterOperation::AddLocalRoute),
        );
        if self.add_exit_routes {
            operations.push(RouterOperation::AddExitRoutes);
        }
        operations
    }

    fn teardown_operations(&self) -> Vec<RouterOperation> {
        let mut operations = Vec::new();
        if self.remove_exit_routes {
            operations.push(RouterOperation::RemoveExitRoutes);
        }
        operations.extend(
            self.remove_routes
                .iter()
                .copied()
                .map(RouterOperation::RemoveRoute),
        );
        operations.extend(
            self.remove_local_routes
                .iter()
                .copied()
                .map(RouterOperation::RemoveLocalRoute),
        );
        operations.extend(
            self.remove_addrs
                .iter()
                .copied()
                .map(RouterOperation::RemoveAddr),
        );
        operations.push(RouterOperation::Down);
        operations
    }
}

/// Compute the configuration delta without performing any OS operation.
pub fn diff(previous: Option<&RouterConfig>, next: &RouterConfig) -> RouterDiff {
    let previous = previous.cloned().unwrap_or_default();
    RouterDiff {
        remove_addrs: vec_difference(&previous.local_addrs, &next.local_addrs),
        add_addrs: vec_difference(&next.local_addrs, &previous.local_addrs),
        remove_routes: prefix_difference(&previous.routes, &next.routes),
        add_routes: prefix_difference(&next.routes, &previous.routes),
        remove_local_routes: prefix_difference(&previous.local_routes, &next.local_routes),
        add_local_routes: prefix_difference(&next.local_routes, &previous.local_routes),
        remove_exit_routes: previous.exit_node && !next.exit_node,
        add_exit_routes: !previous.exit_node && next.exit_node,
    }
}

fn vec_difference<T: Copy + Eq>(left: &[T], right: &[T]) -> Vec<T> {
    let mut result = Vec::new();
    for item in left {
        if !right.contains(item) && !result.contains(item) {
            result.push(*item);
        }
    }
    result
}

fn prefix_difference(left: &[IpPrefix], right: &[IpPrefix]) -> Vec<IpPrefix> {
    vec_difference(left, right)
}

/// An error returned while applying a route operation.
#[derive(Debug)]
pub enum RouterError {
    Command {
        program: String,
        args: Vec<String>,
        exit_code: Option<i32>,
        stderr: String,
    },
    Io(std::io::Error),
    Unsupported,
}

impl RouterError {
    fn non_fatal(&self) -> bool {
        let Self::Command { stderr, .. } = self else {
            return false;
        };
        let stderr = stderr.to_ascii_lowercase();
        stderr.contains("file exists")
            || stderr.contains("already exists")
            || stderr.contains("not in table")
            || stderr.contains("no such process")
            || stderr.contains("not found")
    }
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command {
                program,
                args,
                exit_code,
                stderr,
            } => write!(f, "{program} {args:?} failed ({exit_code:?}): {stderr}"),
            Self::Io(error) => write!(f, "router command failed to start: {error}"),
            Self::Unsupported => f.write_str("OS route management is unsupported on this platform"),
        }
    }
}

impl std::error::Error for RouterError {}

/// Platform router interface. Phase 1 intentionally omits `UpdateMagicsockPort`.
pub trait Router: Send + Sync {
    /// Bring the TUN interface up.
    fn up(&mut self) -> Result<(), RouterError>;
    /// Incrementally apply a configuration.
    fn set(&mut self, config: &RouterConfig) -> Result<(), RouterError>;
    /// Remove all installed state and bring the interface down.
    fn close(&mut self) -> Result<(), RouterError>;
}

trait CommandRunner: Send + Sync {
    fn run(&mut self, program: &str, args: &[String]) -> Result<(), RouterError>;
}

#[derive(Default)]
struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&mut self, program: &str, args: &[String]) -> Result<(), RouterError> {
        let output = Command::new(program)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(RouterError::Io)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(RouterError::Command {
                program: program.to_owned(),
                args: args.to_vec(),
                exit_code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        }
    }
}

trait Platform: Send + Sync {
    fn commands(&self, operation: &RouterOperation) -> Vec<(String, Vec<String>)>;
}

struct StatefulRouter<P, R> {
    platform: P,
    runner: R,
    config: Option<RouterConfig>,
    is_up: bool,
}

impl<P: Platform, R: CommandRunner> StatefulRouter<P, R> {
    fn new(platform: P, runner: R) -> Self {
        Self {
            platform,
            runner,
            config: None,
            is_up: false,
        }
    }

    fn apply(&mut self, operations: &[RouterOperation]) -> Result<(), RouterError> {
        let mut first_error = None;
        for operation in operations {
            for (program, args) in self.platform.commands(operation) {
                if let Err(error) = self.runner.run(&program, &args) {
                    if !error.non_fatal() && first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl<P: Platform, R: CommandRunner> Router for StatefulRouter<P, R> {
    fn up(&mut self) -> Result<(), RouterError> {
        if self.is_up {
            return Ok(());
        }
        self.apply(&[RouterOperation::Up])?;
        self.is_up = true;
        Ok(())
    }

    fn set(&mut self, config: &RouterConfig) -> Result<(), RouterError> {
        let delta = diff(self.config.as_ref(), config);
        self.apply(&delta.operations())?;
        self.config = Some(config.clone());
        Ok(())
    }

    fn close(&mut self) -> Result<(), RouterError> {
        if !self.is_up && self.config.is_none() {
            return Ok(());
        }
        let empty = RouterConfig::default();
        let delta = diff(self.config.as_ref(), &empty);
        let result = self.apply(&delta.teardown_operations());
        self.config = None;
        self.is_up = false;
        result
    }
}

#[cfg(target_os = "macos")]
struct DarwinPlatform {
    tun_name: String,
}

#[cfg(target_os = "macos")]
impl DarwinPlatform {
    fn new(tun_name: &str) -> Self {
        Self {
            tun_name: tun_name.to_owned(),
        }
    }

    fn route(&self, verb: &str, prefix: IpPrefix) -> (String, Vec<String>) {
        let family = if prefix.ip.is_ipv4() {
            "-inet"
        } else {
            "-inet6"
        };
        (
            "route".into(),
            vec![
                "-q".into(),
                "-n".into(),
                verb.into(),
                family.into(),
                prefix.to_string(),
                "-iface".into(),
                self.tun_name.clone(),
            ],
        )
    }

    fn address(&self, add: bool, address: IpAddr) -> (String, Vec<String>) {
        let family = if address.is_ipv4() { "inet" } else { "inet6" };
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let cidr = format!("{address}/{bits}");
        let mut args = vec![self.tun_name.clone(), family.into(), cidr];
        if add {
            if address.is_ipv4() {
                args.push(address.to_string());
            }
        } else {
            args.push("-alias".into());
        }
        ("ifconfig".into(), args)
    }
}

#[cfg(target_os = "macos")]
impl Platform for DarwinPlatform {
    fn commands(&self, operation: &RouterOperation) -> Vec<(String, Vec<String>)> {
        match operation {
            RouterOperation::Up => {
                vec![("ifconfig".into(), vec![self.tun_name.clone(), "up".into()])]
            }
            RouterOperation::Down => vec![(
                "ifconfig".into(),
                vec![self.tun_name.clone(), "down".into()],
            )],
            RouterOperation::AddAddr(address) => vec![self.address(true, *address)],
            RouterOperation::RemoveAddr(address) => vec![self.address(false, *address)],
            RouterOperation::AddRoute(prefix) => vec![self.route("add", *prefix)],
            RouterOperation::RemoveRoute(prefix) => vec![self.route("delete", *prefix)],
            // macOS has no phase-1 equivalent of Linux throw routes.
            RouterOperation::AddLocalRoute(_) | RouterOperation::RemoveLocalRoute(_) => vec![],
            RouterOperation::AddExitRoutes => self.exit_routes("add"),
            RouterOperation::RemoveExitRoutes => self.exit_routes("delete"),
        }
    }
}

#[cfg(target_os = "macos")]
/// Shell-command-backed macOS router for phase 1.
pub struct DarwinRouter(StatefulRouter<DarwinPlatform, SystemCommandRunner>);

#[cfg(target_os = "macos")]
impl DarwinPlatform {
    fn exit_routes(&self, verb: &str) -> Vec<(String, Vec<String>)> {
        ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
            .into_iter()
            .map(|prefix| self.route(verb, IpPrefix::parse(prefix).expect("valid exit prefix")))
            .collect()
    }
}

#[cfg(target_os = "macos")]
impl DarwinRouter {
    /// Construct a router for `tun_name`.
    pub fn new(tun_name: &str) -> Self {
        Self(StatefulRouter::new(
            DarwinPlatform::new(tun_name),
            SystemCommandRunner,
        ))
    }
}

#[cfg(target_os = "macos")]
impl Router for DarwinRouter {
    fn up(&mut self) -> Result<(), RouterError> {
        self.0.up()
    }
    fn set(&mut self, config: &RouterConfig) -> Result<(), RouterError> {
        self.0.set(config)
    }
    fn close(&mut self) -> Result<(), RouterError> {
        self.0.close()
    }
}

#[cfg(target_os = "linux")]
struct LinuxPlatform {
    tun_name: String,
}

#[cfg(target_os = "linux")]
impl LinuxPlatform {
    fn new(tun_name: &str) -> Self {
        Self {
            tun_name: tun_name.to_owned(),
        }
    }

    fn route(&self, verb: &str, prefix: IpPrefix) -> (String, Vec<String>) {
        let mut args = Vec::new();
        if prefix.ip.is_ipv6() {
            args.push("-6".into());
        }
        args.extend([
            "route".into(),
            verb.into(),
            prefix.to_string(),
            "dev".into(),
            self.tun_name.clone(),
        ]);
        ("ip".into(), args)
    }
}

#[cfg(target_os = "linux")]
impl Platform for LinuxPlatform {
    fn commands(&self, operation: &RouterOperation) -> Vec<(String, Vec<String>)> {
        match operation {
            RouterOperation::Up => vec![(
                "ip".into(),
                vec![
                    "link".into(),
                    "set".into(),
                    self.tun_name.clone(),
                    "up".into(),
                ],
            )],
            RouterOperation::Down => vec![(
                "ip".into(),
                vec![
                    "link".into(),
                    "set".into(),
                    self.tun_name.clone(),
                    "down".into(),
                ],
            )],
            RouterOperation::AddAddr(address) => vec![(
                "ip".into(),
                vec![
                    "addr".into(),
                    "add".into(),
                    format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 }),
                    "dev".into(),
                    self.tun_name.clone(),
                ],
            )],
            RouterOperation::RemoveAddr(address) => vec![(
                "ip".into(),
                vec![
                    "addr".into(),
                    "del".into(),
                    format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 }),
                    "dev".into(),
                    self.tun_name.clone(),
                ],
            )],
            RouterOperation::AddRoute(prefix) => vec![self.route("add", *prefix)],
            RouterOperation::RemoveRoute(prefix) => vec![self.route("del", *prefix)],
            RouterOperation::AddLocalRoute(prefix) => vec![("ip".into(), {
                let mut args = Vec::new();
                if prefix.ip.is_ipv6() {
                    args.push("-6".into());
                }
                args.extend([
                    "route".into(),
                    "add".into(),
                    "throw".into(),
                    prefix.to_string(),
                    "table".into(),
                    "52".into(),
                ]);
                args
            })],
            RouterOperation::RemoveLocalRoute(prefix) => vec![("ip".into(), {
                let mut args = Vec::new();
                if prefix.ip.is_ipv6() {
                    args.push("-6".into());
                }
                args.extend([
                    "route".into(),
                    "del".into(),
                    "throw".into(),
                    prefix.to_string(),
                    "table".into(),
                    "52".into(),
                ]);
                args
            })],
            RouterOperation::AddExitRoutes => vec![
                self.route("add", rustscale_tsaddr::all_ipv4()),
                self.route("add", rustscale_tsaddr::all_ipv6()),
            ],
            RouterOperation::RemoveExitRoutes => vec![
                self.route("del", rustscale_tsaddr::all_ipv4()),
                self.route("del", rustscale_tsaddr::all_ipv6()),
            ],
        }
    }
}

#[cfg(target_os = "linux")]
/// Shell-command-backed Linux router for phase 1.
pub struct LinuxRouter(StatefulRouter<LinuxPlatform, SystemCommandRunner>);

#[cfg(target_os = "linux")]
impl LinuxRouter {
    /// Construct a router for `tun_name`.
    pub fn new(tun_name: &str) -> Self {
        Self(StatefulRouter::new(
            LinuxPlatform::new(tun_name),
            SystemCommandRunner,
        ))
    }
}

#[cfg(target_os = "linux")]
impl Router for LinuxRouter {
    fn up(&mut self) -> Result<(), RouterError> {
        self.0.up()
    }
    fn set(&mut self, config: &RouterConfig) -> Result<(), RouterError> {
        self.0.set(config)
    }
    fn close(&mut self) -> Result<(), RouterError> {
        self.0.close()
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
struct UnsupportedRouter;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl Router for UnsupportedRouter {
    fn up(&mut self) -> Result<(), RouterError> {
        Err(RouterError::Unsupported)
    }
    fn set(&mut self, _config: &RouterConfig) -> Result<(), RouterError> {
        Err(RouterError::Unsupported)
    }
    fn close(&mut self) -> Result<(), RouterError> {
        Ok(())
    }
}

/// Construct the router appropriate for the current platform.
pub fn new(tun_name: &str) -> Box<dyn Router> {
    #[cfg(target_os = "macos")]
    return Box::new(DarwinRouter::new(tun_name));
    #[cfg(target_os = "linux")]
    return Box::new(LinuxRouter::new(tun_name));
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = tun_name;
        Box::new(UnsupportedRouter)
    }
}

/// In-memory router for unit tests and embedding tests. It never executes a
/// shell command; callers can inspect the recorded operations.
#[derive(Default)]
pub struct FakeRouter {
    config: Option<RouterConfig>,
    is_up: bool,
    operations: Vec<RouterOperation>,
}

impl FakeRouter {
    /// Recorded operations in application order.
    pub fn operations(&self) -> &[RouterOperation] {
        &self.operations
    }
    /// Clear recorded operations while retaining the installed configuration.
    pub fn clear_operations(&mut self) {
        self.operations.clear();
    }
}

impl Router for FakeRouter {
    fn up(&mut self) -> Result<(), RouterError> {
        if !self.is_up {
            self.operations.push(RouterOperation::Up);
            self.is_up = true;
        }
        Ok(())
    }

    fn set(&mut self, config: &RouterConfig) -> Result<(), RouterError> {
        self.operations
            .extend(diff(self.config.as_ref(), config).operations());
        self.config = Some(config.clone());
        Ok(())
    }

    fn close(&mut self) -> Result<(), RouterError> {
        if !self.is_up && self.config.is_none() {
            return Ok(());
        }
        self.operations
            .extend(diff(self.config.as_ref(), &RouterConfig::default()).teardown_operations());
        self.config = None;
        self.is_up = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn prefix(value: &str) -> IpPrefix {
        IpPrefix::parse(value).unwrap()
    }

    fn config() -> RouterConfig {
        RouterConfig {
            local_addrs: vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
            routes: vec![prefix("100.64.0.0/10")],
            local_routes: vec![],
            exit_node: false,
        }
    }

    #[test]
    fn no_op_set_records_no_operations() {
        let mut router = FakeRouter::default();
        router.up().unwrap();
        router.set(&config()).unwrap();
        router.clear_operations();
        router.set(&config()).unwrap();
        assert!(router.operations().is_empty());
    }

    #[test]
    fn address_change_removes_then_adds() {
        let mut router = FakeRouter::default();
        router.set(&config()).unwrap();
        router.clear_operations();
        let mut changed = config();
        changed.local_addrs = vec![IpAddr::V6(Ipv6Addr::LOCALHOST)];
        router.set(&changed).unwrap();
        assert_eq!(
            router.operations(),
            [
                RouterOperation::RemoveAddr(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
                RouterOperation::AddAddr(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ]
        );
    }

    #[test]
    fn route_add_and_remove_mix_is_incremental() {
        let mut router = FakeRouter::default();
        router.set(&config()).unwrap();
        router.clear_operations();
        let mut changed = config();
        changed.routes = vec![prefix("10.0.0.0/8")];
        changed.local_routes = vec![prefix("192.168.0.0/16")];
        router.set(&changed).unwrap();
        assert_eq!(
            router.operations(),
            [
                RouterOperation::RemoveRoute(prefix("100.64.0.0/10")),
                RouterOperation::AddRoute(prefix("10.0.0.0/8")),
                RouterOperation::AddLocalRoute(prefix("192.168.0.0/16")),
            ]
        );
    }

    #[test]
    fn local_route_diff_removes_before_adding_replacements() {
        let mut previous = config();
        previous.local_routes = vec![prefix("192.168.0.0/16")];
        let mut next = config();
        next.local_routes = vec![prefix("10.0.0.0/8")];

        assert_eq!(
            diff(Some(&previous), &next).operations(),
            [
                RouterOperation::RemoveLocalRoute(prefix("192.168.0.0/16")),
                RouterOperation::AddLocalRoute(prefix("10.0.0.0/8")),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_local_routes_use_tailscale_table_52() {
        let platform = LinuxPlatform::new("tailscale0");
        let commands = platform.commands(&RouterOperation::AddLocalRoute(prefix("192.0.2.0/24")));
        assert_eq!(
            commands,
            vec![(
                ("ip").into(),
                vec![
                    "route".into(),
                    "add".into(),
                    "throw".into(),
                    "192.0.2.0/24".into(),
                    "table".into(),
                    "52".into(),
                ]
            )]
        );
    }

    #[test]
    fn exit_node_toggle_only_changes_exit_routes() {
        let mut router = FakeRouter::default();
        router.set(&config()).unwrap();
        router.clear_operations();
        let mut changed = config();
        changed.exit_node = true;
        router.set(&changed).unwrap();
        assert_eq!(router.operations(), [RouterOperation::AddExitRoutes]);
        router.clear_operations();
        changed.exit_node = false;
        router.set(&changed).unwrap();
        assert_eq!(router.operations(), [RouterOperation::RemoveExitRoutes]);
    }

    #[test]
    fn close_removes_everything_and_is_idempotent() {
        let mut router = FakeRouter::default();
        let mut installed = config();
        installed.exit_node = true;
        installed.local_routes = vec![prefix("192.168.0.0/16")];
        router.up().unwrap();
        router.set(&installed).unwrap();
        router.clear_operations();
        router.close().unwrap();
        assert_eq!(
            router.operations(),
            [
                RouterOperation::RemoveExitRoutes,
                RouterOperation::RemoveRoute(prefix("100.64.0.0/10")),
                RouterOperation::RemoveLocalRoute(prefix("192.168.0.0/16")),
                RouterOperation::RemoveAddr(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
                RouterOperation::Down,
            ]
        );
        router.clear_operations();
        router.close().unwrap();
        assert!(router.operations().is_empty());
    }
}
