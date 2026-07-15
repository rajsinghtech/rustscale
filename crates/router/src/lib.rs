//! OS route management for TUN mode.
//!
//! Phase 1 deliberately uses the platform `route`, `ifconfig`, and `ip`
//! commands behind [`Router`]. Phase 2 will replace those commands with native
//! PF_ROUTE and netlink implementations. `UpdateMagicsockPort` is intentionally
//! not part of this phase.

#![forbid(unsafe_code)]

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::{Command, Stdio};
use std::{fmt, net::IpAddr};

use rustscale_tsaddr::IpPrefix;

/// The subset of Tailscale's router configuration needed by rustscale.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouterConfig {
    /// Addresses configured on the TUN interface.
    pub local_addrs: Vec<IpAddr>,
    /// Prefixes that route through the TUN interface.
    pub routes: Vec<IpPrefix>,
    /// Prefixes that bypass the TUN interface (Linux throw routes in table 52).
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
    EnableDirectBlock,
    DisableDirectBlock,
}

impl RouterOperation {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn inverse(&self) -> Self {
        match self {
            Self::Up => Self::Down,
            Self::Down => Self::Up,
            Self::AddAddr(address) => Self::RemoveAddr(*address),
            Self::RemoveAddr(address) => Self::AddAddr(*address),
            Self::AddRoute(prefix) => Self::RemoveRoute(*prefix),
            Self::RemoveRoute(prefix) => Self::AddRoute(*prefix),
            Self::AddLocalRoute(prefix) => Self::RemoveLocalRoute(*prefix),
            Self::RemoveLocalRoute(prefix) => Self::AddLocalRoute(*prefix),
            Self::AddExitRoutes => Self::RemoveExitRoutes,
            Self::RemoveExitRoutes => Self::AddExitRoutes,
            Self::EnableDirectBlock => Self::DisableDirectBlock,
            Self::DisableDirectBlock => Self::EnableDirectBlock,
        }
    }
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
        // Add bypasses before removing stale ones to avoid transient loops.
        operations.extend(
            self.add_local_routes
                .iter()
                .copied()
                .map(RouterOperation::AddLocalRoute),
        );
        // New TUN routes must exist before removing a bypass (LAN allow →
        // deny); otherwise a connected route can leak during the transition.
        operations.extend(
            self.add_routes
                .iter()
                .copied()
                .map(RouterOperation::AddRoute),
        );
        operations.extend(
            self.remove_local_routes
                .iter()
                .copied()
                .map(RouterOperation::RemoveLocalRoute),
        );
        operations.extend(
            self.remove_routes
                .iter()
                .copied()
                .map(RouterOperation::RemoveRoute),
        );
        operations.extend(
            self.remove_addrs
                .iter()
                .copied()
                .map(RouterOperation::RemoveAddr),
        );
        operations.extend(self.add_addrs.iter().copied().map(RouterOperation::AddAddr));
        if self.add_exit_routes {
            // Catch-all routes are always last, after every required bypass.
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

impl RouterConfig {
    fn normalized(&self) -> Result<Self, RouterError> {
        let mut local_addrs: Vec<_> = self.local_addrs.iter().copied().map(normalize_ip).collect();
        local_addrs.sort_unstable();
        local_addrs.dedup();

        let mut routes = normalize_prefixes(&self.routes)?;
        let mut local_routes = normalize_prefixes(&self.local_routes)?;
        rustscale_tsaddr::sort_prefixes(&mut routes);
        rustscale_tsaddr::sort_prefixes(&mut local_routes);
        routes.dedup();
        local_routes.dedup();

        Ok(Self {
            local_addrs,
            routes,
            local_routes,
            exit_node: self.exit_node,
        })
    }
}

fn normalize_prefixes(prefixes: &[IpPrefix]) -> Result<Vec<IpPrefix>, RouterError> {
    prefixes
        .iter()
        .copied()
        .map(|prefix| {
            let ip = normalize_ip(prefix.ip);
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if prefix.bits > max {
                return Err(RouterError::InvalidConfig(format!(
                    "invalid prefix length in {ip}/{}",
                    prefix.bits
                )));
            }
            let ip = match ip {
                IpAddr::V4(ip) => {
                    let mask = u32::MAX
                        .checked_shl(u32::from(32 - prefix.bits))
                        .unwrap_or(0);
                    IpAddr::V4((u32::from(ip) & mask).into())
                }
                IpAddr::V6(ip) => {
                    let mask = u128::MAX
                        .checked_shl(u32::from(128 - prefix.bits))
                        .unwrap_or(0);
                    IpAddr::V6((u128::from(ip) & mask).into())
                }
            };
            Ok(IpPrefix {
                ip,
                bits: prefix.bits,
            })
        })
        .collect()
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}

/// Compute the configuration delta without performing any OS operation.
/// Callers that apply the result first normalize with [`RouterConfig::normalized`].
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
    InvalidConfig(String),
    Command {
        program: String,
        args: Vec<String>,
        exit_code: Option<i32>,
        stderr: String,
    },
    Io(std::io::Error),
    Transaction {
        primary: Box<RouterError>,
        rollback: Vec<RouterError>,
    },
    Unsupported,
}

impl RouterError {
    #[cfg(any(target_os = "macos", target_os = "linux", test))]
    fn non_fatal(&self) -> bool {
        let Self::Command {
            program,
            args,
            exit_code,
            stderr,
            ..
        } = self
        else {
            return false;
        };
        let stderr = stderr.to_ascii_lowercase();
        // A kernel with IPv6 disabled rejects only the IPv6 variant of these
        // commands with this precise netlink error. Tailscale detects this at
        // startup and skips IPv6 programming; accepting this one result lets
        // the command-backed router behave equivalently without concealing
        // permission, syntax, or IPv4 failures.
        if program == "ip"
            && args.iter().any(|arg| arg == "-6")
            && stderr.trim() == "rtnetlink answers: address family not supported by protocol"
        {
            return true;
        }
        let is_remove = args.iter().any(|arg| arg == "del" || arg == "delete");
        // Duplicate adds are deliberately fatal. Without a native ownership
        // probe, accepting EEXIST would claim a foreign route and later delete
        // it during churn or teardown.
        if !is_remove {
            return false;
        }
        let missing = stderr.contains("not in table")
            || stderr.contains("no such process")
            || stderr.contains("no such file or directory")
            || stderr.contains("not found");
        let syntax_error = stderr.contains("usage")
            || stderr.contains("invalid")
            || stderr.contains("unknown")
            || stderr.contains("syntax");
        let is_linux_ip_rule_del = program == "ip"
            && args
                .windows(2)
                .any(|args| args[0] == "rule" && args[1] == "del");
        missing
            || (!syntax_error
                && stderr.trim().is_empty()
                && is_linux_ip_rule_del
                && matches!(exit_code, Some(2 | 254)))
    }
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(f, "invalid router configuration: {error}"),
            Self::Command {
                program,
                args,
                exit_code,
                stderr,
            } => write!(f, "{program} {args:?} failed ({exit_code:?}): {stderr}"),
            Self::Io(error) => write!(f, "router command failed to start: {error}"),
            Self::Transaction { primary, rollback } => {
                write!(f, "router transaction failed: {primary}")?;
                for error in rollback {
                    write!(f, "; rollback failed: {error}")?;
                }
                Ok(())
            }
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
    /// Install a kernel-level emergency block for unprotected direct traffic.
    fn block_direct(&mut self) -> Result<(), RouterError> {
        Err(RouterError::Unsupported)
    }
    /// Remove the emergency block after route synchronization succeeds.
    fn unblock_direct(&mut self) -> Result<(), RouterError> {
        Err(RouterError::Unsupported)
    }
    /// Remove all installed state and bring the interface down.
    fn close(&mut self) -> Result<(), RouterError>;
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
trait CommandRunner: Send + Sync {
    fn run(&mut self, program: &str, args: &[String]) -> Result<(), RouterError>;

    fn output(&mut self, program: &str, args: &[String]) -> Result<String, RouterError> {
        self.run(program, args)?;
        Ok(String::new())
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Default)]
struct SystemCommandRunner;

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl CommandRunner for SystemCommandRunner {
    fn run(&mut self, program: &str, args: &[String]) -> Result<(), RouterError> {
        self.output(program, args).map(|_| ())
    }

    fn output(&mut self, program: &str, args: &[String]) -> Result<String, RouterError> {
        let output = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(RouterError::Io)?;
        if output.status.success() {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            Ok(text)
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

#[cfg(any(target_os = "macos", target_os = "linux", test))]
type CommandSpec = (String, Vec<String>);

#[cfg(any(target_os = "macos", target_os = "linux", test))]
trait Platform: Send + Sync {
    fn commands(&self, operation: &RouterOperation) -> Vec<CommandSpec>;

    fn claim_ownership(&self) -> Result<(), RouterError> {
        Ok(())
    }

    fn release_ownership(&self) {}

    /// Idempotent stale-state cleanup performed before startup transaction.
    fn up_cleanup_commands(&self) -> Vec<CommandSpec> {
        Vec::new()
    }

    /// Commands and exact output fragments used to verify the emergency
    /// direct-traffic block. Empty means the platform has its own verifier.
    fn direct_block_checks(&self) -> Vec<(CommandSpec, Vec<String>)> {
        Vec::new()
    }

    /// Startup commands paired with their exact rollback commands.
    fn up_transaction_commands(&self) -> Vec<(CommandSpec, CommandSpec)> {
        self.commands(&RouterOperation::Up)
            .into_iter()
            .zip(self.commands(&RouterOperation::Down))
            .collect()
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
struct StatefulRouter<P, R> {
    platform: P,
    runner: R,
    config: Option<RouterConfig>,
    is_up: bool,
    pending_cleanup: Vec<CommandSpec>,
    ownership_claimed: bool,
    direct_blocked: bool,
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
impl<P: Platform, R: CommandRunner> StatefulRouter<P, R> {
    fn new(platform: P, runner: R) -> Self {
        Self {
            platform,
            runner,
            config: None,
            is_up: false,
            pending_cleanup: Vec::new(),
            ownership_claimed: false,
            direct_blocked: false,
        }
    }

    fn apply_commands(
        &mut self,
        commands: impl IntoIterator<Item = CommandSpec>,
    ) -> Result<(), RouterError> {
        let mut first_error = None;
        for (program, args) in commands {
            if let Err(error) = self.runner.run(&program, &args) {
                if !error.non_fatal() && first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn apply(&mut self, operations: &[RouterOperation]) -> Result<(), RouterError> {
        let mut rollback = Vec::new();
        for operation in operations {
            let commands = self.platform.commands(operation);
            let inverse = self.platform.commands(&operation.inverse());
            debug_assert_eq!(commands.len(), inverse.len());
            for (index, (program, args)) in commands.into_iter().enumerate() {
                match self.runner.run(&program, &args) {
                    Ok(()) => rollback.push(inverse[index].clone()),
                    Err(error) if error.non_fatal() => {}
                    Err(error) => {
                        // Restore every command that this transaction changed,
                        // including an earlier command from the same operation.
                        // Failed inverses remain owned and are retried before
                        // another set() or during close().
                        let mut rollback_errors = Vec::new();
                        for (program, args) in rollback.into_iter().rev() {
                            if let Err(rollback_error) = self.runner.run(&program, &args) {
                                if !rollback_error.non_fatal() {
                                    self.pending_cleanup.push((program, args));
                                    rollback_errors.push(rollback_error);
                                }
                            }
                        }
                        return if rollback_errors.is_empty() {
                            Err(error)
                        } else {
                            Err(RouterError::Transaction {
                                primary: Box::new(error),
                                rollback: rollback_errors,
                            })
                        };
                    }
                }
            }
        }
        Ok(())
    }

    fn apply_teardown(&mut self, operations: &[RouterOperation]) -> Result<(), RouterError> {
        let commands: Vec<_> = operations
            .iter()
            .flat_map(|operation| self.platform.commands(operation))
            .collect();
        self.apply_commands(commands)
    }

    fn verify_direct_block(&mut self, expected: bool) -> Result<(), RouterError> {
        for ((program, args), fragments) in self.platform.direct_block_checks() {
            let output = self.runner.output(&program, &args)?;
            let active = output
                .lines()
                .any(|line| fragments.iter().all(|fragment| line.contains(fragment)));
            if active != expected {
                return Err(RouterError::InvalidConfig(format!(
                    "kernel direct-traffic block verification expected {expected} for {program} {args:?}: {output:?}"
                )));
            }
        }
        Ok(())
    }

    fn retry_pending_cleanup(&mut self) -> Result<(), RouterError> {
        let pending = std::mem::take(&mut self.pending_cleanup);
        let mut first_error = None;
        for (program, args) in pending {
            if let Err(error) = self.runner.run(&program, &args) {
                if !error.non_fatal() {
                    self.pending_cleanup.push((program, args));
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn rollback_startup(&mut self, rollback: Vec<CommandSpec>) -> Vec<RouterError> {
        let mut errors = Vec::new();
        for (program, args) in rollback.into_iter().rev() {
            if let Err(error) = self.runner.run(&program, &args) {
                if !error.non_fatal() {
                    self.pending_cleanup.push((program, args));
                    errors.push(error);
                }
            }
        }
        errors
    }

    fn apply_up(&mut self) -> Result<(), RouterError> {
        self.retry_pending_cleanup()?;
        self.apply_commands(self.platform.up_cleanup_commands())?;
        let mut rollback = Vec::new();
        for ((program, args), inverse) in self.platform.up_transaction_commands() {
            match self.runner.run(&program, &args) {
                Ok(()) => rollback.push(inverse),
                Err(error) if error.non_fatal() => {}
                Err(error) => {
                    let rollback = self.rollback_startup(rollback);
                    return if rollback.is_empty() {
                        Err(error)
                    } else {
                        Err(RouterError::Transaction {
                            primary: Box::new(error),
                            rollback,
                        })
                    };
                }
            }
        }
        Ok(())
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
impl<P: Platform, R: CommandRunner> Router for StatefulRouter<P, R> {
    fn up(&mut self) -> Result<(), RouterError> {
        if self.is_up {
            return Ok(());
        }
        if !self.ownership_claimed {
            self.platform.claim_ownership()?;
            self.ownership_claimed = true;
        }
        if let Err(error) = self.apply_up() {
            if self.pending_cleanup.is_empty() {
                self.platform.release_ownership();
                self.ownership_claimed = false;
            }
            return Err(error);
        }
        self.is_up = true;
        Ok(())
    }

    fn set(&mut self, config: &RouterConfig) -> Result<(), RouterError> {
        self.retry_pending_cleanup()?;
        let config = config.normalized()?;
        let delta = diff(self.config.as_ref(), &config);
        self.apply(&delta.operations())?;
        self.config = Some(config);
        Ok(())
    }

    fn block_direct(&mut self) -> Result<(), RouterError> {
        if self.direct_blocked {
            if self.verify_direct_block(true).is_ok() {
                return Ok(());
            }
            // An uncertain/partial unblock invalidates prior verification.
            // Remove any exact remnants, then establish a fresh full block.
            self.apply(&[RouterOperation::DisableDirectBlock])?;
            self.direct_blocked = false;
        }
        self.apply(&[RouterOperation::EnableDirectBlock])?;
        self.direct_blocked = true;
        self.verify_direct_block(true)
    }

    fn unblock_direct(&mut self) -> Result<(), RouterError> {
        if !self.direct_blocked {
            return Ok(());
        }
        self.apply(&[RouterOperation::DisableDirectBlock])?;
        self.verify_direct_block(false)?;
        self.direct_blocked = false;
        Ok(())
    }

    fn close(&mut self) -> Result<(), RouterError> {
        if !self.is_up
            && self.config.is_none()
            && self.pending_cleanup.is_empty()
            && !self.direct_blocked
        {
            return Ok(());
        }
        // A shutdown is itself a security transition: establish the emergency
        // block first and retain it until every pending inverse and teardown
        // command has succeeded. Failed cleanup must never reopen direct paths.
        self.block_direct()?;
        let pending_result = self.retry_pending_cleanup();
        let empty = RouterConfig::default();
        let delta = diff(self.config.as_ref(), &empty);
        let teardown_result = self.apply_teardown(&delta.teardown_operations());
        let cleanup_result = pending_result.and(teardown_result);
        if let Err(error) = cleanup_result {
            if !self.direct_blocked {
                let _ = self.block_direct();
            }
            return Err(error);
        }
        self.config = None;
        self.is_up = false;
        self.unblock_direct()?;
        if self.ownership_claimed {
            self.platform.release_ownership();
            self.ownership_claimed = false;
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
struct DarwinPlatform {
    tun_name: String,
    block_anchor: String,
    block_file: std::path::PathBuf,
    block_file_error: Option<String>,
}

#[cfg(target_os = "macos")]
impl DarwinPlatform {
    fn new(tun_name: &str, state_dir: Option<&std::path::Path>) -> Self {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        static NEXT_FILE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let token: String = tun_name
            .chars()
            .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
            .collect();
        let private_dir = state_dir
            .map_or_else(
                || std::path::PathBuf::from("/var/run/rustscale"),
                std::path::Path::to_path_buf,
            )
            .join("pf");
        let unique = NEXT_FILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let block_file =
            private_dir.join(format!("block-{}-{unique}-{token}.pf", std::process::id()));
        let create_result = (|| -> std::io::Result<()> {
            std::fs::create_dir_all(&private_dir)?;
            std::fs::set_permissions(&private_dir, std::fs::Permissions::from_mode(0o700))?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&block_file)?;
            file.write_all(format!("block drop out quick on ! {tun_name} all\n").as_bytes())?;
            file.sync_all()?;
            Ok(())
        })();
        Self {
            tun_name: tun_name.to_owned(),
            // macOS's system PF ruleset evaluates the com.apple/* wildcard.
            block_anchor: format!("com.apple/rustscale.{token}"),
            block_file,
            block_file_error: create_result.err().map(|error| error.to_string()),
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
impl Drop for DarwinPlatform {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.block_file);
    }
}

#[cfg(target_os = "macos")]
impl Platform for DarwinPlatform {
    fn claim_ownership(&self) -> Result<(), RouterError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if let Some(error) = &self.block_file_error {
            return Err(RouterError::InvalidConfig(format!(
                "create private PF rules file: {error}"
            )));
        }
        let metadata = std::fs::symlink_metadata(&self.block_file).map_err(RouterError::Io)?;
        let parent = self
            .block_file
            .parent()
            .ok_or_else(|| RouterError::InvalidConfig("PF rules file has no parent".into()))?;
        let parent_metadata = std::fs::symlink_metadata(parent).map_err(RouterError::Io)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || !parent_metadata.file_type().is_dir()
            || parent_metadata.file_type().is_symlink()
            || metadata.uid() != parent_metadata.uid()
            || metadata.permissions().mode() & 0o077 != 0
            || parent_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(RouterError::InvalidConfig(
                "PF rules file is not a private owner-only regular file".into(),
            ));
        }
        Ok(())
    }

    fn release_ownership(&self) {}

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
            // Darwin connected routes preserve explicitly allowed LANs.
            RouterOperation::AddLocalRoute(_) | RouterOperation::RemoveLocalRoute(_) => vec![],
            RouterOperation::AddExitRoutes => self.exit_routes("add"),
            RouterOperation::RemoveExitRoutes => self.exit_routes("delete"),
            RouterOperation::EnableDirectBlock => vec![(
                "pfctl".into(),
                vec![
                    "-a".into(),
                    self.block_anchor.clone(),
                    "-f".into(),
                    self.block_file.display().to_string(),
                ],
            )],
            RouterOperation::DisableDirectBlock => vec![(
                "pfctl".into(),
                vec![
                    "-a".into(),
                    self.block_anchor.clone(),
                    "-F".into(),
                    "rules".into(),
                ],
            )],
        }
    }
}

#[cfg(target_os = "macos")]
/// Shell-command-backed macOS router for phase 1.
pub struct DarwinRouter {
    inner: StatefulRouter<DarwinPlatform, SystemCommandRunner>,
    pf_enable_token: Option<String>,
}

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
fn pf_is_enabled(status: &str) -> bool {
    status
        .lines()
        .any(|line| line.trim().eq_ignore_ascii_case("status: enabled"))
}

#[cfg(target_os = "macos")]
fn pf_enable_token(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        let value = value.trim();
        (name.trim().eq_ignore_ascii_case("token") && !value.is_empty()).then(|| value.to_owned())
    })
}

#[cfg(target_os = "macos")]
fn pf_block_active(rules: &str, tun_name: &str) -> bool {
    rules.contains("block drop out quick") && rules.contains(&format!("! {tun_name}"))
}

#[cfg(target_os = "macos")]
impl DarwinRouter {
    /// Construct a router for `tun_name`.
    pub fn new(tun_name: &str) -> Self {
        Self::new_with_state_dir(tun_name, None)
    }

    pub fn new_with_state_dir(tun_name: &str, state_dir: Option<&std::path::Path>) -> Self {
        Self {
            inner: StatefulRouter::new(
                DarwinPlatform::new(tun_name, state_dir),
                SystemCommandRunner,
            ),
            pf_enable_token: None,
        }
    }

    fn ensure_pf_enabled(&mut self) -> Result<(), RouterError> {
        let status = self
            .inner
            .runner
            .output("pfctl", &["-s".into(), "info".into()])?;
        if pf_is_enabled(&status) {
            return Ok(());
        }
        let enabled = self.inner.runner.output("pfctl", &["-E".into()])?;
        let token = pf_enable_token(&enabled).ok_or_else(|| {
            RouterError::InvalidConfig("pfctl enabled PF without returning a teardown token".into())
        })?;
        self.pf_enable_token = Some(token);
        Ok(())
    }

    fn verify_pf_block(&mut self, expected: bool) -> Result<(), RouterError> {
        let rules = self.inner.runner.output(
            "pfctl",
            &[
                "-a".into(),
                self.inner.platform.block_anchor.clone(),
                "-sr".into(),
            ],
        )?;
        let active = pf_block_active(&rules, &self.inner.platform.tun_name);
        if active == expected {
            Ok(())
        } else {
            Err(RouterError::InvalidConfig(format!(
                "PF emergency anchor verification failed (expected active={expected})"
            )))
        }
    }

    fn release_pf_enable_token(&mut self) -> Result<(), RouterError> {
        if let Some(token) = self.pf_enable_token.clone() {
            self.inner.runner.run("pfctl", &["-X".into(), token])?;
            self.pf_enable_token = None;
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Router for DarwinRouter {
    fn up(&mut self) -> Result<(), RouterError> {
        self.inner.up()
    }
    fn set(&mut self, config: &RouterConfig) -> Result<(), RouterError> {
        self.inner.set(config)
    }
    fn block_direct(&mut self) -> Result<(), RouterError> {
        self.ensure_pf_enabled()?;
        self.inner.block_direct()?;
        if self.verify_pf_block(true).is_ok() {
            return Ok(());
        }
        // A prior partial unblock may leave the inner state marked active
        // while the evaluated anchor is incomplete. Flush and freshly load
        // the exact anchor before authorizing route mutation.
        self.inner.unblock_direct()?;
        self.ensure_pf_enabled()?;
        self.inner.block_direct()?;
        self.verify_pf_block(true)
    }
    fn unblock_direct(&mut self) -> Result<(), RouterError> {
        self.inner.unblock_direct()?;
        self.verify_pf_block(false)?;
        self.release_pf_enable_token()
    }
    fn close(&mut self) -> Result<(), RouterError> {
        self.block_direct()?;
        self.inner.close()?;
        self.verify_pf_block(false)?;
        self.release_pf_enable_token()?;
        match std::fs::remove_file(&self.inner.platform.block_file) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(RouterError::Io(error)),
        }
    }
}

#[cfg(target_os = "linux")]
struct LinuxPlatform {
    tun_name: String,
    rule_base: Option<u32>,
}

#[cfg(target_os = "linux")]
impl LinuxPlatform {
    fn new(tun_name: &str) -> Self {
        let interface_index = if_addrs::get_if_addrs().ok().and_then(|interfaces| {
            interfaces
                .into_iter()
                .find(|interface| interface.name == tun_name)
                .and_then(|interface| interface.index)
        });
        Self {
            tun_name: tun_name.to_owned(),
            rule_base: interface_index.map(Self::rule_base_for_index),
        }
    }

    #[cfg(test)]
    fn new_with_interface_index(tun_name: &str, interface_index: u32) -> Self {
        Self {
            tun_name: tun_name.to_owned(),
            rule_base: Some(Self::rule_base_for_index(interface_index)),
        }
    }

    fn rule_base_for_index(interface_index: u32) -> u32 {
        // Keep the chain ahead of Linux's built-in main rule (32766). There
        // are 200 disjoint per-instance slots; a live collision is detected
        // and refused rather than sharing/deleting ownership.
        5_000 + (interface_index % 200) * 100
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
            "table".into(),
            "52".into(),
        ]);
        ("ip".into(), args)
    }

    const RULE_PROTOCOL: u8 = 201;

    fn policy_rules(&self, add: bool) -> Vec<(String, Vec<String>)> {
        let verb = if add { "add" } else { "del" };
        let protocol = Self::RULE_PROTOCOL.to_string();
        let base = self.rule_base.unwrap_or(5_200);
        let rules = [
            (base + 10, Some("main")),
            (base + 30, Some("default")),
            (base + 50, None),
            (base + 70, Some("52")),
        ];
        let mut commands = Vec::with_capacity(8);
        for family in ["-4", "-6"] {
            for offset in 0..rules.len() {
                // Remove each family's rules in the reverse order from
                // installation, without reversing the IPv4/IPv6 family
                // order itself.
                let index = if add {
                    offset
                } else {
                    rules.len() - 1 - offset
                };
                let (pref, table) = rules[index];
                let mut args = vec![
                    family.into(),
                    "rule".into(),
                    verb.into(),
                    "pref".into(),
                    pref.to_string(),
                ];
                // Deletions repeat every selector used for installation;
                // never delete by shared priority/table alone.
                if pref != base + 70 {
                    args.extend(["fwmark".into(), "0x80000/0xff0000".into()]);
                }
                args.extend(["protocol".into(), protocol.clone()]);
                if let Some(table) = table {
                    args.extend(["table".into(), (*table).into()]);
                } else {
                    args.extend(["type".into(), "unreachable".into()]);
                }
                commands.push(("ip".into(), args));
            }
        }
        commands
    }
}

#[cfg(target_os = "linux")]
fn linux_rule_owner_dir() -> std::path::PathBuf {
    #[cfg(test)]
    return std::env::temp_dir().join(format!("rustscale-rule-owners-{}", std::process::id()));
    #[cfg(not(test))]
    return std::path::PathBuf::from("/run/rustscale/rule-owners");
}

#[cfg(target_os = "linux")]
fn claim_linux_rule_owner_file(base: u32, tun_name: &str) -> Result<(), RouterError> {
    use std::io::Write;
    let dir = linux_rule_owner_dir();
    std::fs::create_dir_all(&dir).map_err(RouterError::Io)?;
    let path = dir.join(base.to_string());
    let identity = format!("{} {tun_name}\n", std::process::id());
    for _ in 0..2 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(identity.as_bytes())
                    .map_err(RouterError::Io)?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = std::fs::read_to_string(&path).unwrap_or_default();
                if existing == identity {
                    return Ok(());
                }
                let live = existing
                    .split_whitespace()
                    .next()
                    .and_then(|pid| pid.parse::<u32>().ok())
                    .is_some_and(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists());
                if live {
                    return Err(RouterError::InvalidConfig(format!(
                        "Linux policy-rule ownership collision at base {base}: {}",
                        existing.trim()
                    )));
                }
                std::fs::remove_file(&path).map_err(RouterError::Io)?;
            }
            Err(error) => return Err(RouterError::Io(error)),
        }
    }
    Err(RouterError::InvalidConfig(format!(
        "could not claim Linux policy-rule base {base}"
    )))
}

#[cfg(target_os = "linux")]
fn linux_rule_owners() -> &'static std::sync::Mutex<std::collections::HashMap<u32, (String, usize)>>
{
    static OWNERS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<u32, (String, usize)>>,
    > = std::sync::OnceLock::new();
    OWNERS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

#[cfg(target_os = "linux")]
impl Platform for LinuxPlatform {
    fn claim_ownership(&self) -> Result<(), RouterError> {
        let base = self.rule_base.ok_or_else(|| {
            RouterError::InvalidConfig(format!(
                "cannot determine interface index for {}",
                self.tun_name
            ))
        })?;
        let mut owners = linux_rule_owners()
            .lock()
            .map_err(|_| RouterError::InvalidConfig("Linux rule owner registry poisoned".into()))?;
        match owners.get_mut(&base) {
            None => {
                claim_linux_rule_owner_file(base, &self.tun_name)?;
                owners.insert(base, (self.tun_name.clone(), 1));
                Ok(())
            }
            Some((owner, refs)) if owner == &self.tun_name => {
                #[cfg(test)]
                {
                    // Command-injection unit tests construct parallel mock
                    // routers with one synthetic name; production is exclusive.
                    *refs += 1;
                    Ok(())
                }
                #[cfg(not(test))]
                {
                    let _ = refs;
                    Err(RouterError::InvalidConfig(format!(
                        "Linux policy-rule owner {} is already active at base {base}",
                        self.tun_name
                    )))
                }
            }
            Some((owner, _)) => Err(RouterError::InvalidConfig(format!(
                "Linux policy-rule ownership collision: {} and {} map to base {base}",
                owner, self.tun_name
            ))),
        }
    }

    fn release_ownership(&self) {
        let Some(base) = self.rule_base else {
            return;
        };
        let Ok(mut owners) = linux_rule_owners().lock() else {
            return;
        };
        if let Some((owner, refs)) = owners.get_mut(&base) {
            if owner == &self.tun_name && *refs > 1 {
                *refs -= 1;
            } else if owner == &self.tun_name {
                owners.remove(&base);
                let path = linux_rule_owner_dir().join(base.to_string());
                let identity = format!("{} {}\n", std::process::id(), self.tun_name);
                if std::fs::read_to_string(&path).ok().as_deref() == Some(identity.as_str()) {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }

    fn direct_block_checks(&self) -> Vec<(CommandSpec, Vec<String>)> {
        let pref = self.rule_base.unwrap_or(5_200).to_string();
        ["-4", "-6"]
            .into_iter()
            .map(|family| {
                (
                    (
                        "ip".into(),
                        vec![
                            family.into(),
                            "rule".into(),
                            "show".into(),
                            "pref".into(),
                            pref.clone(),
                        ],
                    ),
                    vec![
                        format!("{pref}:"),
                        "not".into(),
                        "fwmark 0x80000/0xff0000".into(),
                        format!("proto {}", Self::RULE_PROTOCOL),
                        "unreachable".into(),
                    ],
                )
            })
            .collect()
    }

    fn commands(&self, operation: &RouterOperation) -> Vec<CommandSpec> {
        match operation {
            RouterOperation::Up => self
                .up_cleanup_commands()
                .into_iter()
                .chain(
                    self.up_transaction_commands()
                        .into_iter()
                        .map(|(command, _)| command),
                )
                .collect(),
            RouterOperation::Down => {
                let mut commands = vec![(
                    "ip".into(),
                    vec![
                        "link".into(),
                        "set".into(),
                        self.tun_name.clone(),
                        "down".into(),
                    ],
                )];
                commands.extend(self.policy_rules(false));
                commands
            }
            RouterOperation::AddAddr(address) => vec![("ip".into(), {
                let mut args = Vec::new();
                if address.is_ipv6() {
                    args.push("-6".into());
                }
                args.extend([
                    "addr".into(),
                    "add".into(),
                    format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 }),
                    "dev".into(),
                    self.tun_name.clone(),
                ]);
                args
            })],
            RouterOperation::RemoveAddr(address) => vec![("ip".into(), {
                let mut args = Vec::new();
                if address.is_ipv6() {
                    args.push("-6".into());
                }
                args.extend([
                    "addr".into(),
                    "del".into(),
                    format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 }),
                    "dev".into(),
                    self.tun_name.clone(),
                ]);
                args
            })],
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
            RouterOperation::EnableDirectBlock | RouterOperation::DisableDirectBlock => {
                let verb = if matches!(operation, RouterOperation::EnableDirectBlock) {
                    "add"
                } else {
                    "del"
                };
                let pref = self.rule_base.unwrap_or(5_200).to_string();
                ["-4", "-6"]
                    .into_iter()
                    .map(|family| {
                        (
                            "ip".into(),
                            vec![
                                family.into(),
                                "rule".into(),
                                verb.into(),
                                "pref".into(),
                                pref.clone(),
                                "not".into(),
                                "fwmark".into(),
                                "0x80000/0xff0000".into(),
                                "protocol".into(),
                                Self::RULE_PROTOCOL.to_string(),
                                "type".into(),
                                "unreachable".into(),
                            ],
                        )
                    })
                    .collect()
            }
        }
    }

    fn up_cleanup_commands(&self) -> Vec<CommandSpec> {
        // Delete broadly-selected managed priorities before the transaction.
        // These commands remove only rustscale's reserved priorities.
        self.policy_rules(false)
    }

    fn up_transaction_commands(&self) -> Vec<(CommandSpec, CommandSpec)> {
        let mut commands = Vec::new();
        for (program, args) in self.policy_rules(true) {
            let mut rollback_args = args.clone();
            if let Some(add) = rollback_args.iter_mut().find(|arg| arg.as_str() == "add") {
                *add = "del".into();
            }
            commands.push(((program.clone(), args), (program, rollback_args)));
        }
        commands.push((
            (
                "ip".into(),
                vec![
                    "link".into(),
                    "set".into(),
                    self.tun_name.clone(),
                    "up".into(),
                ],
            ),
            (
                "ip".into(),
                vec![
                    "link".into(),
                    "set".into(),
                    self.tun_name.clone(),
                    "down".into(),
                ],
            ),
        ));
        commands
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
    fn block_direct(&mut self) -> Result<(), RouterError> {
        self.0.block_direct()
    }
    fn unblock_direct(&mut self) -> Result<(), RouterError> {
        self.0.unblock_direct()
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
    new_with_state_dir(tun_name, None)
}

pub fn new_with_state_dir(tun_name: &str, state_dir: Option<&std::path::Path>) -> Box<dyn Router> {
    #[cfg(target_os = "macos")]
    {
        Box::new(DarwinRouter::new_with_state_dir(tun_name, state_dir))
    }
    #[cfg(target_os = "linux")]
    {
        let _ = state_dir;
        Box::new(LinuxRouter::new(tun_name))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (tun_name, state_dir);
        Box::new(UnsupportedRouter)
    }
}

/// In-memory router for unit tests and embedding tests. It never executes a
/// shell command; callers can inspect the recorded operations.
#[derive(Default)]
pub struct FakeRouter {
    config: Option<RouterConfig>,
    is_up: bool,
    direct_blocked: bool,
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
        let config = config.normalized()?;
        self.operations
            .extend(diff(self.config.as_ref(), &config).operations());
        self.config = Some(config);
        Ok(())
    }

    fn block_direct(&mut self) -> Result<(), RouterError> {
        if !self.direct_blocked {
            self.operations.push(RouterOperation::EnableDirectBlock);
            self.direct_blocked = true;
        }
        Ok(())
    }

    fn unblock_direct(&mut self) -> Result<(), RouterError> {
        if self.direct_blocked {
            self.operations.push(RouterOperation::DisableDirectBlock);
            self.direct_blocked = false;
        }
        Ok(())
    }

    fn close(&mut self) -> Result<(), RouterError> {
        if !self.is_up && self.config.is_none() && !self.direct_blocked {
            return Ok(());
        }
        self.block_direct()?;
        self.operations
            .extend(diff(self.config.as_ref(), &RouterConfig::default()).teardown_operations());
        self.config = None;
        self.is_up = false;
        self.unblock_direct()
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

    struct TestPlatform {
        command: (String, Vec<String>),
    }

    impl Platform for TestPlatform {
        fn commands(&self, _operation: &RouterOperation) -> Vec<(String, Vec<String>)> {
            vec![self.command.clone()]
        }
    }

    struct MissingStateRunner;

    impl CommandRunner for MissingStateRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), RouterError> {
            Err(RouterError::Command {
                program: program.into(),
                args: args.to_vec(),
                exit_code: Some(2),
                stderr: "RTNETLINK answers: No such file or directory".into(),
            })
        }
    }

    #[test]
    fn only_missing_removal_commands_are_benign() {
        let add = TestPlatform {
            command: (
                "ip".into(),
                vec!["route".into(), "add".into(), "192.0.2.0/24".into()],
            ),
        };
        let mut router = StatefulRouter::new(add, MissingStateRunner);
        assert!(router.up().is_err(), "missing route add must be fatal");

        let delete = TestPlatform {
            command: (
                "ip".into(),
                vec!["route".into(), "del".into(), "192.0.2.0/24".into()],
            ),
        };
        let mut router = StatefulRouter::new(delete, MissingStateRunner);
        assert!(router.up().is_ok(), "missing route delete must be benign");
    }

    #[test]
    fn empty_stderr_ip_rule_del_exit_2_is_benign() {
        let error = RouterError::Command {
            program: "ip".into(),
            args: vec![
                "-4".into(),
                "rule".into(),
                "del".into(),
                "pref".into(),
                "5210".into(),
            ],
            exit_code: Some(2),
            stderr: String::new(),
        };

        assert!(error.non_fatal());
    }

    #[test]
    fn duplicate_policy_rule_add_is_fatal_after_cleanup() {
        let error = RouterError::Command {
            program: "ip".into(),
            args: vec![
                "-4".into(),
                "rule".into(),
                "add".into(),
                "pref".into(),
                "5210".into(),
            ],
            exit_code: Some(2),
            stderr: "RTNETLINK answers: File exists".into(),
        };
        assert!(!error.non_fatal());
    }

    #[test]
    fn duplicate_route_and_address_adds_are_fatal_without_ownership_proof() {
        let route = RouterError::Command {
            program: "ip".into(),
            args: vec!["route".into(), "add".into(), "192.0.2.0/24".into()],
            exit_code: Some(2),
            stderr: "RTNETLINK answers: File exists".into(),
        };
        assert!(!route.non_fatal());

        let address = RouterError::Command {
            program: "ip".into(),
            args: vec![
                "addr".into(),
                "add".into(),
                "192.0.2.1/32".into(),
                "dev".into(),
                "tailscale0".into(),
            ],
            exit_code: Some(2),
            stderr: "RTNETLINK answers: Already exists".into(),
        };
        assert!(!address.non_fatal());
    }

    #[test]
    fn empty_stderr_ip_route_del_exit_2_is_fatal() {
        let error = RouterError::Command {
            program: "ip".into(),
            args: vec!["route".into(), "del".into(), "192.0.2.0/24".into()],
            exit_code: Some(2),
            stderr: String::new(),
        };

        assert!(!error.non_fatal());
    }

    #[test]
    fn permission_denied_ip_rule_del_exit_2_is_fatal() {
        let error = RouterError::Command {
            program: "ip".into(),
            args: vec!["rule".into(), "del".into(), "pref".into(), "5210".into()],
            exit_code: Some(2),
            stderr: "RTNETLINK answers: Operation not permitted".into(),
        };

        assert!(!error.non_fatal());
    }

    #[test]
    fn unsupported_ipv6_family_is_benign_only_for_ipv6_ip_commands() {
        let ipv6 = RouterError::Command {
            program: "ip".into(),
            args: vec![
                "-6".into(),
                "rule".into(),
                "add".into(),
                "pref".into(),
                "5210".into(),
            ],
            exit_code: Some(2),
            stderr: "RTNETLINK answers: Address family not supported by protocol".into(),
        };
        assert!(ipv6.non_fatal());

        let ipv6_permission = RouterError::Command {
            program: "ip".into(),
            args: vec![
                "-6".into(),
                "rule".into(),
                "add".into(),
                "pref".into(),
                "5210".into(),
            ],
            exit_code: Some(2),
            stderr: "RTNETLINK answers: Operation not permitted".into(),
        };
        assert!(!ipv6_permission.non_fatal());

        let ipv6_syntax = RouterError::Command {
            program: "ip".into(),
            args: vec!["-6".into(), "rule".into(), "add".into(), "bogus".into()],
            exit_code: Some(1),
            stderr: "Error: invalid argument".into(),
        };
        assert!(!ipv6_syntax.non_fatal());

        let ipv4 = RouterError::Command {
            program: "ip".into(),
            args: vec![
                "-4".into(),
                "rule".into(),
                "add".into(),
                "pref".into(),
                "5210".into(),
            ],
            exit_code: Some(2),
            stderr: "RTNETLINK answers: Address family not supported by protocol".into(),
        };
        assert!(!ipv4.non_fatal());
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
                RouterOperation::AddLocalRoute(prefix("192.168.0.0/16")),
                RouterOperation::AddRoute(prefix("10.0.0.0/8")),
                RouterOperation::RemoveRoute(prefix("100.64.0.0/10")),
            ]
        );
    }

    #[test]
    fn local_route_diff_adds_before_removing_replacements() {
        let mut previous = config();
        previous.local_routes = vec![prefix("192.168.0.0/16")];
        let mut next = config();
        next.local_routes = vec![prefix("10.0.0.0/8")];

        assert_eq!(
            diff(Some(&previous), &next).operations(),
            [
                RouterOperation::AddLocalRoute(prefix("10.0.0.0/8")),
                RouterOperation::RemoveLocalRoute(prefix("192.168.0.0/16")),
            ]
        );
    }

    #[test]
    fn tun_route_is_added_before_corresponding_bypass_is_removed() {
        let lan = prefix("192.168.0.0/16");
        let child = prefix("192.168.0.0/17");
        let previous = RouterConfig {
            local_routes: vec![lan],
            exit_node: true,
            ..Default::default()
        };
        let next = RouterConfig {
            routes: vec![child],
            exit_node: true,
            ..Default::default()
        };
        assert_eq!(
            diff(Some(&previous), &next).operations(),
            [
                RouterOperation::AddRoute(child),
                RouterOperation::RemoveLocalRoute(lan),
            ]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_pf_enable_status_and_token_are_verified() {
        assert!(pf_is_enabled("Status: Enabled\nDebug: Urgent"));
        assert!(!pf_is_enabled("Status: Disabled"));
        assert_eq!(
            pf_enable_token("pf enabled\nToken : 12345\n"),
            Some("12345".into())
        );
        assert_eq!(pf_enable_token("pf enabled without token"), None);
        assert!(pf_block_active(
            "block drop out quick on ! utun42 all flags S/SA",
            "utun42"
        ));
        assert!(!pf_block_active("", "utun42"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_emergency_block_uses_evaluated_pf_anchor_and_all_non_tun_interfaces() {
        let state_dir =
            std::env::temp_dir().join(format!("rustscale-router-test-{}", std::process::id()));
        let platform = DarwinPlatform::new("utun42", Some(&state_dir));
        platform.claim_ownership().unwrap();
        let commands = platform.commands(&RouterOperation::EnableDirectBlock);
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].0, "pfctl");
        assert!(commands[0]
            .1
            .windows(2)
            .any(|pair| { pair == ["-a", "com.apple/rustscale.utun42"] }));
        let rules = std::fs::read_to_string(&platform.block_file).unwrap();
        assert_eq!(rules, "block drop out quick on ! utun42 all\n");
        let disable = platform.commands(&RouterOperation::DisableDirectBlock);
        assert!(disable[0].1.windows(2).any(|pair| pair == ["-F", "rules"]));
        platform.release_ownership();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_pf_rules_file_rejects_symlink_replacement() {
        use std::os::unix::fs::symlink;
        let state_dir = std::env::temp_dir().join(format!(
            "rustscale-router-symlink-test-{}",
            std::process::id()
        ));
        let platform = DarwinPlatform::new("utun43", Some(&state_dir));
        std::fs::remove_file(&platform.block_file).unwrap();
        symlink("/etc/passwd", &platform.block_file).unwrap();
        assert!(platform.claim_ownership().is_err());
        std::fs::remove_file(&platform.block_file).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_direct_block_checks_match_only_exact_owned_rule() {
        let platform = LinuxPlatform::new_with_interface_index("tailscale0", 2);
        let pref = platform.rule_base.unwrap().to_string();
        let owned = format!(
            "{pref}: not from all fwmark 0x80000/0xff0000 unreachable proto {}\n",
            LinuxPlatform::RULE_PROTOCOL
        );
        for ((program, args), fragments) in platform.direct_block_checks() {
            assert_eq!(program, "ip");
            assert!(args.windows(2).any(|pair| pair == ["pref", &pref]));
            assert!(fragments.iter().all(|fragment| owned.contains(fragment)));
            let foreign = format!("{pref}: from all unreachable proto 99\n");
            assert!(!fragments.iter().all(|fragment| foreign.contains(fragment)));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_routes_use_tailscale_table_52() {
        let platform = LinuxPlatform::new("tailscale0");
        let commands = platform.commands(&RouterOperation::AddRoute(prefix("192.0.2.0/24")));
        assert_eq!(
            commands,
            vec![(
                ("ip").into(),
                vec![
                    "route".into(),
                    "add".into(),
                    "192.0.2.0/24".into(),
                    "dev".into(),
                    "tailscale0".into(),
                    "table".into(),
                    "52".into(),
                ]
            )]
        );

        let exit = platform.commands(&RouterOperation::AddExitRoutes);
        assert_eq!(
            exit,
            vec![
                (
                    "ip".into(),
                    vec![
                        "route".into(),
                        "add".into(),
                        "0.0.0.0/0".into(),
                        "dev".into(),
                        "tailscale0".into(),
                        "table".into(),
                        "52".into(),
                    ],
                ),
                (
                    "ip".into(),
                    vec![
                        "-6".into(),
                        "route".into(),
                        "add".into(),
                        "::/0".into(),
                        "dev".into(),
                        "tailscale0".into(),
                        "table".into(),
                        "52".into(),
                    ],
                ),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_policy_rules_match_tailscale_base_chain() {
        let platform = LinuxPlatform::new_with_interface_index("rustscale0", 2);
        let mut commands = platform.policy_rules(true);
        for (_, args) in &mut commands {
            if let Some(index) = args.iter().position(|arg| arg == "protocol") {
                args.drain(index..=index + 1);
            }
        }
        assert_eq!(
            &commands[..],
            [
                (
                    "ip".into(),
                    vec![
                        "-4".into(),
                        "rule".into(),
                        "add".into(),
                        "pref".into(),
                        "5210".into(),
                        "fwmark".into(),
                        "0x80000/0xff0000".into(),
                        "table".into(),
                        "main".into()
                    ]
                ),
                (
                    "ip".into(),
                    vec![
                        "-4".into(),
                        "rule".into(),
                        "add".into(),
                        "pref".into(),
                        "5230".into(),
                        "fwmark".into(),
                        "0x80000/0xff0000".into(),
                        "table".into(),
                        "default".into()
                    ]
                ),
                (
                    "ip".into(),
                    vec![
                        "-4".into(),
                        "rule".into(),
                        "add".into(),
                        "pref".into(),
                        "5250".into(),
                        "fwmark".into(),
                        "0x80000/0xff0000".into(),
                        "type".into(),
                        "unreachable".into()
                    ]
                ),
                (
                    "ip".into(),
                    vec![
                        "-4".into(),
                        "rule".into(),
                        "add".into(),
                        "pref".into(),
                        "5270".into(),
                        "table".into(),
                        "52".into()
                    ]
                ),
                (
                    "ip".into(),
                    vec![
                        "-6".into(),
                        "rule".into(),
                        "add".into(),
                        "pref".into(),
                        "5210".into(),
                        "fwmark".into(),
                        "0x80000/0xff0000".into(),
                        "table".into(),
                        "main".into()
                    ]
                ),
                (
                    "ip".into(),
                    vec![
                        "-6".into(),
                        "rule".into(),
                        "add".into(),
                        "pref".into(),
                        "5230".into(),
                        "fwmark".into(),
                        "0x80000/0xff0000".into(),
                        "table".into(),
                        "default".into()
                    ]
                ),
                (
                    "ip".into(),
                    vec![
                        "-6".into(),
                        "rule".into(),
                        "add".into(),
                        "pref".into(),
                        "5250".into(),
                        "fwmark".into(),
                        "0x80000/0xff0000".into(),
                        "type".into(),
                        "unreachable".into()
                    ]
                ),
                (
                    "ip".into(),
                    vec![
                        "-6".into(),
                        "rule".into(),
                        "add".into(),
                        "pref".into(),
                        "5270".into(),
                        "table".into(),
                        "52".into()
                    ]
                ),
            ]
        );

        let mut down = platform.policy_rules(false);
        for (_, args) in &mut down {
            if let Some(index) = args.iter().position(|arg| arg == "protocol") {
                args.drain(index..=index + 1);
            }
            if let Some(index) = args.iter().position(|arg| arg == "fwmark") {
                args.drain(index..=index + 1);
            }
        }
        assert_eq!(
            &down[..8],
            [
                (
                    "ip".into(),
                    vec![
                        "-4".into(),
                        "rule".into(),
                        "del".into(),
                        "pref".into(),
                        "5270".into(),
                        "table".into(),
                        "52".into()
                    ]
                ),
                (
                    "ip".into(),
                    vec![
                        "-4".into(),
                        "rule".into(),
                        "del".into(),
                        "pref".into(),
                        "5250".into(),
                        "type".into(),
                        "unreachable".into()
                    ]
                ),
                (
                    "ip".into(),
                    vec![
                        "-4".into(),
                        "rule".into(),
                        "del".into(),
                        "pref".into(),
                        "5230".into(),
                        "table".into(),
                        "default".into()
                    ]
                ),
                (
                    "ip".into(),
                    vec![
                        "-4".into(),
                        "rule".into(),
                        "del".into(),
                        "pref".into(),
                        "5210".into(),
                        "table".into(),
                        "main".into()
                    ]
                ),
                (
                    "ip".into(),
                    vec![
                        "-6".into(),
                        "rule".into(),
                        "del".into(),
                        "pref".into(),
                        "5270".into(),
                        "table".into(),
                        "52".into()
                    ]
                ),
                (
                    "ip".into(),
                    vec![
                        "-6".into(),
                        "rule".into(),
                        "del".into(),
                        "pref".into(),
                        "5250".into(),
                        "type".into(),
                        "unreachable".into()
                    ]
                ),
                (
                    "ip".into(),
                    vec![
                        "-6".into(),
                        "rule".into(),
                        "del".into(),
                        "pref".into(),
                        "5230".into(),
                        "table".into(),
                        "default".into()
                    ]
                ),
                (
                    "ip".into(),
                    vec![
                        "-6".into(),
                        "rule".into(),
                        "del".into(),
                        "pref".into(),
                        "5210".into(),
                        "table".into(),
                        "main".into()
                    ]
                ),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_rule_cleanup_selects_only_exact_owned_rules() {
        let first = LinuxPlatform::new_with_interface_index("rustscale0", 2);
        let second = LinuxPlatform::new_with_interface_index("rustscale1", 3);
        assert_ne!(first.rule_base, second.rule_base);

        for (_, delete) in first.policy_rules(false) {
            assert!(delete.windows(2).any(|pair| pair == ["protocol", "201"]));
            if delete.iter().any(|arg| arg == "fwmark") {
                assert!(delete
                    .windows(2)
                    .any(|pair| pair == ["fwmark", "0x80000/0xff0000"]));
            }
            // A foreign rule can use the same priority/table, but without our
            // exact ownership protocol it is not selected by this deletion.
            let mut foreign = delete.clone();
            let protocol = foreign.iter().position(|arg| arg == "protocol").unwrap();
            foreign[protocol + 1] = "99".into();
            assert_ne!(delete, foreign);
        }
        for (_, block) in first.commands(&RouterOperation::EnableDirectBlock) {
            assert!(block.windows(2).any(|pair| pair == ["protocol", "201"]));
            assert!(block.windows(2).any(|pair| pair == ["not", "fwmark"]));
            assert_eq!(block[4], first.rule_base.unwrap().to_string());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_rule_owner_collision_is_refused_without_cleanup() {
        let first = LinuxPlatform::new_with_interface_index("collision-a", 199);
        let colliding = LinuxPlatform::new_with_interface_index("collision-b", 399);
        first.claim_ownership().unwrap();
        let error = colliding.claim_ownership().unwrap_err();
        assert!(error.to_string().contains("ownership collision"));
        first.release_ownership();
        colliding.claim_ownership().unwrap();
        colliding.release_ownership();
    }

    #[cfg(target_os = "linux")]
    #[derive(Clone, Copy)]
    enum RunnerOutcome {
        Success,
        Missing,
        Fatal,
        FileExists,
    }

    #[cfg(target_os = "linux")]
    #[derive(Default)]
    struct RecordingRunner {
        outcomes: Vec<RunnerOutcome>,
        commands: Vec<CommandSpec>,
    }

    #[cfg(target_os = "linux")]
    impl CommandRunner for RecordingRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), RouterError> {
            let outcome = self.outcomes.get(self.commands.len()).copied();
            self.commands.push((program.into(), args.to_vec()));
            match outcome {
                None | Some(RunnerOutcome::Success) => Ok(()),
                Some(RunnerOutcome::Missing) => Err(RouterError::Command {
                    program: program.into(),
                    args: args.to_vec(),
                    exit_code: Some(2),
                    stderr: "RTNETLINK answers: No such file or directory".into(),
                }),
                Some(RunnerOutcome::Fatal) => Err(RouterError::Command {
                    program: program.into(),
                    args: args.to_vec(),
                    exit_code: Some(2),
                    stderr: "RTNETLINK answers: Operation not permitted".into(),
                }),
                Some(RunnerOutcome::FileExists) => Err(RouterError::Command {
                    program: program.into(),
                    args: args.to_vec(),
                    exit_code: Some(2),
                    stderr: "RTNETLINK answers: File exists".into(),
                }),
            }
        }

        fn output(&mut self, program: &str, args: &[String]) -> Result<String, RouterError> {
            self.run(program, args)?;
            let Some(family) = args.first() else {
                return Ok(String::new());
            };
            let Some(pref) = args
                .windows(2)
                .find_map(|pair| (pair[0] == "pref").then_some(pair[1].as_str()))
            else {
                return Ok(String::new());
            };
            let active = self.commands[..self.commands.len() - 1]
                .iter()
                .rev()
                .find(|(_, prior)| {
                    prior.first() == Some(family)
                        && prior.windows(2).any(|pair| pair == ["pref", pref])
                        && prior.iter().any(|arg| arg == "not")
                        && prior.iter().any(|arg| arg == "unreachable")
                })
                .is_some_and(|(_, prior)| prior.iter().any(|arg| arg == "add"));
            if active {
                Ok(format!(
                    "{pref}: not from all fwmark 0x80000/0xff0000 unreachable proto {}\n",
                    LinuxPlatform::RULE_PROTOCOL
                ))
            } else {
                Ok(String::new())
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn linux_router_with(
        outcomes: Vec<RunnerOutcome>,
    ) -> StatefulRouter<LinuxPlatform, RecordingRunner> {
        StatefulRouter::new(
            LinuxPlatform::new_with_interface_index("tailscale0", 2),
            RecordingRunner {
                outcomes,
                ..Default::default()
            },
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_startup_fatal_cleanup_runs_all_deletes_but_no_later_phase() {
        let mut router = linux_router_with(vec![RunnerOutcome::Fatal]);

        assert!(router.up().is_err());
        assert_eq!(router.runner.commands.len(), 8);
        assert!(router
            .runner
            .commands
            .iter()
            .all(|(_, args)| { args.windows(2).any(|args| args == ["rule", "del"]) }));
        assert!(!router.is_up);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_startup_duplicate_first_add_fails_without_claiming_state() {
        let mut outcomes = vec![RunnerOutcome::Success; 8];
        outcomes.push(RunnerOutcome::FileExists);
        let mut router = linux_router_with(outcomes);

        assert!(router.up().is_err());
        assert_eq!(router.runner.commands.len(), 9);
        assert!(router.runner.commands[8]
            .1
            .windows(2)
            .any(|args| args == ["rule", "add"]));
        assert!(!router.is_up);
        assert!(router.pending_cleanup.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_startup_rolls_back_every_success_before_each_later_failure() {
        for fail_offset in 0..9 {
            let mut outcomes = vec![RunnerOutcome::Success; 8 + fail_offset];
            outcomes.push(RunnerOutcome::Fatal);
            let mut router = linux_router_with(outcomes);

            assert!(router.up().is_err(), "failure offset {fail_offset}");
            assert_eq!(
                router.runner.commands.len(),
                9 + 2 * fail_offset,
                "failure offset {fail_offset}",
            );
            assert!(!router.is_up);
            assert!(router.pending_cleanup.is_empty());
            let rollback = &router.runner.commands[9 + fail_offset..];
            assert_eq!(rollback.len(), fail_offset);
            assert!(rollback
                .iter()
                .all(|(_, args)| { args.windows(2).any(|args| args == ["rule", "del"]) }));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_failed_startup_rollback_is_dirty_and_close_retries() {
        let mut outcomes = vec![RunnerOutcome::Success; 9];
        outcomes.extend([RunnerOutcome::Fatal, RunnerOutcome::Fatal]);
        let mut router = linux_router_with(outcomes);

        let error = router.up().unwrap_err();
        assert!(matches!(
            error,
            RouterError::Transaction { ref rollback, .. } if rollback.len() == 1
        ));
        assert_eq!(router.pending_cleanup.len(), 1);
        assert!(!router.is_up);
        router.close().unwrap();
        assert!(router.pending_cleanup.is_empty());
        assert!(!router.is_up);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_startup_missing_cleanup_reaches_adds_and_link_up() {
        let mut router = linux_router_with(vec![RunnerOutcome::Missing; 8]);

        assert!(router.up().is_ok());
        assert_eq!(router.runner.commands.len(), 17);
        assert_eq!(
            router.runner.commands.last(),
            Some(&(
                "ip".into(),
                vec![
                    "link".into(),
                    "set".into(),
                    "tailscale0".into(),
                    "up".into()
                ]
            ))
        );
        assert!(router.is_up);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_startup_successfully_runs_phases_in_order() {
        let mut router = linux_router_with(vec![]);

        router.up().unwrap();
        let actual: Vec<_> = router
            .runner
            .commands
            .iter()
            .map(|(program, args)| {
                let mut args = args.clone();
                if let Some(index) = args.iter().position(|arg| arg == "protocol") {
                    args.drain(index..=index + 1);
                }
                if args.iter().any(|arg| arg == "del") {
                    if let Some(index) = args.iter().position(|arg| arg == "fwmark") {
                        args.drain(index..=index + 1);
                    }
                }
                format!("{program} {}", args.join(" "))
            })
            .collect();
        assert_eq!(
            actual,
            [
                "ip -4 rule del pref 5270 table 52",
                "ip -4 rule del pref 5250 type unreachable",
                "ip -4 rule del pref 5230 table default",
                "ip -4 rule del pref 5210 table main",
                "ip -6 rule del pref 5270 table 52",
                "ip -6 rule del pref 5250 type unreachable",
                "ip -6 rule del pref 5230 table default",
                "ip -6 rule del pref 5210 table main",
                "ip -4 rule add pref 5210 fwmark 0x80000/0xff0000 table main",
                "ip -4 rule add pref 5230 fwmark 0x80000/0xff0000 table default",
                "ip -4 rule add pref 5250 fwmark 0x80000/0xff0000 type unreachable",
                "ip -4 rule add pref 5270 table 52",
                "ip -6 rule add pref 5210 fwmark 0x80000/0xff0000 table main",
                "ip -6 rule add pref 5230 fwmark 0x80000/0xff0000 table default",
                "ip -6 rule add pref 5250 fwmark 0x80000/0xff0000 type unreachable",
                "ip -6 rule add pref 5270 table 52",
                "ip link set tailscale0 up",
            ]
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

    #[derive(Default)]
    struct TransactionRunner {
        commands: Vec<String>,
        fail_at: Option<usize>,
        fail_also_at: Option<usize>,
    }

    impl CommandRunner for TransactionRunner {
        fn run(&mut self, _program: &str, args: &[String]) -> Result<(), RouterError> {
            let index = self.commands.len();
            self.commands.push(args.join(" "));
            if self.fail_at == Some(index) || self.fail_also_at == Some(index) {
                return Err(RouterError::Command {
                    program: "route-test".into(),
                    args: args.to_vec(),
                    exit_code: Some(1),
                    stderr: "injected failure".into(),
                });
            }
            Ok(())
        }
    }

    struct TransactionPlatform;

    impl Platform for TransactionPlatform {
        fn commands(&self, operation: &RouterOperation) -> Vec<CommandSpec> {
            let command = match operation {
                RouterOperation::AddLocalRoute(prefix) => format!("add {prefix}"),
                RouterOperation::RemoveLocalRoute(prefix) => format!("remove {prefix}"),
                _ => return Vec::new(),
            };
            vec![("route-test".into(), vec![command])]
        }
    }

    #[derive(Default)]
    struct ForeignRouteRunner {
        commands: Vec<String>,
    }

    impl CommandRunner for ForeignRouteRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), RouterError> {
            self.commands.push(args.join(" "));
            if args.first().is_some_and(|arg| arg.starts_with("add ")) {
                return Err(RouterError::Command {
                    program: program.into(),
                    args: args.to_vec(),
                    exit_code: Some(2),
                    stderr: "File exists".into(),
                });
            }
            Ok(())
        }
    }

    #[test]
    fn foreign_duplicate_route_is_never_claimed_or_deleted() {
        let mut router = StatefulRouter::new(TransactionPlatform, ForeignRouteRunner::default());
        let desired = RouterConfig {
            local_routes: vec![prefix("192.0.2.10/32")],
            ..Default::default()
        };
        assert!(router.set(&desired).is_err());
        router.close().unwrap();
        assert_eq!(router.runner.commands, ["add 192.0.2.10/32"]);
        assert!(router.config.is_none());
    }

    #[test]
    fn endpoint_churn_adds_new_bypass_before_removing_stale() {
        let mut previous = RouterConfig {
            local_routes: vec![prefix("192.0.2.10/32")],
            ..Default::default()
        };
        previous.exit_node = true;
        let mut next = previous.clone();
        next.local_routes = vec![prefix("192.0.2.20/32")];

        assert_eq!(
            diff(Some(&previous), &next).operations(),
            [
                RouterOperation::AddLocalRoute(prefix("192.0.2.20/32")),
                RouterOperation::RemoveLocalRoute(prefix("192.0.2.10/32")),
            ]
        );
    }

    #[test]
    fn partial_endpoint_churn_rolls_back_and_retains_previous_state() {
        let mut router = StatefulRouter::new(TransactionPlatform, TransactionRunner::default());
        let previous = RouterConfig {
            local_routes: vec![prefix("192.0.2.10/32")],
            exit_node: true,
            ..Default::default()
        };
        router.set(&previous).unwrap();
        let start = router.runner.commands.len();
        router.runner.fail_at = Some(start + 1);
        let next = RouterConfig {
            local_routes: vec![prefix("192.0.2.20/32")],
            exit_node: true,
            ..Default::default()
        };

        assert!(router.set(&next).is_err());
        assert_eq!(router.config, Some(previous));
        assert_eq!(
            &router.runner.commands[start..],
            [
                "add 192.0.2.20/32",
                "remove 192.0.2.10/32",
                "remove 192.0.2.20/32",
            ]
        );
    }

    #[test]
    fn inverse_failure_is_aggregated_owned_and_retried_before_next_set() {
        let mut router = StatefulRouter::new(TransactionPlatform, TransactionRunner::default());
        let previous = RouterConfig {
            local_routes: vec![prefix("192.0.2.10/32")],
            ..Default::default()
        };
        router.set(&previous).unwrap();
        let start = router.runner.commands.len();
        router.runner.fail_at = Some(start + 1);
        router.runner.fail_also_at = Some(start + 2);
        let next = RouterConfig {
            local_routes: vec![prefix("192.0.2.20/32")],
            ..Default::default()
        };

        let error = router.set(&next).unwrap_err();
        assert!(matches!(
            error,
            RouterError::Transaction { ref rollback, .. } if rollback.len() == 1
        ));
        assert_eq!(router.config, Some(previous.clone()));
        assert_eq!(router.pending_cleanup.len(), 1);

        router.runner.fail_at = None;
        router.runner.fail_also_at = None;
        router.set(&previous).unwrap();
        assert!(router.pending_cleanup.is_empty());
        assert_eq!(
            router.runner.commands.last().unwrap(),
            "remove 192.0.2.20/32"
        );
    }

    #[test]
    fn failed_teardown_retains_state_for_retry() {
        let mut router = StatefulRouter::new(TransactionPlatform, TransactionRunner::default());
        let installed = RouterConfig {
            local_routes: vec![prefix("192.0.2.10/32")],
            exit_node: true,
            ..Default::default()
        };
        router.is_up = true;
        router.set(&installed).unwrap();
        router.runner.fail_at = Some(router.runner.commands.len());

        assert!(router.close().is_err());
        assert_eq!(router.config, Some(installed));
        assert!(router.is_up);
        assert!(router.direct_blocked);
        router.runner.fail_at = None;
        router.close().unwrap();
        assert!(router.config.is_none());
        assert!(!router.is_up);
        assert!(!router.direct_blocked);
    }

    #[test]
    fn normalization_masks_sorts_deduplicates_and_unmaps_v4() {
        let mut router = FakeRouter::default();
        router
            .set(&RouterConfig {
                local_addrs: vec!["::ffff:192.0.2.1".parse().unwrap()],
                local_routes: vec![prefix("192.168.1.99/24"), prefix("192.168.1.0/24")],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            router.config.unwrap(),
            RouterConfig {
                local_addrs: vec!["192.0.2.1".parse().unwrap()],
                local_routes: vec![prefix("192.168.1.0/24")],
                ..Default::default()
            }
        );
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
                RouterOperation::EnableDirectBlock,
                RouterOperation::RemoveExitRoutes,
                RouterOperation::RemoveRoute(prefix("100.64.0.0/10")),
                RouterOperation::RemoveLocalRoute(prefix("192.168.0.0/16")),
                RouterOperation::RemoveAddr(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
                RouterOperation::Down,
                RouterOperation::DisableDirectBlock,
            ]
        );
        router.clear_operations();
        router.close().unwrap();
        assert!(router.operations().is_empty());
    }
}
