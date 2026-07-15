//! Desired-state management for Linux kernel IP sets.
//!
//! The manager invokes the `ipset` executable directly with argument vectors;
//! it never constructs a shell command. It only updates or tears down sets that
//! it successfully created during its own lifetime. A pre-existing set with the
//! same name therefore causes creation to fail rather than being adopted.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
};

#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

const IPSET_NAME_MAX_LEN: usize = 31;

/// An IP address family supported by an `ipset` `hash:ip` set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpSetFamily {
    Ipv4,
    Ipv6,
}

impl IpSetFamily {
    fn command_name(self) -> &'static str {
        match self {
            Self::Ipv4 => "inet",
            Self::Ipv6 => "inet6",
        }
    }

    fn matches(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
        )
    }
}

/// A validated kernel IP set name.
///
/// Names are limited to 31 ASCII characters (the kernel ipset limit excluding
/// its terminating NUL), start with an alphanumeric character, and otherwise
/// contain only alphanumerics, `-`, `_`, or `.`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpSetName(String);

impl IpSetName {
    pub fn new(name: impl Into<String>) -> Result<Self, IpSetError> {
        let name = name.into();
        let mut chars = name.chars();
        let valid = !name.is_empty()
            && name.len() <= IPSET_NAME_MAX_LEN
            && name.is_ascii()
            && chars.next().is_some_and(|ch| ch.is_ascii_alphanumeric())
            && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'));
        if !valid {
            return Err(IpSetError::InvalidName(name));
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IpSetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The complete desired contents of one `hash:ip` set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpSetSpec {
    name: IpSetName,
    family: IpSetFamily,
    addresses: BTreeSet<IpAddr>,
}

impl IpSetSpec {
    pub fn new(
        name: impl Into<String>,
        family: IpSetFamily,
        addresses: impl IntoIterator<Item = IpAddr>,
    ) -> Result<Self, IpSetError> {
        let name = IpSetName::new(name)?;
        let addresses = addresses.into_iter().collect::<BTreeSet<_>>();
        if let Some(address) = addresses
            .iter()
            .copied()
            .find(|address| !family.matches(*address))
        {
            return Err(IpSetError::AddressFamilyMismatch {
                set: name,
                family,
                address,
            });
        }
        Ok(Self {
            name,
            family,
            addresses,
        })
    }

    /// Parse and validate string addresses before constructing a set.
    pub fn parse<I, S>(
        name: impl Into<String>,
        family: IpSetFamily,
        addresses: I,
    ) -> Result<Self, IpSetError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut parsed = Vec::new();
        for address in addresses {
            let value = address.as_ref();
            parsed.push(
                value
                    .parse()
                    .map_err(|_| IpSetError::InvalidAddress(value.to_owned()))?,
            );
        }
        Self::new(name, family, parsed)
    }

    pub fn name(&self) -> &IpSetName {
        &self.name
    }

    pub fn family(&self) -> IpSetFamily {
        self.family
    }

    pub fn addresses(&self) -> &BTreeSet<IpAddr> {
        &self.addresses
    }
}

/// A validated collection of desired IP sets, sorted by name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpSetState {
    sets: BTreeMap<IpSetName, IpSetSpec>,
}

impl IpSetState {
    pub fn new(sets: impl IntoIterator<Item = IpSetSpec>) -> Result<Self, IpSetError> {
        let mut state = Self::default();
        for set in sets {
            let name = set.name.clone();
            if state.sets.insert(name.clone(), set).is_some() {
                return Err(IpSetError::DuplicateName(name));
            }
        }
        Ok(state)
    }

    pub fn iter(&self) -> impl Iterator<Item = &IpSetSpec> {
        self.sets.values()
    }

    pub fn get(&self, name: &IpSetName) -> Option<&IpSetSpec> {
        self.sets.get(name)
    }

    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }
}

/// One deterministic operation in an IP set desired-state transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpSetOperation {
    Create {
        name: IpSetName,
        family: IpSetFamily,
    },
    Add {
        name: IpSetName,
        address: IpAddr,
    },
    Remove {
        name: IpSetName,
        address: IpAddr,
    },
    Delete(IpSetSpec),
}

/// Compute a stable desired-state delta.
///
/// New sets and members are installed before ordinary removals. A family
/// change is represented as delete/create because an ipset family's type is
/// immutable. Names and addresses are always ordered lexicographically.
pub fn diff_ip_sets(previous: &IpSetState, next: &IpSetState) -> Vec<IpSetOperation> {
    let mut operations = Vec::new();

    // Family changes cannot be incremental and must vacate the name first.
    for (name, old) in &previous.sets {
        if let Some(new) = next.sets.get(name).filter(|new| new.family != old.family) {
            operations.push(IpSetOperation::Delete(old.clone()));
            operations.push(IpSetOperation::Create {
                name: name.clone(),
                family: new.family,
            });
            operations.extend(
                new.addresses
                    .iter()
                    .copied()
                    .map(|address| IpSetOperation::Add {
                        name: name.clone(),
                        address,
                    }),
            );
        }
    }

    // Create wholly new sets.
    for (name, set) in &next.sets {
        if !previous.sets.contains_key(name) {
            operations.push(IpSetOperation::Create {
                name: name.clone(),
                family: set.family,
            });
            operations.extend(
                set.addresses
                    .iter()
                    .copied()
                    .map(|address| IpSetOperation::Add {
                        name: name.clone(),
                        address,
                    }),
            );
        }
    }

    // Add members to sets whose family did not change.
    for (name, new) in &next.sets {
        let Some(old) = previous
            .sets
            .get(name)
            .filter(|old| old.family == new.family)
        else {
            continue;
        };
        operations.extend(
            new.addresses
                .difference(&old.addresses)
                .copied()
                .map(|address| IpSetOperation::Add {
                    name: name.clone(),
                    address,
                }),
        );
    }

    // Remove obsolete members only after additions have completed.
    for (name, old) in &previous.sets {
        let Some(new) = next.sets.get(name).filter(|new| new.family == old.family) else {
            continue;
        };
        operations.extend(
            old.addresses
                .difference(&new.addresses)
                .copied()
                .map(|address| IpSetOperation::Remove {
                    name: name.clone(),
                    address,
                }),
        );
    }

    // Delete wholly obsolete sets last.
    operations.extend(
        previous
            .sets
            .iter()
            .filter(|(name, _)| !next.sets.contains_key(*name))
            .map(|(_, set)| IpSetOperation::Delete(set.clone())),
    );
    operations
}

/// An executor failure. The manager adds the exact program and argument vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpSetExecutionError {
    message: String,
}

impl IpSetExecutionError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for IpSetExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for IpSetExecutionError {}

/// Injectable process executor used by [`IpSetManager`].
pub trait IpSetExecutor: Send {
    fn execute(&mut self, program: &str, args: &[String]) -> Result<(), IpSetExecutionError>;
}

/// The production executor. It is a supported command runner only on Linux.
#[derive(Default)]
pub struct SystemIpSetExecutor;

impl IpSetExecutor for SystemIpSetExecutor {
    fn execute(&mut self, program: &str, args: &[String]) -> Result<(), IpSetExecutionError> {
        #[cfg(target_os = "linux")]
        {
            let output = Command::new(program)
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()
                .map_err(|error| IpSetExecutionError::new(error.to_string()))?;
            if output.status.success() {
                return Ok(());
            }
            return Err(IpSetExecutionError::new(format!(
                "exit {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (program, args);
            Err(IpSetExecutionError::new(
                "Linux ipset management is unsupported on this platform",
            ))
        }
    }
}

/// A failed command, including its unambiguous argument vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpSetCommandFailure {
    pub program: String,
    pub args: Vec<String>,
    pub error: IpSetExecutionError,
}

/// Errors from input validation or desired-state application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpSetError {
    InvalidName(String),
    InvalidAddress(String),
    AddressFamilyMismatch {
        set: IpSetName,
        family: IpSetFamily,
        address: IpAddr,
    },
    DuplicateName(IpSetName),
    Apply {
        failed: IpSetCommandFailure,
        rollback_failures: Vec<IpSetCommandFailure>,
    },
}

impl fmt::Display for IpSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(name) => write!(f, "invalid ipset name {name:?}"),
            Self::InvalidAddress(address) => write!(f, "invalid IP address {address:?}"),
            Self::AddressFamilyMismatch {
                set,
                family,
                address,
            } => write!(
                f,
                "address {address} does not match {family:?} family of set {set}"
            ),
            Self::DuplicateName(name) => write!(f, "duplicate ipset name {name}"),
            Self::Apply {
                failed,
                rollback_failures,
            } => write!(
                f,
                "ipset {:?} {:?} failed: {}; {} rollback command(s) failed",
                failed.program,
                failed.args,
                failed.error.message,
                rollback_failures.len()
            ),
        }
    }
}

impl std::error::Error for IpSetError {}

type CommandSpec = (String, Vec<String>);

#[derive(Clone)]
enum Effect {
    Create(IpSetSpec),
    Add(IpSetName, IpAddr),
    Remove(IpSetName, IpAddr),
    Delete(IpSetName),
}

#[derive(Clone)]
struct Step {
    command: CommandSpec,
    effect: Effect,
}

struct PlannedStep {
    forward: Step,
    rollback: Vec<Step>,
}

fn command(args: impl IntoIterator<Item = String>) -> CommandSpec {
    ("ipset".to_owned(), args.into_iter().collect())
}

fn create_step(name: &IpSetName, family: IpSetFamily) -> Step {
    Step {
        command: command([
            "create".to_owned(),
            name.to_string(),
            "hash:ip".to_owned(),
            "family".to_owned(),
            family.command_name().to_owned(),
        ]),
        effect: Effect::Create(IpSetSpec {
            name: name.clone(),
            family,
            addresses: BTreeSet::new(),
        }),
    }
}

fn add_step(name: &IpSetName, address: IpAddr) -> Step {
    Step {
        command: command([
            "add".to_owned(),
            name.to_string(),
            address.to_string(),
            "-exist".to_owned(),
        ]),
        effect: Effect::Add(name.clone(), address),
    }
}

fn remove_step(name: &IpSetName, address: IpAddr) -> Step {
    Step {
        command: command([
            "del".to_owned(),
            name.to_string(),
            address.to_string(),
            "-exist".to_owned(),
        ]),
        effect: Effect::Remove(name.clone(), address),
    }
}

fn delete_step(name: &IpSetName) -> Step {
    Step {
        command: command(["destroy".to_owned(), name.to_string()]),
        effect: Effect::Delete(name.clone()),
    }
}

fn plan(operations: &[IpSetOperation]) -> Vec<PlannedStep> {
    operations
        .iter()
        .map(|operation| match operation {
            IpSetOperation::Create { name, family } => PlannedStep {
                forward: create_step(name, *family),
                rollback: vec![delete_step(name)],
            },
            IpSetOperation::Add { name, address } => PlannedStep {
                forward: add_step(name, *address),
                rollback: vec![remove_step(name, *address)],
            },
            IpSetOperation::Remove { name, address } => PlannedStep {
                forward: remove_step(name, *address),
                rollback: vec![add_step(name, *address)],
            },
            IpSetOperation::Delete(set) => {
                let mut rollback = vec![create_step(&set.name, set.family)];
                rollback.extend(
                    set.addresses
                        .iter()
                        .copied()
                        .map(|address| add_step(&set.name, address)),
                );
                PlannedStep {
                    forward: delete_step(&set.name),
                    rollback,
                }
            }
        })
        .collect()
}

fn apply_effect(state: &mut IpSetState, effect: &Effect) {
    match effect {
        Effect::Create(set) => {
            state.sets.insert(set.name.clone(), set.clone());
        }
        Effect::Add(name, address) => {
            if let Some(set) = state.sets.get_mut(name) {
                set.addresses.insert(*address);
            }
        }
        Effect::Remove(name, address) => {
            if let Some(set) = state.sets.get_mut(name) {
                set.addresses.remove(address);
            }
        }
        Effect::Delete(name) => {
            state.sets.remove(name);
        }
    }
}

/// Transactional, desired-state manager for sets owned by this instance.
///
/// Every successful forward command is journaled. On failure, inverse commands
/// are run in reverse order. The tracked state is updated after each successful
/// forward or rollback command, so even a rollback failure does not make the
/// manager claim ownership of an uncreated or already-destroyed set.
pub struct IpSetManager<E> {
    executor: E,
    state: IpSetState,
}

impl IpSetManager<SystemIpSetExecutor> {
    pub fn system() -> Self {
        Self::with_executor(SystemIpSetExecutor)
    }
}

impl<E: IpSetExecutor> IpSetManager<E> {
    pub fn with_executor(executor: E) -> Self {
        Self {
            executor,
            state: IpSetState::default(),
        }
    }

    pub fn state(&self) -> &IpSetState {
        &self.state
    }

    pub fn executor(&self) -> &E {
        &self.executor
    }

    pub fn executor_mut(&mut self) -> &mut E {
        &mut self.executor
    }

    /// Apply `desired`, or best-effort roll back every completed command.
    pub fn apply(&mut self, desired: &IpSetState) -> Result<(), IpSetError> {
        let operations = diff_ip_sets(&self.state, desired);
        let planned = plan(&operations);
        let mut completed: Vec<PlannedStep> = Vec::new();

        for step in planned {
            if let Err(error) = self.run(&step.forward) {
                let mut rollback_failures = Vec::new();
                for completed_step in completed.iter().rev() {
                    for rollback in &completed_step.rollback {
                        if let Err(error) = self.run(rollback) {
                            rollback_failures.push(IpSetCommandFailure {
                                program: rollback.command.0.clone(),
                                args: rollback.command.1.clone(),
                                error,
                            });
                            // Later commands in this inverse operation depend
                            // on this one. In particular, never add members if
                            // recreating a destroyed set failed: another owner
                            // might now hold that name.
                            break;
                        }
                        apply_effect(&mut self.state, &rollback.effect);
                    }
                }
                return Err(IpSetError::Apply {
                    failed: IpSetCommandFailure {
                        program: step.forward.command.0,
                        args: step.forward.command.1,
                        error,
                    },
                    rollback_failures,
                });
            }
            apply_effect(&mut self.state, &step.forward.effect);
            completed.push(step);
        }

        debug_assert_eq!(&self.state, desired);
        Ok(())
    }

    /// Destroy all sets still owned by this manager. Calling `close` again is a
    /// no-op. Sets that this manager did not successfully create are untouched.
    pub fn close(&mut self) -> Result<(), IpSetError> {
        self.apply(&IpSetState::default())
    }

    pub fn into_executor(self) -> E {
        self.executor
    }

    fn run(&mut self, step: &Step) -> Result<(), IpSetExecutionError> {
        self.executor.execute(&step.command.0, &step.command.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    type RecordedCommand = (String, Vec<String>);

    #[derive(Default)]
    struct RecordingExecutor {
        commands: Vec<RecordedCommand>,
        calls: usize,
        fail_at: BTreeSet<usize>,
    }

    impl RecordingExecutor {
        fn reset(&mut self, fail_at: impl IntoIterator<Item = usize>) {
            self.commands.clear();
            self.calls = 0;
            self.fail_at = fail_at.into_iter().collect();
        }
    }

    impl IpSetExecutor for RecordingExecutor {
        fn execute(&mut self, program: &str, args: &[String]) -> Result<(), IpSetExecutionError> {
            let call = self.calls;
            self.calls += 1;
            self.commands.push((program.to_owned(), args.to_vec()));
            if self.fail_at.remove(&call) {
                Err(IpSetExecutionError::new(format!("failure at {call}")))
            } else {
                Ok(())
            }
        }
    }

    fn v4(values: &[u8]) -> IpSetSpec {
        IpSetSpec::new(
            "alpha",
            IpSetFamily::Ipv4,
            values
                .iter()
                .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, *last))),
        )
        .unwrap()
    }

    fn v6(name: &str) -> IpSetSpec {
        IpSetSpec::new(name, IpSetFamily::Ipv6, [IpAddr::V6(Ipv6Addr::LOCALHOST)]).unwrap()
    }

    fn state(sets: impl IntoIterator<Item = IpSetSpec>) -> IpSetState {
        IpSetState::new(sets).unwrap()
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn validates_names_addresses_families_and_duplicate_sets() {
        for invalid in [
            "",
            "-option",
            "with space",
            "semi;colon",
            "nonascii-ß",
            "abcdefghijklmnopqrstuvwxyz123456",
        ] {
            assert!(matches!(
                IpSetName::new(invalid),
                Err(IpSetError::InvalidName(_))
            ));
        }
        assert!(IpSetName::new("rustscale.peers-4").is_ok());

        assert!(matches!(
            IpSetSpec::parse("valid", IpSetFamily::Ipv4, ["not-an-ip"]),
            Err(IpSetError::InvalidAddress(_))
        ));
        assert!(matches!(
            IpSetSpec::parse("valid", IpSetFamily::Ipv4, ["::1"]),
            Err(IpSetError::AddressFamilyMismatch { .. })
        ));

        let first = v4(&[1]);
        assert!(matches!(
            IpSetState::new([first.clone(), first]),
            Err(IpSetError::DuplicateName(_))
        ));
    }

    #[test]
    fn desired_state_diff_is_deterministic_and_adds_before_removes() {
        let obsolete = IpSetSpec::new(
            "z-obsolete",
            IpSetFamily::Ipv4,
            [IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))],
        )
        .unwrap();
        let previous = state([obsolete.clone(), v4(&[2, 1])]);
        let next = state([v6("beta"), v4(&[3, 2])]);
        let alpha = IpSetName::new("alpha").unwrap();
        let beta = IpSetName::new("beta").unwrap();

        assert_eq!(
            diff_ip_sets(&previous, &next),
            [
                IpSetOperation::Create {
                    name: beta.clone(),
                    family: IpSetFamily::Ipv6,
                },
                IpSetOperation::Add {
                    name: beta,
                    address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                },
                IpSetOperation::Add {
                    name: alpha.clone(),
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
                },
                IpSetOperation::Remove {
                    name: alpha,
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                },
                IpSetOperation::Delete(obsolete),
            ]
        );
    }

    #[test]
    fn exact_command_vectors_are_argument_separated_and_idempotent() {
        let desired = state([v6("beta"), v4(&[2, 1, 1])]);
        let mut manager = IpSetManager::with_executor(RecordingExecutor::default());
        manager.apply(&desired).unwrap();

        assert_eq!(
            manager.executor().commands,
            [
                (
                    "ipset".into(),
                    strings(&["create", "alpha", "hash:ip", "family", "inet"]),
                ),
                (
                    "ipset".into(),
                    strings(&["add", "alpha", "192.0.2.1", "-exist"]),
                ),
                (
                    "ipset".into(),
                    strings(&["add", "alpha", "192.0.2.2", "-exist"]),
                ),
                (
                    "ipset".into(),
                    strings(&["create", "beta", "hash:ip", "family", "inet6"]),
                ),
                ("ipset".into(), strings(&["add", "beta", "::1", "-exist"]),),
            ]
        );

        manager.executor_mut().reset([]);
        manager.apply(&desired).unwrap();
        assert!(manager.executor().commands.is_empty());

        let changed = state([
            v4(&[2, 3]),
            IpSetSpec::new(
                "gamma",
                IpSetFamily::Ipv4,
                [IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))],
            )
            .unwrap(),
        ]);
        manager.apply(&changed).unwrap();
        assert_eq!(
            manager.executor().commands,
            [
                (
                    "ipset".into(),
                    strings(&["create", "gamma", "hash:ip", "family", "inet"]),
                ),
                (
                    "ipset".into(),
                    strings(&["add", "gamma", "203.0.113.9", "-exist"]),
                ),
                (
                    "ipset".into(),
                    strings(&["add", "alpha", "192.0.2.3", "-exist"]),
                ),
                (
                    "ipset".into(),
                    strings(&["del", "alpha", "192.0.2.1", "-exist"]),
                ),
                ("ipset".into(), strings(&["destroy", "beta"])),
            ]
        );

        manager.executor_mut().reset([]);
        manager.close().unwrap();
        assert_eq!(
            manager.executor().commands,
            [
                ("ipset".into(), strings(&["destroy", "alpha"])),
                ("ipset".into(), strings(&["destroy", "gamma"])),
            ]
        );
        manager.executor_mut().reset([]);
        manager.close().unwrap();
        assert!(manager.executor().commands.is_empty());
    }

    fn old_and_changed() -> (IpSetState, IpSetState) {
        let old = state([v4(&[1]), v6("beta")]);
        let changed = state([
            v4(&[2]),
            IpSetSpec::new(
                "gamma",
                IpSetFamily::Ipv4,
                [IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))],
            )
            .unwrap(),
        ]);
        (old, changed)
    }

    #[test]
    fn failure_at_each_create_update_delete_step_rolls_back() {
        let (old, changed) = old_and_changed();

        for failure in 0..5 {
            let mut manager = IpSetManager::with_executor(RecordingExecutor::default());
            manager.apply(&old).unwrap();
            manager.executor_mut().reset([failure]);

            let error = manager.apply(&changed).unwrap_err();
            let IpSetError::Apply {
                rollback_failures, ..
            } = error
            else {
                panic!("unexpected error: {error}");
            };
            assert!(
                rollback_failures.is_empty(),
                "failure {failure}: {rollback_failures:?}"
            );
            assert_eq!(manager.state(), &old, "failure at command {failure}");
        }
    }

    #[test]
    fn family_replacement_rolls_back_at_each_step() {
        let old = state([v4(&[1])]);
        let new = state([IpSetSpec::new(
            "alpha",
            IpSetFamily::Ipv6,
            [IpAddr::V6(Ipv6Addr::LOCALHOST)],
        )
        .unwrap()]);

        for failure in 0..3 {
            let mut manager = IpSetManager::with_executor(RecordingExecutor::default());
            manager.apply(&old).unwrap();
            manager.executor_mut().reset([failure]);

            let error = manager.apply(&new).unwrap_err();
            let IpSetError::Apply {
                rollback_failures, ..
            } = error
            else {
                panic!("unexpected error: {error}");
            };
            assert!(rollback_failures.is_empty());
            assert_eq!(manager.state(), &old, "failure at command {failure}");
        }
    }

    #[test]
    fn teardown_failure_at_each_step_recreates_destroyed_sets() {
        let installed = state([v4(&[1]), v6("beta")]);

        for failure in 0..2 {
            let mut manager = IpSetManager::with_executor(RecordingExecutor::default());
            manager.apply(&installed).unwrap();
            manager.executor_mut().reset([failure]);

            let error = manager.close().unwrap_err();
            let IpSetError::Apply {
                rollback_failures, ..
            } = error
            else {
                panic!("unexpected error: {error}");
            };
            assert!(rollback_failures.is_empty());
            assert_eq!(manager.state(), &installed, "failure at command {failure}");
        }
    }

    #[test]
    fn failed_recreate_does_not_add_members_to_a_possibly_foreign_set() {
        let installed = state([v4(&[1]), v6("beta")]);
        let mut manager = IpSetManager::with_executor(RecordingExecutor::default());
        manager.apply(&installed).unwrap();
        // Alpha is destroyed, beta's destroy fails, then alpha's recreation
        // fails. Its dependent member add must not run against that name.
        manager.executor_mut().reset([1, 2]);

        let error = manager.close().unwrap_err();
        let IpSetError::Apply {
            rollback_failures, ..
        } = error
        else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(rollback_failures.len(), 1);
        assert_eq!(
            manager.executor().commands,
            [
                ("ipset".into(), strings(&["destroy", "alpha"])),
                ("ipset".into(), strings(&["destroy", "beta"])),
                (
                    "ipset".into(),
                    strings(&["create", "alpha", "hash:ip", "family", "inet"]),
                ),
            ]
        );
        assert!(manager
            .state()
            .get(&IpSetName::new("alpha").unwrap())
            .is_none());
        assert!(manager
            .state()
            .get(&IpSetName::new("beta").unwrap())
            .is_some());
    }

    #[test]
    fn rollback_failure_is_reported_and_retains_only_known_owned_state() {
        let (old, changed) = old_and_changed();
        let mut manager = IpSetManager::with_executor(RecordingExecutor::default());
        manager.apply(&old).unwrap();
        // Fail alpha's forward add, then fail destruction of the newly-created
        // gamma set while rolling back. Gamma remains tracked as owned and empty.
        manager.executor_mut().reset([2, 4]);

        let error = manager.apply(&changed).unwrap_err();
        let IpSetError::Apply {
            rollback_failures, ..
        } = error
        else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(rollback_failures.len(), 1);
        assert_eq!(manager.state().sets.len(), 3);
        assert!(manager
            .state()
            .get(&IpSetName::new("gamma").unwrap())
            .unwrap()
            .addresses()
            .is_empty());

        manager.executor_mut().reset([]);
        manager.close().unwrap();
        assert!(manager.state().is_empty());
        assert_eq!(
            manager.executor().commands,
            [
                ("ipset".into(), strings(&["destroy", "alpha"])),
                ("ipset".into(), strings(&["destroy", "beta"])),
                ("ipset".into(), strings(&["destroy", "gamma"])),
            ]
        );
    }

    #[test]
    fn failed_create_never_claims_or_tears_down_a_foreign_set() {
        let desired = state([v4(&[1])]);
        let mut executor = RecordingExecutor::default();
        executor.reset([0]);
        let mut manager = IpSetManager::with_executor(executor);

        assert!(manager.apply(&desired).is_err());
        assert!(manager.state().is_empty());
        manager.executor_mut().reset([]);
        manager.close().unwrap();
        assert!(manager.executor().commands.is_empty());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn system_executor_is_cfg_safe_and_reports_unsupported() {
        let desired = state([v4(&[1])]);
        let mut manager = IpSetManager::system();
        let error = manager.apply(&desired).unwrap_err();
        assert!(error.to_string().contains("unsupported"));
        assert!(manager.state().is_empty());
    }
}
