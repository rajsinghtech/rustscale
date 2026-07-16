//! Small, fail-closed helpers for Linux freedesktop sessions.
//!
//! This crate deliberately does not implement a tray or GUI. It detects whether
//! a command is running in a graphical user session and exposes only the two
//! desktop operations used by upstream clients: opening an HTTP(S) URL and
//! posting a notification. Production calls use direct argv execution with a
//! deadline; no shell is involved.

#![forbid(unsafe_code)]

pub mod systemd_user;

use std::ffi::OsString;
use std::process::{Command, Stdio};
use std::time::Duration;

use thiserror::Error;
use url::Url;
use wait_timeout::ChildExt;

const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_URI_BYTES: usize = 8 * 1024;
const MAX_NOTIFICATION_SUMMARY_BYTES: usize = 512;
const MAX_NOTIFICATION_BODY_BYTES: usize = 16 * 1024;
const MAX_NOTIFICATION_EXPIRY: Duration = Duration::from_secs(60);

/// A commonly encountered Linux desktop environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DesktopEnvironment {
    Gnome,
    Kde,
    Cinnamon,
    Xfce,
    Mate,
    Lxde,
    Lxqt,
    Unity,
    Pantheon,
    Deepin,
    Cosmic,
    Sway,
    Hyprland,
    Other(String),
}

/// The display protocol reported by the login session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionType {
    Wayland,
    X11,
    Mir,
    Tty,
    Unknown,
}

/// A conservative snapshot of the caller's desktop session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopSession {
    pub environment: Option<DesktopEnvironment>,
    pub session_type: SessionType,
    pub has_graphical_display: bool,
    pub has_session_bus: bool,
    pub is_remote: bool,
}

impl DesktopSession {
    /// Detect a session from the current process environment.
    pub fn detect() -> Self {
        Self::detect_with(&SystemEnvironment)
    }

    /// Detect a session through an injectable environment provider.
    pub fn detect_with(environment: &dyn Environment) -> Self {
        let desktop = desktop_candidates(environment);
        let session_type = detect_session_type(environment);
        let has_display_variable = ["WAYLAND_DISPLAY", "DISPLAY", "MIR_SOCKET"]
            .iter()
            .any(|name| nonempty(environment.var(name).as_deref()));

        Self {
            environment: detect_desktop_environment(&desktop),
            session_type,
            has_graphical_display: has_display_variable
                || matches!(
                    session_type,
                    SessionType::Wayland | SessionType::X11 | SessionType::Mir
                ),
            has_session_bus: nonempty(environment.var("DBUS_SESSION_BUS_ADDRESS").as_deref()),
            is_remote: ["SSH_CONNECTION", "SSH_CLIENT", "REMOTEHOST"]
                .iter()
                .any(|name| nonempty(environment.var(name).as_deref())),
        }
    }
}

/// Environment lookup abstraction for hermetic session-detection tests.
pub trait Environment: Send + Sync {
    fn var(&self, name: &str) -> Option<OsString>;
}

/// Current-process environment lookup.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemEnvironment;

impl Environment for SystemEnvironment {
    fn var(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

fn nonempty(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

fn environment_text(environment: &dyn Environment, name: &str) -> Option<String> {
    let value = environment.var(name)?;
    let value = value.to_string_lossy();
    let value = value.trim();
    (!value.is_empty() && !value.contains('\0')).then(|| value.to_owned())
}

fn desktop_candidates(environment: &dyn Environment) -> Vec<String> {
    [
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_DESKTOP",
        "DESKTOP_SESSION",
        "GDMSESSION",
    ]
    .iter()
    .filter_map(|name| environment_text(environment, name))
    .flat_map(|value| {
        value
            .split([':', ';', ','])
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    })
    .collect()
}

fn detect_desktop_environment(candidates: &[String]) -> Option<DesktopEnvironment> {
    candidates
        .iter()
        .find_map(|candidate| classify_desktop(candidate, false))
        .or_else(|| {
            candidates
                .first()
                .and_then(|candidate| classify_desktop(candidate, true))
        })
}

fn classify_desktop(value: &str, permit_other: bool) -> Option<DesktopEnvironment> {
    let normalized = value.trim().to_ascii_lowercase();
    let known = if normalized.contains("gnome") || normalized == "ubuntu" {
        Some(DesktopEnvironment::Gnome)
    } else if normalized.contains("plasma") || normalized == "kde" {
        Some(DesktopEnvironment::Kde)
    } else if normalized.contains("cinnamon") {
        Some(DesktopEnvironment::Cinnamon)
    } else if normalized.contains("xfce") {
        Some(DesktopEnvironment::Xfce)
    } else if normalized == "mate" || normalized.starts_with("mate-") {
        Some(DesktopEnvironment::Mate)
    } else if normalized == "lxde" || normalized.starts_with("lxde-") {
        Some(DesktopEnvironment::Lxde)
    } else if normalized.contains("lxqt") {
        Some(DesktopEnvironment::Lxqt)
    } else if normalized.contains("unity") {
        Some(DesktopEnvironment::Unity)
    } else if normalized.contains("pantheon") {
        Some(DesktopEnvironment::Pantheon)
    } else if normalized.contains("deepin") {
        Some(DesktopEnvironment::Deepin)
    } else if normalized.contains("cosmic") {
        Some(DesktopEnvironment::Cosmic)
    } else if normalized == "sway" {
        Some(DesktopEnvironment::Sway)
    } else if normalized == "hyprland" {
        Some(DesktopEnvironment::Hyprland)
    } else {
        None
    };

    known.or_else(|| {
        (permit_other && !normalized.is_empty())
            .then(|| DesktopEnvironment::Other(normalized.chars().take(128).collect::<String>()))
    })
}

fn detect_session_type(environment: &dyn Environment) -> SessionType {
    match environment_text(environment, "XDG_SESSION_TYPE")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "wayland" => SessionType::Wayland,
        "x11" => SessionType::X11,
        "mir" => SessionType::Mir,
        "tty" => SessionType::Tty,
        _ if nonempty(environment.var("WAYLAND_DISPLAY").as_deref()) => SessionType::Wayland,
        _ if nonempty(environment.var("DISPLAY").as_deref()) => SessionType::X11,
        _ if nonempty(environment.var("MIR_SOCKET").as_deref()) => SessionType::Mir,
        _ => SessionType::Unknown,
    }
}

/// A command and its hard execution deadline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub timeout: Duration,
}

/// Failure reported by an injected command runner.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CommandError {
    #[error("command is unavailable")]
    Unavailable,
    #[error("command timed out")]
    TimedOut,
    #[error("command exited unsuccessfully")]
    Failed,
    #[error("command I/O failed: {0}")]
    Io(String),
}

/// Injectable direct-command transport.
pub trait CommandRunner: Send + Sync {
    fn run(&self, command: &CommandSpec) -> Result<(), CommandError>;
}

/// Production runner. It never invokes a shell and always kills a timed-out child.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, command: &CommandSpec) -> Result<(), CommandError> {
        if command.program.is_empty() || command.program.contains('\0') {
            return Err(CommandError::Unavailable);
        }
        let timeout = command.timeout.min(MAX_COMMAND_TIMEOUT);
        if timeout.is_zero() {
            return Err(CommandError::TimedOut);
        }
        let mut child = Command::new(&command.program)
            .args(&command.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => CommandError::Unavailable,
                _ => CommandError::Io(error.to_string()),
            })?;
        let Some(status) = child
            .wait_timeout(timeout)
            .map_err(|error| CommandError::Io(error.to_string()))?
        else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CommandError::TimedOut);
        };
        status.success().then_some(()).ok_or(CommandError::Failed)
    }
}

/// Which freedesktop opener accepted a URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenMethod {
    XdgOpen,
    Gio,
}

/// Errors from a desktop operation. Callers should normally treat
/// `NoGraphicalSession` and `NoSessionBus` as graceful absence.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum IntegrationError {
    #[error("no graphical desktop session is available")]
    NoGraphicalSession,
    #[error("no desktop session bus is available")]
    NoSessionBus,
    #[error("URI is not a safe HTTP(S) URL: {0}")]
    InvalidUri(&'static str),
    #[error("notification is invalid: {0}")]
    InvalidNotification(&'static str),
    #[error("desktop integration command failed or is unavailable")]
    TransportUnavailable,
}

/// Injectable freedesktop transport used by CLI and daemon callers.
pub trait DesktopTransport: Send + Sync {
    fn open_url(&self, session: &DesktopSession, uri: &str)
        -> Result<OpenMethod, IntegrationError>;

    fn notify(
        &self,
        session: &DesktopSession,
        summary: &str,
        body: &str,
        expiry: Duration,
    ) -> Result<(), IntegrationError>;
}

/// Bounded command-backed freedesktop integration.
pub struct Freedesktop<R = SystemCommandRunner> {
    runner: R,
    command_timeout: Duration,
}

impl Default for Freedesktop<SystemCommandRunner> {
    fn default() -> Self {
        Self::new(SystemCommandRunner, DEFAULT_COMMAND_TIMEOUT)
    }
}

impl<R: CommandRunner> Freedesktop<R> {
    pub fn new(runner: R, command_timeout: Duration) -> Self {
        Self {
            runner,
            command_timeout: command_timeout.min(MAX_COMMAND_TIMEOUT),
        }
    }

    fn command(&self, program: &str, args: Vec<String>) -> Result<(), CommandError> {
        if self.command_timeout.is_zero() {
            return Err(CommandError::TimedOut);
        }
        self.runner.run(&CommandSpec {
            program: program.to_owned(),
            args,
            timeout: self.command_timeout,
        })
    }
}

impl<R: CommandRunner> DesktopTransport for Freedesktop<R> {
    fn open_url(
        &self,
        session: &DesktopSession,
        uri: &str,
    ) -> Result<OpenMethod, IntegrationError> {
        if !session.has_graphical_display {
            return Err(IntegrationError::NoGraphicalSession);
        }
        let uri = validate_http_uri(uri)?;

        if self.command("xdg-open", vec![uri.clone()]).is_ok() {
            return Ok(OpenMethod::XdgOpen);
        }
        if self.command("gio", vec!["open".to_owned(), uri]).is_ok() {
            return Ok(OpenMethod::Gio);
        }
        Err(IntegrationError::TransportUnavailable)
    }

    fn notify(
        &self,
        session: &DesktopSession,
        summary: &str,
        body: &str,
        expiry: Duration,
    ) -> Result<(), IntegrationError> {
        if !session.has_graphical_display {
            return Err(IntegrationError::NoGraphicalSession);
        }
        if !session.has_session_bus {
            return Err(IntegrationError::NoSessionBus);
        }
        validate_notification(summary, body)?;
        let expiry_ms = expiry.min(MAX_NOTIFICATION_EXPIRY).as_millis().max(1);
        self.command(
            "notify-send",
            vec![
                "--app-name=RustScale".to_owned(),
                format!("--expire-time={expiry_ms}"),
                "--".to_owned(),
                summary.to_owned(),
                body.to_owned(),
            ],
        )
        .map_err(|_| IntegrationError::TransportUnavailable)
    }
}

fn validate_http_uri(uri: &str) -> Result<String, IntegrationError> {
    if uri.is_empty() || uri.len() > MAX_URI_BYTES {
        return Err(IntegrationError::InvalidUri("invalid length"));
    }
    if uri.chars().any(char::is_control) {
        return Err(IntegrationError::InvalidUri("control character"));
    }
    let parsed = Url::parse(uri).map_err(|_| IntegrationError::InvalidUri("malformed URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(IntegrationError::InvalidUri("unsupported scheme"));
    }
    if parsed.host_str().is_none() {
        return Err(IntegrationError::InvalidUri("missing host"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(IntegrationError::InvalidUri("embedded credentials"));
    }
    Ok(parsed.into())
}

fn validate_notification(summary: &str, body: &str) -> Result<(), IntegrationError> {
    if summary.is_empty() || summary.len() > MAX_NOTIFICATION_SUMMARY_BYTES {
        return Err(IntegrationError::InvalidNotification(
            "summary has invalid length",
        ));
    }
    if body.len() > MAX_NOTIFICATION_BODY_BYTES {
        return Err(IntegrationError::InvalidNotification("body is too long"));
    }
    if summary.contains('\0') || body.contains('\0') {
        return Err(IntegrationError::InvalidNotification("contains NUL"));
    }
    Ok(())
}

/// Quote one argument according to the Desktop Entry Specification's `Exec`
/// grammar. This is for writing `.desktop` files, not for shell execution.
pub fn quote_desktop_exec_arg(argument: &str) -> String {
    const RESERVED: &str = " \t\n\"'\\><~|&;$*?#()`";
    if argument.is_empty() {
        return "\"\"".to_owned();
    }
    if !argument
        .chars()
        .any(|character| RESERVED.contains(character))
    {
        return argument.to_owned();
    }

    let mut quoted = String::with_capacity(argument.len() + 2);
    quoted.push('"');
    for character in argument.chars() {
        if matches!(character, '"' | '`' | '$' | '\\') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct FakeEnvironment(HashMap<String, OsString>);

    impl FakeEnvironment {
        fn with(mut self, name: &str, value: &str) -> Self {
            self.0.insert(name.to_owned(), value.into());
            self
        }
    }

    impl Environment for FakeEnvironment {
        fn var(&self, name: &str) -> Option<OsString> {
            self.0.get(name).cloned()
        }
    }

    #[derive(Default)]
    struct FakeRunner {
        commands: Mutex<Vec<CommandSpec>>,
        results: Mutex<VecDeque<Result<(), CommandError>>>,
    }

    impl FakeRunner {
        fn with_results(results: Vec<Result<(), CommandError>>) -> Self {
            Self {
                commands: Mutex::new(Vec::new()),
                results: Mutex::new(results.into()),
            }
        }

        fn commands(&self) -> Vec<CommandSpec> {
            self.commands.lock().unwrap().clone()
        }
    }

    impl CommandRunner for &FakeRunner {
        fn run(&self, command: &CommandSpec) -> Result<(), CommandError> {
            self.commands.lock().unwrap().push(command.clone());
            self.results.lock().unwrap().pop_front().unwrap_or(Ok(()))
        }
    }

    fn graphical_session() -> DesktopSession {
        DesktopSession {
            environment: Some(DesktopEnvironment::Gnome),
            session_type: SessionType::Wayland,
            has_graphical_display: true,
            has_session_bus: true,
            is_remote: false,
        }
    }

    #[test]
    fn detects_colon_separated_desktop_and_wayland_session() {
        let environment = FakeEnvironment::default()
            .with("XDG_CURRENT_DESKTOP", "ubuntu:GNOME")
            .with("XDG_SESSION_TYPE", "wayland")
            .with("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus");
        let session = DesktopSession::detect_with(&environment);
        assert_eq!(session.environment, Some(DesktopEnvironment::Gnome));
        assert_eq!(session.session_type, SessionType::Wayland);
        assert!(session.has_graphical_display);
        assert!(session.has_session_bus);
    }

    #[test]
    fn display_variables_are_safe_session_type_fallbacks() {
        let environment = FakeEnvironment::default()
            .with("XDG_CURRENT_DESKTOP", "plasmawayland")
            .with("DISPLAY", ":1")
            .with("SSH_CONNECTION", "client server");
        let session = DesktopSession::detect_with(&environment);
        assert_eq!(session.environment, Some(DesktopEnvironment::Kde));
        assert_eq!(session.session_type, SessionType::X11);
        assert!(session.has_graphical_display);
        assert!(session.is_remote);
    }

    #[test]
    fn desktop_name_alone_does_not_claim_a_graphical_session() {
        let environment = FakeEnvironment::default().with("XDG_CURRENT_DESKTOP", "XFCE");
        let session = DesktopSession::detect_with(&environment);
        assert_eq!(session.environment, Some(DesktopEnvironment::Xfce));
        assert!(!session.has_graphical_display);
        assert!(!session.has_session_bus);
    }

    #[test]
    fn unknown_desktop_is_preserved_in_normalized_bounded_form() {
        let environment = FakeEnvironment::default()
            .with("DESKTOP_SESSION", &format!("MyDesktop{}", "x".repeat(200)))
            .with("XDG_SESSION_TYPE", "tty");
        let session = DesktopSession::detect_with(&environment);
        let Some(DesktopEnvironment::Other(name)) = session.environment else {
            panic!("expected unknown desktop");
        };
        assert_eq!(name.len(), 128);
        assert_eq!(session.session_type, SessionType::Tty);
        assert!(!session.has_graphical_display);
    }

    #[test]
    fn open_url_uses_literal_argv_without_a_shell() {
        let runner = FakeRunner::default();
        let integration = Freedesktop::new(&runner, Duration::from_secs(2));
        let uri = "https://login.example.test/a?next=%24%28touch%20/tmp/pwned%29&x='quoted'";
        assert_eq!(
            integration.open_url(&graphical_session(), uri),
            Ok(OpenMethod::XdgOpen)
        );
        assert_eq!(
            runner.commands(),
            vec![CommandSpec {
                program: "xdg-open".to_owned(),
                args: vec![
                    "https://login.example.test/a?next=%24%28touch%20/tmp/pwned%29&x=%27quoted%27"
                        .to_owned(),
                ],
                timeout: Duration::from_secs(2),
            }]
        );
    }

    #[test]
    fn open_url_falls_back_to_gio() {
        let runner = FakeRunner::with_results(vec![Err(CommandError::Unavailable), Ok(())]);
        let integration = Freedesktop::new(&runner, Duration::from_secs(2));
        assert_eq!(
            integration.open_url(&graphical_session(), "http://127.0.0.1:8088/"),
            Ok(OpenMethod::Gio)
        );
        let commands = runner.commands();
        assert_eq!(commands[0].program, "xdg-open");
        assert_eq!(commands[1].program, "gio");
        assert_eq!(commands[1].args, ["open", "http://127.0.0.1:8088/"]);
    }

    #[test]
    fn unsafe_or_non_web_uris_never_reach_transport() {
        for uri in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://user:secret@example.test/",
            "https://example.test/\n--help",
            "not a URL",
        ] {
            let runner = FakeRunner::default();
            let integration = Freedesktop::new(&runner, Duration::from_secs(1));
            assert!(matches!(
                integration.open_url(&graphical_session(), uri),
                Err(IntegrationError::InvalidUri(_))
            ));
            assert!(runner.commands().is_empty());
        }
    }

    #[test]
    fn headless_open_is_a_graceful_noop_error() {
        let runner = FakeRunner::default();
        let integration = Freedesktop::new(&runner, Duration::from_secs(1));
        let mut session = graphical_session();
        session.has_graphical_display = false;
        assert_eq!(
            integration.open_url(&session, "https://example.test/"),
            Err(IntegrationError::NoGraphicalSession)
        );
        assert!(runner.commands().is_empty());
    }

    #[test]
    fn notification_requires_a_session_bus_and_uses_safe_argv() {
        let runner = FakeRunner::default();
        let integration = Freedesktop::new(&runner, Duration::from_secs(3));
        let summary = "Copied --value $(not-a-shell)";
        let body = "100.64.0.1; rm -rf /";
        integration
            .notify(
                &graphical_session(),
                summary,
                body,
                Duration::from_secs(300),
            )
            .unwrap();
        assert_eq!(
            runner.commands(),
            vec![CommandSpec {
                program: "notify-send".to_owned(),
                args: vec![
                    "--app-name=RustScale".to_owned(),
                    "--expire-time=60000".to_owned(),
                    "--".to_owned(),
                    summary.to_owned(),
                    body.to_owned(),
                ],
                timeout: Duration::from_secs(3),
            }]
        );

        let mut no_bus = graphical_session();
        no_bus.has_session_bus = false;
        assert_eq!(
            integration.notify(&no_bus, "title", "body", Duration::from_secs(3)),
            Err(IntegrationError::NoSessionBus)
        );
    }

    #[test]
    fn command_deadline_is_capped() {
        let runner = FakeRunner::default();
        let integration = Freedesktop::new(&runner, Duration::from_secs(600));
        integration
            .open_url(&graphical_session(), "https://example.test/")
            .unwrap();
        assert_eq!(runner.commands()[0].timeout, MAX_COMMAND_TIMEOUT);
    }

    #[test]
    fn desktop_exec_quote_matches_upstream_vectors() {
        let tests = [
            ("/home/user", "/home/user"),
            ("", "\"\""),
            (" ", "\" \""),
            ("\"", "\"\\\"\""),
            ("'", "\"'\""),
            ("\\", "\"\\\\\""),
            ("$", "\"\\$\""),
            ("`", "\"\\`\""),
            ("a;b", "\"a;b\""),
        ];
        for (input, expected) in tests {
            assert_eq!(quote_desktop_exec_arg(input), expected, "input={input:?}");
        }
    }
}
