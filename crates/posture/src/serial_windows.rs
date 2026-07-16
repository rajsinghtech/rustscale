#[cfg(target_os = "windows")]
use std::io::Read;
#[cfg(target_os = "windows")]
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::{is_sentinel_serial, PostureError, MAX_SERIAL_LEN};

const REG_EXE: &str = r"C:\Windows\System32\reg.exe";
const SYSTEM32: &str = r"C:\Windows\System32";
const WINDOWS_ROOT: &str = r"C:\Windows";
const BIOS_KEY_ARG: &str = r"HKLM\HARDWARE\DESCRIPTION\System\BIOS";
const BIOS_KEY_OUTPUT: &str = r"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS";
const SERIAL_VALUE: &str = "SystemSerialNumber";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_REG_OUTPUT: usize = 4 * 1024;
const MAX_REG_LINES: usize = 8;
const MAX_REG_LINE_LEN: usize = MAX_SERIAL_LEN + 128;
const MAX_REG_TOKENS: usize = 32;
const ERROR_ACCESS_DENIED: i32 = 5;

#[cfg(target_os = "windows")]
static NEVER_CANCELLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegistryView {
    Registry64,
    Registry32,
}

impl RegistryView {
    const fn argument(self) -> &'static str {
        match self {
            Self::Registry64 => "/reg:64",
            Self::Registry32 => "/reg:32",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CommandOutput {
    exit_code: Option<i32>,
    stdout: Vec<u8>,
}

trait RegistryRunner {
    fn query(
        &self,
        view: RegistryView,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<CommandOutput, PostureError>;
}

#[cfg(target_os = "windows")]
struct SystemRegistryRunner;

#[cfg(target_os = "windows")]
impl RegistryRunner for SystemRegistryRunner {
    fn query(
        &self,
        view: RegistryView,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<CommandOutput, PostureError> {
        run_registry_command(view, deadline, cancelled)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum QueryValue {
    Missing,
    Serial(String),
}

#[cfg(target_os = "windows")]
pub(crate) fn get_serial_numbers_impl() -> Result<Vec<String>, PostureError> {
    collect_serial_numbers(&SystemRegistryRunner, &NEVER_CANCELLED)
}

fn collect_serial_numbers(
    runner: &dyn RegistryRunner,
    cancelled: &AtomicBool,
) -> Result<Vec<String>, PostureError> {
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let registry64 = query_view(runner, RegistryView::Registry64, deadline, cancelled)?;
    let registry32 = query_view(runner, RegistryView::Registry32, deadline, cancelled)?;

    match (registry64, registry32) {
        (QueryValue::Missing, QueryValue::Missing) => Err(PostureError::CollectionFailed),
        (QueryValue::Serial(left), QueryValue::Serial(right)) if left == right => Ok(vec![left]),
        // A value in only one architecture view, or conflicting values, is
        // ambiguous. Do not guess which identity should be reported.
        _ => Err(PostureError::InvalidData),
    }
}

fn query_view(
    runner: &dyn RegistryRunner,
    view: RegistryView,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<QueryValue, PostureError> {
    if cancelled.load(Ordering::Acquire) {
        return Err(PostureError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(PostureError::Timeout);
    }
    let output = runner.query(view, deadline, cancelled)?;
    match output.exit_code {
        Some(0) => parse_registry_output(&output.stdout).map(QueryValue::Serial),
        // reg.exe documents exit status 1 for an unsuccessful query. Because
        // its diagnostic text is localized, treat it as unavailable instead
        // of trying to distinguish a missing key/value from localized text.
        Some(1) => Ok(QueryValue::Missing),
        Some(ERROR_ACCESS_DENIED) => Err(PostureError::Io(std::io::ErrorKind::PermissionDenied)),
        Some(_) | None => Err(PostureError::Io(std::io::ErrorKind::Other)),
    }
}

struct CommandSpec {
    program: &'static str,
    args: [&'static str; 5],
    cwd: &'static str,
    clear_environment: bool,
    environment: [(&'static str, &'static str); 2],
}

fn registry_command_spec(view: RegistryView) -> CommandSpec {
    CommandSpec {
        program: REG_EXE,
        args: ["query", BIOS_KEY_ARG, "/v", SERIAL_VALUE, view.argument()],
        cwd: SYSTEM32,
        clear_environment: true,
        environment: [("SystemRoot", WINDOWS_ROOT), ("WINDIR", WINDOWS_ROOT)],
    }
}

#[cfg(target_os = "windows")]
fn run_registry_command(
    view: RegistryView,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<CommandOutput, PostureError> {
    let spec = registry_command_spec(view);
    let mut command = Command::new(spec.program);
    if spec.clear_environment {
        command.env_clear();
    }
    command
        .args(spec.args)
        .current_dir(spec.cwd)
        .envs(spec.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = ManagedChild::new(command.spawn()?);
    let stdout = match child.take_stdout() {
        Some(stdout) => stdout,
        None => return Err(PostureError::InvalidData),
    };
    let reader = thread::Builder::new()
        .name("rustscale-posture-windows-output".into())
        .spawn(move || {
            let mut bytes = Vec::with_capacity(MAX_REG_OUTPUT + 1);
            stdout
                .take((MAX_REG_OUTPUT + 1) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        })?;

    let exit_result = wait_for_exit(&mut child, deadline, cancelled);
    // Always join the bounded reader after the child has exited or has been
    // killed and reaped; timeout/cancellation must not detach helper work.
    let read_result = reader.join().map_err(|_| PostureError::InvalidData);
    let exit_code = exit_result?;
    let bytes = read_result??;
    if bytes.len() > MAX_REG_OUTPUT {
        return Err(PostureError::InvalidData);
    }
    Ok(CommandOutput {
        exit_code,
        stdout: bytes,
    })
}

enum PollStatus {
    Running,
    Exited(Option<i32>),
}

trait ChildLifecycle {
    fn try_wait_code(&mut self) -> std::io::Result<PollStatus>;
    fn kill_child(&mut self) -> std::io::Result<()>;
    fn wait_code(&mut self) -> std::io::Result<Option<i32>>;
}

#[cfg(target_os = "windows")]
struct ManagedChild {
    child: Child,
    reaped: bool,
}

#[cfg(target_os = "windows")]
impl ManagedChild {
    const fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.stdout.take()
    }
}

#[cfg(target_os = "windows")]
impl ChildLifecycle for ManagedChild {
    fn try_wait_code(&mut self) -> std::io::Result<PollStatus> {
        self.child.try_wait().map(|status| match status {
            Some(status) => PollStatus::Exited(status.code()),
            None => PollStatus::Running,
        })
    }

    fn kill_child(&mut self) -> std::io::Result<()> {
        self.child.kill()
    }

    fn wait_code(&mut self) -> std::io::Result<Option<i32>> {
        let result = self.child.wait().map(|status| status.code());
        if result.is_ok() {
            self.reaped = true;
        }
        result
    }
}

#[cfg(target_os = "windows")]
impl Drop for ManagedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn wait_for_exit(
    child: &mut dyn ChildLifecycle,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Option<i32>, PostureError> {
    loop {
        if cancelled.load(Ordering::Acquire) {
            terminate_and_reap(child);
            return Err(PostureError::Cancelled);
        }
        match child.try_wait_code() {
            Ok(PollStatus::Exited(exit_code)) => {
                // `try_wait` has observed termination. Call `wait` as the
                // single explicit ownership/reap point before returning.
                child.wait_code().map_err(PostureError::from)?;
                return Ok(exit_code);
            }
            Ok(PollStatus::Running) => {}
            Err(error) => {
                terminate_and_reap(child);
                return Err(error.into());
            }
        }
        let now = Instant::now();
        if now >= deadline {
            terminate_and_reap(child);
            return Err(PostureError::Timeout);
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
}

fn terminate_and_reap(child: &mut dyn ChildLifecycle) {
    let _ = child.kill_child();
    let _ = child.wait_code();
}

fn parse_registry_output(bytes: &[u8]) -> Result<String, PostureError> {
    if bytes.is_empty() || bytes.len() > MAX_REG_OUTPUT || !bytes.ends_with(b"\n") {
        return Err(PostureError::InvalidData);
    }
    let output = std::str::from_utf8(bytes).map_err(|_| PostureError::InvalidData)?;
    let mut key_lines = 0_usize;
    let mut serial = None;
    let mut lines = 0_usize;

    for raw_line in output.lines() {
        lines += 1;
        if lines > MAX_REG_LINES || raw_line.len() > MAX_REG_LINE_LEN {
            return Err(PostureError::InvalidData);
        }
        let line = raw_line.trim_ascii();
        if line.is_empty() {
            continue;
        }
        if line.eq_ignore_ascii_case(BIOS_KEY_OUTPUT) {
            key_lines += 1;
            if key_lines > 1 {
                return Err(PostureError::InvalidData);
            }
            continue;
        }
        let value = parse_value_line(line)?;
        if serial.replace(value).is_some() {
            return Err(PostureError::InvalidData);
        }
    }

    match (key_lines, serial) {
        (1, Some(serial)) => Ok(serial),
        _ => Err(PostureError::InvalidData),
    }
}

fn parse_value_line(line: &str) -> Result<String, PostureError> {
    if line.split_ascii_whitespace().count() > MAX_REG_TOKENS {
        return Err(PostureError::InvalidData);
    }
    let after_name = strip_field(line, SERIAL_VALUE)?;
    let value = strip_field(after_name, "REG_SZ")?.trim_ascii();
    if value.is_empty()
        || value.len() > MAX_SERIAL_LEN
        || value.chars().any(char::is_control)
        || is_sentinel_serial(value)
    {
        return Err(PostureError::InvalidData);
    }
    Ok(value.to_owned())
}

fn strip_field<'a>(line: &'a str, expected: &str) -> Result<&'a str, PostureError> {
    let line = line.trim_ascii_start();
    let field_end = line
        .find(|character: char| character.is_ascii_whitespace())
        .unwrap_or(line.len());
    let (field, rest) = line.split_at(field_end);
    if field != expected || rest.is_empty() {
        return Err(PostureError::InvalidData);
    }
    Ok(rest.trim_ascii_start())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    fn output(serial: &str) -> Vec<u8> {
        format!("\r\n{BIOS_KEY_OUTPUT}\r\n    {SERIAL_VALUE}    REG_SZ    {serial}\r\n")
            .into_bytes()
    }

    #[derive(Default)]
    struct FixtureRunner {
        outputs: Mutex<VecDeque<Result<CommandOutput, PostureError>>>,
        views: Mutex<Vec<RegistryView>>,
    }

    impl FixtureRunner {
        fn with_outputs(outputs: Vec<Result<CommandOutput, PostureError>>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into()),
                views: Mutex::new(Vec::new()),
            }
        }
    }

    impl RegistryRunner for FixtureRunner {
        fn query(
            &self,
            view: RegistryView,
            _deadline: Instant,
            _cancelled: &AtomicBool,
        ) -> Result<CommandOutput, PostureError> {
            self.views.lock().unwrap().push(view);
            self.outputs
                .lock()
                .unwrap()
                .pop_front()
                .expect("fixture output")
        }
    }

    #[test]
    fn command_is_absolute_and_ignores_poisoned_environment_and_locale() {
        for view in [RegistryView::Registry64, RegistryView::Registry32] {
            let spec = registry_command_spec(view);
            assert_eq!(spec.program, r"C:\Windows\System32\reg.exe");
            assert_eq!(spec.cwd, r"C:\Windows\System32");
            assert!(spec.clear_environment);
            assert_eq!(spec.args[0..4], ["query", BIOS_KEY_ARG, "/v", SERIAL_VALUE]);
            assert_eq!(spec.args[4], view.argument());
            assert_eq!(
                spec.environment,
                [("SystemRoot", r"C:\Windows"), ("WINDIR", r"C:\Windows")]
            );
            for poisoned in [
                "PATH",
                "PATHEXT",
                "COMSPEC",
                "PSModulePath",
                "LANG",
                "LC_ALL",
            ] {
                assert!(spec.environment.iter().all(|(name, _)| *name != poisoned));
            }
        }

        assert_eq!(
            parse_registry_output(&output("Sérial-東京")),
            Ok("Sérial-東京".into())
        );
    }

    #[test]
    fn matching_architecture_views_return_one_upstream_system_serial() {
        let runner = FixtureRunner::with_outputs(vec![
            Ok(CommandOutput {
                exit_code: Some(0),
                stdout: output("ABC 123"),
            }),
            Ok(CommandOutput {
                exit_code: Some(0),
                stdout: output("ABC 123"),
            }),
        ]);
        assert_eq!(
            collect_serial_numbers(&runner, &AtomicBool::new(false)),
            Ok(vec!["ABC 123".into()])
        );
        assert_eq!(
            *runner.views.lock().unwrap(),
            [RegistryView::Registry64, RegistryView::Registry32]
        );
    }

    #[test]
    fn missing_access_and_abnormal_exit_statuses_are_classified_without_text() {
        let missing = FixtureRunner::with_outputs(vec![
            Ok(CommandOutput {
                exit_code: Some(1),
                stdout: b"localized missing diagnostic\r\n".to_vec(),
            }),
            Ok(CommandOutput {
                exit_code: Some(1),
                stdout: Vec::new(),
            }),
        ]);
        assert_eq!(
            collect_serial_numbers(&missing, &AtomicBool::new(false)),
            Err(PostureError::CollectionFailed)
        );

        for (exit_code, expected) in [
            (
                Some(ERROR_ACCESS_DENIED),
                PostureError::Io(std::io::ErrorKind::PermissionDenied),
            ),
            (Some(9), PostureError::Io(std::io::ErrorKind::Other)),
            (None, PostureError::Io(std::io::ErrorKind::Other)),
        ] {
            let runner = FixtureRunner::with_outputs(vec![Ok(CommandOutput {
                exit_code,
                stdout: Vec::new(),
            })]);
            assert_eq!(
                collect_serial_numbers(&runner, &AtomicBool::new(false)),
                Err(expected)
            );
        }
    }

    #[test]
    fn conflicting_missing_and_duplicate_values_are_rejected_as_ambiguous() {
        let conflicting = FixtureRunner::with_outputs(vec![
            Ok(CommandOutput {
                exit_code: Some(0),
                stdout: output("SERIAL-64"),
            }),
            Ok(CommandOutput {
                exit_code: Some(0),
                stdout: output("SERIAL-32"),
            }),
        ]);
        assert_eq!(
            collect_serial_numbers(&conflicting, &AtomicBool::new(false)),
            Err(PostureError::InvalidData)
        );

        let one_missing = FixtureRunner::with_outputs(vec![
            Ok(CommandOutput {
                exit_code: Some(0),
                stdout: output("SERIAL"),
            }),
            Ok(CommandOutput {
                exit_code: Some(1),
                stdout: Vec::new(),
            }),
        ]);
        assert_eq!(
            collect_serial_numbers(&one_missing, &AtomicBool::new(false)),
            Err(PostureError::InvalidData)
        );

        let mut duplicate = output("SERIAL");
        duplicate
            .extend_from_slice(format!("    {SERIAL_VALUE}    REG_SZ    SERIAL\r\n").as_bytes());
        assert_eq!(
            parse_registry_output(&duplicate),
            Err(PostureError::InvalidData)
        );
    }

    #[test]
    fn malformed_placeholder_oversized_and_truncated_output_is_rejected() {
        for malformed in [
            Vec::new(),
            b"not utf-8: \xff\n".to_vec(),
            output("To Be Filled By O.E.M."),
            format!("{BIOS_KEY_OUTPUT}\n    {SERIAL_VALUE}    REG_DWORD    123\n").into_bytes(),
        ] {
            assert_eq!(
                parse_registry_output(&malformed),
                Err(PostureError::InvalidData)
            );
        }

        let oversized_serial = "x".repeat(MAX_SERIAL_LEN + 1);
        assert_eq!(
            parse_registry_output(&output(&oversized_serial)),
            Err(PostureError::InvalidData)
        );

        let mut truncated = output("SERIAL");
        truncated.pop();
        assert_eq!(
            parse_registry_output(&truncated),
            Err(PostureError::InvalidData)
        );

        let oversized_output = vec![b'x'; MAX_REG_OUTPUT + 1];
        assert_eq!(
            parse_registry_output(&oversized_output),
            Err(PostureError::InvalidData)
        );

        let too_many_lines = format!(
            "{}{}\n    {SERIAL_VALUE}    REG_SZ    SERIAL\n",
            "\n".repeat(MAX_REG_LINES),
            BIOS_KEY_OUTPUT
        );
        assert_eq!(
            parse_registry_output(too_many_lines.as_bytes()),
            Err(PostureError::InvalidData)
        );

        let too_many_tokens = (0..MAX_REG_TOKENS)
            .map(|_| "x")
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            parse_registry_output(&output(&too_many_tokens)),
            Err(PostureError::InvalidData)
        );
    }

    #[derive(Default)]
    struct LifecycleFixture {
        polls: VecDeque<std::io::Result<PollStatus>>,
        kills: usize,
        waits: usize,
    }

    impl ChildLifecycle for LifecycleFixture {
        fn try_wait_code(&mut self) -> std::io::Result<PollStatus> {
            self.polls.pop_front().unwrap_or(Ok(PollStatus::Running))
        }

        fn kill_child(&mut self) -> std::io::Result<()> {
            self.kills += 1;
            Ok(())
        }

        fn wait_code(&mut self) -> std::io::Result<Option<i32>> {
            self.waits += 1;
            Ok(Some(0))
        }
    }

    #[test]
    fn timeout_and_cancellation_kill_and_reap_the_child() {
        let mut timed_out = LifecycleFixture::default();
        assert_eq!(
            wait_for_exit(&mut timed_out, Instant::now(), &AtomicBool::new(false)),
            Err(PostureError::Timeout)
        );
        assert_eq!((timed_out.kills, timed_out.waits), (1, 1));

        let mut cancelled = LifecycleFixture::default();
        assert_eq!(
            wait_for_exit(
                &mut cancelled,
                Instant::now() + Duration::from_secs(60),
                &AtomicBool::new(true),
            ),
            Err(PostureError::Cancelled)
        );
        assert_eq!((cancelled.kills, cancelled.waits), (1, 1));
    }

    #[test]
    fn success_and_poll_errors_are_also_reaped() {
        let mut success = LifecycleFixture {
            polls: VecDeque::from([Ok(PollStatus::Exited(Some(0)))]),
            ..LifecycleFixture::default()
        };
        assert_eq!(
            wait_for_exit(
                &mut success,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false),
            ),
            Ok(Some(0))
        );
        assert_eq!((success.kills, success.waits), (0, 1));

        let mut failed = LifecycleFixture {
            polls: VecDeque::from([Err(std::io::Error::other("fixture"))]),
            ..LifecycleFixture::default()
        };
        assert_eq!(
            wait_for_exit(
                &mut failed,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false),
            ),
            Err(PostureError::Io(std::io::ErrorKind::Other))
        );
        assert_eq!((failed.kills, failed.waits), (1, 1));
    }
}
