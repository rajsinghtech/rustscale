use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(crate) struct BoundedOutput {
    pub status_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandError {
    Spawn,
    Timeout,
    OutputTooLarge,
}

/// Runs a fixed executable directly, without a shell, with bounded output and
/// wall-clock runtime.
pub(crate) fn run_bounded(
    executable: &Path,
    args: &[&str],
    timeout: Duration,
    max_output: usize,
) -> Result<BoundedOutput, CommandError> {
    if !executable.is_absolute() {
        return Err(CommandError::Spawn);
    }
    let mut child = Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| CommandError::Spawn)?;
    let stdout = child.stdout.take().ok_or(CommandError::Spawn)?;
    let stderr = child.stderr.take().ok_or(CommandError::Spawn)?;
    let stdout_reader = bounded_reader(stdout, max_output);
    let stderr_reader = bounded_reader(stderr, max_output);

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(CommandError::Timeout);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(CommandError::Spawn);
            }
        }
    };
    let stdout = stdout_reader.join().map_err(|_| CommandError::Spawn)?;
    let stderr = stderr_reader.join().map_err(|_| CommandError::Spawn)?;
    if stdout.len() > max_output || stderr.len() > max_output {
        return Err(CommandError::OutputTooLarge);
    }
    Ok(BoundedOutput {
        status_code: status.code(),
        stdout,
        stderr,
    })
}

fn bounded_reader<R: Read + Send + 'static>(
    reader: R,
    max_output: usize,
) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::with_capacity(max_output.saturating_add(1));
        let _ = reader
            .take(
                u64::try_from(max_output)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut bytes);
        bytes
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn command_runtime_and_output_are_bounded() {
        let output = run_bounded(
            Path::new("/usr/bin/printf"),
            &["ok"],
            Duration::from_secs(1),
            16,
        )
        .unwrap();
        assert_eq!(output.status_code, Some(0));
        assert_eq!(output.stdout, b"ok");
        assert!(output.stderr.is_empty());

        assert_eq!(
            run_bounded(
                Path::new("/bin/sleep"),
                &["1"],
                Duration::from_millis(10),
                16,
            )
            .unwrap_err(),
            CommandError::Timeout
        );
        assert_eq!(
            run_bounded(
                Path::new("/usr/bin/printf"),
                &["0123456789"],
                Duration::from_secs(1),
                4,
            )
            .unwrap_err(),
            CommandError::OutputTooLarge
        );
    }
}
