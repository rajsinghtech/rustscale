use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::{is_sentinel_serial, PostureError, MAX_SERIAL_LEN};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_IOREG_OUTPUT: usize = 64 * 1024;

pub(crate) fn get_serial_numbers_impl() -> Result<Vec<String>, PostureError> {
    let serial = bounded_command_output(
        "/usr/sbin/sysctl",
        &["-n", "hw.serialnumber"],
        COMMAND_TIMEOUT,
        MAX_SERIAL_LEN,
    )
    .and_then(validate_serial)
    .or_else(|_| {
        bounded_command_output(
            "/usr/sbin/ioreg",
            &["-c", "IOPlatformExpertDevice", "-d", "1", "-r", "-n"],
            COMMAND_TIMEOUT,
            MAX_IOREG_OUTPUT,
        )
        .and_then(|output| parse_ioreg_serial(&output).ok_or(PostureError::CollectionFailed))
    })?;

    if is_sentinel_serial(&serial) {
        Err(PostureError::CollectionFailed)
    } else {
        Ok(vec![serial])
    }
}

/// Run a fixed absolute-path platform utility without a shell. Output and
/// runtime are bounded so a broken utility cannot stall posture handling.
fn bounded_command_output(
    command: &str,
    args: &[&str],
    timeout: Duration,
    max_output: usize,
) -> Result<String, PostureError> {
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().ok_or(PostureError::InvalidData)?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::with_capacity(max_output + 1);
        stdout
            .take((max_output + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err(PostureError::Timeout);
        }
        thread::sleep(Duration::from_millis(10));
    };
    let bytes = reader.join().map_err(|_| PostureError::InvalidData)??;
    if !status.success() || bytes.len() > max_output {
        return Err(PostureError::InvalidData);
    }
    let output = std::str::from_utf8(&bytes).map_err(|_| PostureError::InvalidData)?;
    Ok(output.to_owned())
}

fn validate_serial(value: String) -> Result<String, PostureError> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_SERIAL_LEN || value.chars().any(char::is_control) {
        return Err(PostureError::InvalidData);
    }
    Ok(value.to_owned())
}

fn parse_ioreg_serial(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let value = line
            .trim()
            .strip_prefix("\"IOPlatformSerialNumber\" = \"")?
            .strip_suffix('"')?
            .trim();
        (!value.is_empty() && value.len() <= MAX_SERIAL_LEN && !value.chars().any(char::is_control))
            .then(|| value.to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::parse_ioreg_serial;

    #[test]
    fn serial_macos_ioreg_parsing() {
        let output = r#"
            "IOPlatformUUID" = "123"
            "IOPlatformSerialNumber" = "C02TEST12345"
        "#;
        assert_eq!(parse_ioreg_serial(output), Some("C02TEST12345".into()));
        assert_eq!(
            parse_ioreg_serial("\"IOPlatformSerialNumber\" = \"\""),
            None
        );
    }
}
