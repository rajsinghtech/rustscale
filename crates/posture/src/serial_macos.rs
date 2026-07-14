use std::process::Command;

use crate::PostureError;

pub(crate) fn get_serial_numbers_impl() -> Result<Vec<String>, PostureError> {
    if let Some(serial) = command_output("sysctl", &["-n", "hw.serialnumber"]) {
        return Ok(vec![serial]);
    }

    let output = Command::new("ioreg")
        .args(["-c", "IOPlatformExpertDevice", "-d", "1", "-r", "-n"])
        .output()?;
    let serial = parse_ioreg_serial(&String::from_utf8_lossy(&output.stdout));
    serial.map_or_else(
        || {
            Err(PostureError::CollectionFailed(
                "no serial found via ioreg".into(),
            ))
        },
        |serial| Ok(vec![serial]),
    )
}

fn command_output(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn parse_ioreg_serial(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let value = line
            .trim()
            .strip_prefix("\"IOPlatformSerialNumber\" = \"")?
            .strip_suffix('\"')?
            .trim();
        (!value.is_empty()).then(|| value.to_string())
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
