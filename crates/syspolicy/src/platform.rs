#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::collections::BTreeMap;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::time::Duration;

#[cfg(any(target_os = "macos", target_os = "windows"))]
use crate::SettingDefinition;
use crate::{PolicyError, PolicyErrorKind, PolicyKey};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use crate::{PolicyProvider, ProviderValues, RawValue};

#[cfg(any(target_os = "macos", target_os = "windows"))]
const MAX_OUTPUT: usize = 64 * 1024;
#[cfg(any(target_os = "macos", target_os = "windows"))]
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn requested_posture(definitions: &[SettingDefinition]) -> bool {
    definitions
        .iter()
        .any(|definition| definition.key == PolicyKey::PostureChecking)
}

fn managed_string(bytes: &[u8]) -> Result<String, PolicyError> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| PolicyError::for_key(PolicyErrorKind::Parse, PolicyKey::PostureChecking))?
        .trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(PolicyError::for_key(
            PolicyErrorKind::Parse,
            PolicyKey::PostureChecking,
        ));
    }
    Ok(value.to_owned())
}

/// Native managed-policy provider for the posture preference.
///
/// It intentionally implements the current [`PolicyProvider`] contract rather
/// than the deleted single-store API. Provider failures are surfaced so the
/// policy engine and posture caller can fail closed.
#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
pub struct NativePostureProvider;

#[cfg(target_os = "macos")]
impl NativePostureProvider {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl PolicyProvider for NativePostureProvider {
    fn load(&self, definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
        if !requested_posture(definitions) {
            return Ok(BTreeMap::new());
        }
        let output = crate::command::run_bounded(
            Path::new("/usr/bin/defaults"),
            &["read", "io.tailscale.ipn.macsys", "PostureChecking"],
            COMMAND_TIMEOUT,
            MAX_OUTPUT,
        )
        .map_err(|_| PolicyError::new(PolicyErrorKind::Provider))?;
        if output.status_code == Some(0) {
            return Ok(BTreeMap::from([(
                PolicyKey::PostureChecking,
                managed_string(&output.stdout).map(RawValue::String),
            )]));
        }
        let missing = output.status_code == Some(1)
            && std::str::from_utf8(&output.stderr).is_ok_and(|stderr| {
                stderr.contains("The domain/default pair of") && stderr.contains("does not exist")
            });
        if missing {
            Ok(BTreeMap::new())
        } else {
            Err(PolicyError::new(PolicyErrorKind::Provider))
        }
    }
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryValue {
    kind: String,
    value: String,
}

#[cfg(any(test, target_os = "windows"))]
fn parse_registry_query(output: &str, value_name: &str) -> Option<RegistryValue> {
    output.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let name = fields.next()?;
        let kind = fields.next()?;
        let value = fields.collect::<Vec<_>>().join(" ");
        (name.eq_ignore_ascii_case(value_name) && !value.is_empty()).then(|| RegistryValue {
            kind: kind.to_owned(),
            value,
        })
    })
}

/// Native managed-policy provider for the posture preference.
#[cfg(target_os = "windows")]
#[derive(Debug, Default)]
pub struct NativePostureProvider;

#[cfg(target_os = "windows")]
impl NativePostureProvider {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "windows")]
impl PolicyProvider for NativePostureProvider {
    fn load(&self, definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
        if !requested_posture(definitions) {
            return Ok(BTreeMap::new());
        }
        const PRIMARY: &str = r"HKLM\SOFTWARE\Policies\Tailscale";
        const LEGACY: &str = r"HKLM\SOFTWARE\Tailscale IPN";
        let executable = Path::new(r"C:\Windows\System32\reg.exe");

        for registry_key in [PRIMARY, LEGACY] {
            let output = crate::command::run_bounded(
                executable,
                &[
                    "query",
                    registry_key,
                    "/v",
                    PolicyKey::PostureChecking.wire_name(),
                    "/reg:64",
                ],
                COMMAND_TIMEOUT,
                MAX_OUTPUT,
            )
            .map_err(|_| PolicyError::new(PolicyErrorKind::Provider))?;
            if output.status_code == Some(0) {
                let stdout = std::str::from_utf8(&output.stdout).map_err(|_| {
                    PolicyError::for_key(PolicyErrorKind::Parse, PolicyKey::PostureChecking)
                })?;
                let value = parse_registry_query(stdout, PolicyKey::PostureChecking.wire_name())
                    .ok_or_else(|| {
                        PolicyError::for_key(PolicyErrorKind::Parse, PolicyKey::PostureChecking)
                    })?;
                if !value.kind.eq_ignore_ascii_case("REG_SZ") {
                    return Ok(BTreeMap::from([(
                        PolicyKey::PostureChecking,
                        Err(PolicyError::for_key(
                            PolicyErrorKind::TypeMismatch,
                            PolicyKey::PostureChecking,
                        )),
                    )]));
                }
                return Ok(BTreeMap::from([(
                    PolicyKey::PostureChecking,
                    managed_string(value.value.as_bytes()).map(RawValue::String),
                )]));
            }
            let missing = output.status_code == Some(1)
                && [output.stdout.as_slice(), output.stderr.as_slice()]
                    .into_iter()
                    .filter_map(|bytes| std::str::from_utf8(bytes).ok())
                    .any(|text| {
                        let text = text.to_ascii_lowercase();
                        text.contains("unable to find") || text.contains("cannot find")
                    });
            if !missing {
                return Err(PolicyError::new(PolicyErrorKind::Provider));
            }
        }
        Ok(BTreeMap::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_managed_strings_without_disclosing_values() {
        assert_eq!(managed_string(b"always\n").unwrap(), "always");
        assert_eq!(managed_string(b"never\n").unwrap(), "never");
        assert_eq!(managed_string(b"user-decides\n").unwrap(), "user-decides");
        let error = managed_string(b"always\0never").unwrap_err();
        assert_eq!(error.kind, PolicyErrorKind::Parse);
        assert!(!error.to_string().contains("always"));
    }

    #[test]
    fn parses_only_the_requested_registry_value() {
        let output = concat!(
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Tailscale\r\n",
            "    PostureChecking    REG_SZ    always\r\n",
        );
        assert_eq!(
            parse_registry_query(output, "PostureChecking"),
            Some(RegistryValue {
                kind: "REG_SZ".into(),
                value: "always".into(),
            })
        );
        assert_eq!(parse_registry_query(output, "Other"), None);
    }
}
