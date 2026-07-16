use std::collections::BTreeMap;
#[cfg(any(test, target_os = "windows"))]
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::path::Path;

#[cfg(any(target_os = "macos", target_os = "windows"))]
use crate::{
    watch::{PollingSubscription, SystemWatchClock, WatchClock},
    PolicyProvider, ProviderSubscription, ProviderValues, WatchOptions,
};
use crate::{PolicyError, PolicyErrorKind, PolicyKey, RawValue, SettingDefinition, ValueType};

#[cfg(any(target_os = "macos", target_os = "windows"))]
const MAX_OUTPUT: usize = 64 * 1024;
#[cfg(any(target_os = "macos", target_os = "windows"))]
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "windows")]
const REGISTRY_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "macos")]
const MACOS_DOMAIN: &str = "io.tailscale.ipn.macsys";
#[cfg(any(test, target_os = "windows"))]
const PRIMARY_REGISTRY_KEY: &str = r"HKLM\SOFTWARE\Policies\Tailscale";
#[cfg(any(test, target_os = "windows"))]
const LEGACY_REGISTRY_KEY: &str = r"HKLM\SOFTWARE\Tailscale IPN";

fn item_error(kind: PolicyErrorKind, key: PolicyKey) -> PolicyError {
    PolicyError::for_key(kind, key)
}

fn managed_string(key: PolicyKey, bytes: &[u8]) -> Result<String, PolicyError> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| item_error(PolicyErrorKind::Parse, key))?
        .trim();
    if value.chars().any(char::is_control) {
        return Err(item_error(PolicyErrorKind::Parse, key));
    }
    Ok(value.to_owned())
}

#[cfg(any(test, target_os = "macos"))]
fn parse_macos_value(definition: SettingDefinition, bytes: &[u8]) -> Result<RawValue, PolicyError> {
    let key = definition.key;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| item_error(PolicyErrorKind::Parse, key))?
        .trim();
    match definition.value_type {
        ValueType::Boolean => match text {
            "1" | "true" | "TRUE" | "YES" => Ok(RawValue::Boolean(true)),
            "0" | "false" | "FALSE" | "NO" => Ok(RawValue::Boolean(false)),
            _ => Err(item_error(PolicyErrorKind::TypeMismatch, key)),
        },
        ValueType::Integer => text
            .parse::<u64>()
            .map(RawValue::Integer)
            .map_err(|_| item_error(PolicyErrorKind::TypeMismatch, key)),
        ValueType::StringList => parse_macos_string_list(key, text).map(RawValue::StringList),
        ValueType::String
        | ValueType::PreferenceOption
        | ValueType::Visibility
        | ValueType::Duration => managed_string(key, bytes).map(RawValue::String),
    }
}

#[cfg(any(test, target_os = "macos"))]
fn parse_macos_string_list(key: PolicyKey, text: &str) -> Result<Vec<String>, PolicyError> {
    let body = text
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .ok_or_else(|| item_error(PolicyErrorKind::TypeMismatch, key))?;
    let mut result = Vec::new();
    for line in body.lines() {
        let item = line.trim().trim_end_matches(',').trim();
        if item.is_empty() {
            continue;
        }
        let item = if item.starts_with('"') && item.ends_with('"') && item.len() >= 2 {
            parse_quoted_macos_string(key, &item[1..item.len() - 1])?
        } else if item.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
        }) {
            item.to_owned()
        } else {
            return Err(item_error(PolicyErrorKind::Parse, key));
        };
        result.push(item);
    }
    Ok(result)
}

#[cfg(any(test, target_os = "macos"))]
fn parse_quoted_macos_string(key: PolicyKey, value: &str) -> Result<String, PolicyError> {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            if character.is_control() {
                return Err(item_error(PolicyErrorKind::Parse, key));
            }
            result.push(character);
            continue;
        }
        match chars.next() {
            Some('\\') => result.push('\\'),
            Some('"') => result.push('"'),
            Some('n') => result.push('\n'),
            Some('r') => result.push('\r'),
            Some('t') => result.push('\t'),
            _ => return Err(item_error(PolicyErrorKind::Parse, key)),
        }
    }
    Ok(result)
}

/// Native preference provider for existing well-known definitions.
///
/// On Windows it reads machine Group Policy/MDM values, preferring the current
/// policy key over the legacy key for each setting. On macOS it reads effective
/// values from the existing macsys preference domain; these values are not
/// claimed to be forced MDM policy. Watching remains explicit and owned.
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Clone)]
pub struct NativePolicyProvider {
    watch_options: Option<WatchOptions>,
    watch_clock: Arc<dyn WatchClock>,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl fmt::Debug for NativePolicyProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativePolicyProvider")
            .field("watch_options", &self.watch_options)
            .finish_non_exhaustive()
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl Default for NativePolicyProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl NativePolicyProvider {
    /// Creates a provider without a background watcher.
    pub fn new() -> Self {
        Self {
            watch_options: None,
            watch_clock: Arc::new(SystemWatchClock),
        }
    }

    /// Enables bounded native preference polling.
    pub fn with_watching(mut self) -> Self {
        self.watch_options = Some(
            WatchOptions::new(Duration::from_secs(30), Duration::from_secs(1))
                .expect("native watch constants are valid"),
        );
        self
    }

    /// Enables native preference polling with validated options.
    pub fn with_watch_options(mut self, options: WatchOptions) -> Self {
        self.watch_options = Some(options);
        self
    }
}

/// Backwards-compatible name for the original posture-only provider.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub type NativePostureProvider = NativePolicyProvider;

#[cfg(target_os = "macos")]
impl PolicyProvider for NativePolicyProvider {
    fn load(&self, definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
        let mut values = BTreeMap::new();
        for definition in definitions {
            let output = crate::command::run_bounded(
                Path::new("/usr/bin/defaults"),
                &["read", MACOS_DOMAIN, definition.key.wire_name()],
                COMMAND_TIMEOUT,
                MAX_OUTPUT,
            )
            .map_err(|_| PolicyError::new(PolicyErrorKind::Provider))?;
            if output.status_code == Some(0) {
                values.insert(
                    definition.key,
                    parse_macos_value(*definition, &output.stdout),
                );
                continue;
            }
            if !macos_value_missing(&output) {
                return Err(PolicyError::new(PolicyErrorKind::Provider));
            }
        }
        Ok(values)
    }

    fn subscribe(
        &self,
        callback: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Option<Box<dyn ProviderSubscription>>, PolicyError> {
        start_native_watcher(self, callback)
    }
}

#[cfg(target_os = "macos")]
fn macos_value_missing(output: &crate::command::BoundedOutput) -> bool {
    output.status_code == Some(1)
        && std::str::from_utf8(&output.stderr).is_ok_and(|stderr| {
            stderr.contains("The domain/default pair of") && stderr.contains("does not exist")
        })
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryValue {
    kind: String,
    value: String,
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Default)]
struct RegistryDump {
    paths: BTreeSet<String>,
    values: BTreeMap<(String, String), RegistryValue>,
}

#[cfg(any(test, target_os = "windows"))]
impl RegistryDump {
    fn parse(output: &str, root: &str) -> Self {
        let mut dump = Self::default();
        let mut path = String::new();
        let output_root = registry_output_root(root);
        let output_root_lower = output_root.to_ascii_lowercase();
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.to_ascii_lowercase().starts_with(&output_root_lower) {
                path = trimmed[output_root.len()..]
                    .trim_start_matches('\\')
                    .to_ascii_lowercase();
                dump.paths.insert(path.clone());
                continue;
            }
            let Some(value) = parse_registry_line(trimmed) else {
                continue;
            };
            dump.values
                .insert((path.clone(), value.0.to_ascii_lowercase()), value.1);
        }
        dump
    }

    fn value(&self, path: &str, name: &str) -> Option<&RegistryValue> {
        self.values
            .get(&(path.to_ascii_lowercase(), name.to_ascii_lowercase()))
    }

    fn string_list_subkey(&self, path: &str) -> Option<Result<Vec<String>, ()>> {
        let path = path.to_ascii_lowercase();
        if !self.paths.contains(&path) {
            return None;
        }
        let mut values = Vec::new();
        for ((entry_path, _), value) in &self.values {
            if entry_path != &path {
                continue;
            }
            if !matches!(value.kind.as_str(), "REG_SZ" | "REG_EXPAND_SZ") {
                return Some(Err(()));
            }
            values.push(value.value.clone());
        }
        Some(Ok(values))
    }
}

#[cfg(any(test, target_os = "windows"))]
fn registry_output_root(root: &str) -> String {
    root.strip_prefix("HKLM\\").map_or_else(
        || root.to_owned(),
        |suffix| format!("HKEY_LOCAL_MACHINE\\{suffix}"),
    )
}

#[cfg(any(test, target_os = "windows"))]
fn parse_registry_line(line: &str) -> Option<(String, RegistryValue)> {
    const KINDS: [&str; 6] = [
        "REG_SZ",
        "REG_EXPAND_SZ",
        "REG_DWORD",
        "REG_QWORD",
        "REG_MULTI_SZ",
        "REG_BINARY",
    ];
    for kind in KINDS {
        let marker = format!(" {kind}");
        let Some(index) = line.find(&marker) else {
            continue;
        };
        let remainder = &line[index + marker.len()..];
        if !remainder.is_empty() && !remainder.starts_with(char::is_whitespace) {
            continue;
        }
        let name = line[..index].trim();
        if name.is_empty() {
            return None;
        }
        return Some((
            name.to_owned(),
            RegistryValue {
                kind: kind.to_owned(),
                value: remainder.trim().to_owned(),
            },
        ));
    }
    None
}

#[cfg(any(test, target_os = "windows"))]
fn raw_from_registry(
    definition: SettingDefinition,
    value: &RegistryValue,
) -> Result<RawValue, PolicyError> {
    let key = definition.key;
    match definition.value_type {
        ValueType::Boolean if matches!(value.kind.as_str(), "REG_DWORD" | "REG_QWORD") => {
            parse_registry_integer(&value.value)
                .map(|value| RawValue::Boolean(value != 0))
                .ok_or_else(|| item_error(PolicyErrorKind::Parse, key))
        }
        ValueType::Integer if matches!(value.kind.as_str(), "REG_DWORD" | "REG_QWORD") => {
            parse_registry_integer(&value.value)
                .map(RawValue::Integer)
                .ok_or_else(|| item_error(PolicyErrorKind::Parse, key))
        }
        ValueType::StringList if value.kind == "REG_MULTI_SZ" => Ok(RawValue::StringList(
            value
                .value
                .split("\\0")
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
        )),
        ValueType::String
        | ValueType::PreferenceOption
        | ValueType::Visibility
        | ValueType::Duration
            if matches!(value.kind.as_str(), "REG_SZ" | "REG_EXPAND_SZ") =>
        {
            managed_string(key, value.value.as_bytes()).map(RawValue::String)
        }
        _ => Err(item_error(PolicyErrorKind::TypeMismatch, key)),
    }
}

#[cfg(any(test, target_os = "windows"))]
fn parse_registry_integer(value: &str) -> Option<u64> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |digits| u64::from_str_radix(digits, 16).ok(),
        )
}

#[cfg(any(test, target_os = "windows"))]
fn registry_value_for(
    definition: SettingDefinition,
    primary: &RegistryDump,
    legacy: &RegistryDump,
) -> Option<Result<RawValue, PolicyError>> {
    let wire_name = definition.key.wire_name();
    let (path, name) = wire_name
        .rsplit_once('/')
        .map_or(("", wire_name), |(path, name)| (path, name));
    let path = path.replace('/', "\\");
    for dump in [primary, legacy] {
        if let Some(value) = dump.value(&path, name) {
            return Some(raw_from_registry(definition, value));
        }
        if definition.value_type == ValueType::StringList {
            let list_path = if path.is_empty() {
                name.to_owned()
            } else {
                format!("{path}\\{name}")
            };
            if let Some(values) = dump.string_list_subkey(&list_path) {
                return Some(
                    values
                        .map(RawValue::StringList)
                        .map_err(|()| item_error(PolicyErrorKind::TypeMismatch, definition.key)),
                );
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
impl PolicyProvider for NativePolicyProvider {
    fn load(&self, definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
        let primary = query_registry_dump(PRIMARY_REGISTRY_KEY)?;
        let legacy = query_registry_dump(LEGACY_REGISTRY_KEY)?;
        Ok(definitions
            .iter()
            .filter_map(|definition| {
                registry_value_for(*definition, &primary, &legacy)
                    .map(|value| (definition.key, value))
            })
            .collect())
    }

    fn subscribe(
        &self,
        callback: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Option<Box<dyn ProviderSubscription>>, PolicyError> {
        start_native_watcher(self, callback)
    }
}

#[cfg(target_os = "windows")]
fn query_registry_dump(root: &str) -> Result<RegistryDump, PolicyError> {
    let output = run_registry_query(root)?;
    if output.status_code == Some(0) {
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|_| PolicyError::new(PolicyErrorKind::Parse))?;
        return Ok(RegistryDump::parse(text, root));
    }
    match probe_registry_key(root)? {
        RegistryKeyState::Missing => Ok(RegistryDump::default()),
        RegistryKeyState::Present => Err(PolicyError::new(PolicyErrorKind::Provider)),
    }
}

#[cfg(target_os = "windows")]
fn run_registry_query(root: &str) -> Result<crate::command::BoundedOutput, PolicyError> {
    crate::command::run_bounded(
        Path::new(r"C:\Windows\System32\reg.exe"),
        &["query", root, "/s", "/reg:64"],
        COMMAND_TIMEOUT,
        MAX_OUTPUT,
    )
    .map_err(|_| PolicyError::new(PolicyErrorKind::Provider))
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryKeyState {
    Present,
    Missing,
}

#[cfg(any(test, target_os = "windows"))]
fn registry_probe_state(status: Option<i32>) -> Result<RegistryKeyState, PolicyError> {
    match status {
        Some(0) => Ok(RegistryKeyState::Present),
        Some(3) => Ok(RegistryKeyState::Missing),
        // The fixed probe maps access denied and all other exceptions to
        // distinct non-missing exit codes. Never infer absence from text.
        _ => Err(PolicyError::new(PolicyErrorKind::Provider)),
    }
}

#[cfg(target_os = "windows")]
fn probe_registry_key(root: &str) -> Result<RegistryKeyState, PolicyError> {
    const SCRIPT: &str = concat!(
        "$p=$args[0] -replace '^HKLM\\\\','';",
        "try {",
        "$b=[Microsoft.Win32.RegistryKey]::OpenBaseKey(",
        "[Microsoft.Win32.RegistryHive]::LocalMachine,",
        "[Microsoft.Win32.RegistryView]::Registry64);",
        "$k=$b.OpenSubKey($p,$false);",
        "if($null -eq $k){exit 3};$k.Dispose();$b.Dispose();exit 0",
        "} catch [System.UnauthorizedAccessException] { exit 5 } ",
        "catch { exit 6 }"
    );
    let output = crate::command::run_bounded(
        Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        &[
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SCRIPT,
            root,
        ],
        REGISTRY_PROBE_TIMEOUT,
        MAX_OUTPUT,
    )
    .map_err(|_| PolicyError::new(PolicyErrorKind::Provider))?;
    registry_probe_state(output.status_code)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn start_native_watcher(
    provider: &NativePolicyProvider,
    callback: Arc<dyn Fn() + Send + Sync>,
) -> Result<Option<Box<dyn ProviderSubscription>>, PolicyError> {
    let Some(options) = provider.watch_options else {
        return Ok(None);
    };
    PollingSubscription::start(
        "syspolicy-native-watch",
        options,
        provider.watch_clock.clone(),
        |_| native_observation(),
        callback,
    )
    .map(Some)
}

#[cfg(target_os = "macos")]
fn native_observation() -> u64 {
    let output = crate::command::run_bounded(
        Path::new("/usr/bin/defaults"),
        &["read", MACOS_DOMAIN],
        COMMAND_TIMEOUT,
        MAX_OUTPUT,
    )
    .map_err(|_| PolicyError::new(PolicyErrorKind::Provider));
    hash_command_result(output)
}

#[cfg(target_os = "windows")]
fn native_observation() -> u64 {
    let primary = run_registry_query(PRIMARY_REGISTRY_KEY);
    let legacy = run_registry_query(LEGACY_REGISTRY_KEY);
    hash_pair(hash_command_result(primary), hash_command_result(legacy))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn hash_command_result(output: Result<crate::command::BoundedOutput, PolicyError>) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    match output {
        Ok(output) => {
            hash = hash_bytes(hash, &output.status_code.unwrap_or(i32::MIN).to_le_bytes());
            hash = hash_bytes(hash, &output.stdout);
            hash_bytes(hash, &output.stderr)
        }
        Err(error) => hash_bytes(hash, &[error.kind as u8]),
    }
}

#[cfg(target_os = "windows")]
fn hash_pair(first: u64, second: u64) -> u64 {
    hash_bytes(
        hash_bytes(0xcbf2_9ce4_8422_2325, &first.to_le_bytes()),
        &second.to_le_bytes(),
    )
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn hash_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_managed_strings_without_disclosing_values() {
        assert_eq!(
            managed_string(PolicyKey::PostureChecking, b"always\n").unwrap(),
            "always"
        );
        assert_eq!(managed_string(PolicyKey::ControlURL, b"\n").unwrap(), "");
        let error = managed_string(PolicyKey::PostureChecking, b"always\0never").unwrap_err();
        assert_eq!(error.kind, PolicyErrorKind::Parse);
        assert!(!error.to_string().contains("always"));
    }

    #[test]
    fn parses_macos_values_for_existing_definition_types() {
        assert_eq!(
            parse_macos_value(PolicyKey::AlwaysOn.definition(), b"1\n"),
            Ok(RawValue::Boolean(true))
        );
        assert_eq!(
            parse_macos_value(
                PolicyKey::AllowedSuggestedExitNodes.definition(),
                b"(\n  \"node-a\",\n  node-b\n)\n"
            ),
            Ok(RawValue::StringList(vec!["node-a".into(), "node-b".into()]))
        );
        assert_eq!(
            parse_macos_value(PolicyKey::PostureChecking.definition(), b"never\n"),
            Ok(RawValue::String("never".into()))
        );
    }

    #[test]
    fn parses_windows_registry_types_paths_and_fallback() {
        let primary_root = r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Tailscale";
        let legacy_root = r"HKEY_LOCAL_MACHINE\SOFTWARE\Tailscale IPN";
        let primary = RegistryDump::parse(
            &format!(
                "{primary_root}\r\n    PostureChecking    REG_SZ    always\r\n    AlwaysOn.Enabled    REG_DWORD    0x1\r\n{primary_root}\\AllowedSuggestedExitNodes\r\n    1    REG_SZ    node-a\r\n    2    REG_SZ    node-b\r\n"
            ),
            PRIMARY_REGISTRY_KEY,
        );
        let legacy = RegistryDump::parse(
            &format!("{legacy_root}\r\n    PostureChecking    REG_SZ    never\r\n"),
            LEGACY_REGISTRY_KEY,
        );
        assert_eq!(
            parse_registry_line("LoginURL    REG_SZ"),
            Some((
                "LoginURL".into(),
                RegistryValue {
                    kind: "REG_SZ".into(),
                    value: String::new(),
                }
            ))
        );
        assert_eq!(
            registry_value_for(PolicyKey::PostureChecking.definition(), &primary, &legacy),
            Some(Ok(RawValue::String("always".into())))
        );
        assert_eq!(
            registry_value_for(PolicyKey::AlwaysOn.definition(), &primary, &legacy),
            Some(Ok(RawValue::Boolean(true)))
        );
        assert_eq!(
            registry_value_for(
                PolicyKey::AllowedSuggestedExitNodes.definition(),
                &primary,
                &legacy
            ),
            Some(Ok(RawValue::StringList(vec![
                "node-a".into(),
                "node-b".into()
            ])))
        );

        let empty_primary = RegistryDump::parse(
            &format!("{primary_root}\\AllowedSuggestedExitNodes\r\n"),
            PRIMARY_REGISTRY_KEY,
        );
        assert_eq!(
            registry_value_for(
                PolicyKey::AllowedSuggestedExitNodes.definition(),
                &empty_primary,
                &legacy
            ),
            Some(Ok(RawValue::StringList(Vec::new())))
        );
    }

    #[test]
    fn registry_missing_probe_is_locale_independent_and_distinguishes_access() {
        assert_eq!(registry_probe_state(Some(0)), Ok(RegistryKeyState::Present));
        assert_eq!(registry_probe_state(Some(3)), Ok(RegistryKeyState::Missing));
        assert_eq!(
            registry_probe_state(Some(5)).unwrap_err().kind,
            PolicyErrorKind::Provider
        );
        assert_eq!(
            registry_probe_state(Some(6)).unwrap_err().kind,
            PolicyErrorKind::Provider
        );
    }

    #[test]
    fn native_type_mismatches_are_item_errors() {
        let error = raw_from_registry(
            PolicyKey::AlwaysOn.definition(),
            &RegistryValue {
                kind: "REG_SZ".into(),
                value: "true".into(),
            },
        )
        .unwrap_err();
        assert_eq!(error.kind, PolicyErrorKind::TypeMismatch);
        assert_eq!(error.key, Some(PolicyKey::AlwaysOn));
    }
}
