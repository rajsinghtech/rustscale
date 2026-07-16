use std::path::PathBuf;

/// Normalize a Taildrive share name using the upstream-compatible character
/// set: ASCII letters/digits, `_`, spaces, and parentheses.
pub fn normalize_share_name(name: &str) -> Result<String, PathError> {
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty() || name.len() > 255 {
        return Err(PathError::InvalidShareName);
    }
    if name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | ' ' | '(' | ')'))
    {
        Ok(name)
    } else {
        Err(PathError::InvalidShareName)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ParsedPath {
    pub(crate) share: Option<String>,
    pub(crate) relative: PathBuf,
    pub(crate) components: Vec<String>,
}

pub(crate) fn parse_request_path(path: &str, max_bytes: usize) -> Result<ParsedPath, PathError> {
    if path.len() > max_bytes {
        return Err(PathError::TooLong);
    }
    if !path.starts_with('/') || path.contains('?') || path.contains('#') {
        return Err(PathError::NotOriginForm);
    }
    if path == "/" {
        return Ok(ParsedPath {
            share: None,
            relative: PathBuf::new(),
            components: Vec::new(),
        });
    }
    if path.contains("//") {
        return Err(PathError::EmptyComponent);
    }

    let encoded = path
        .strip_prefix('/')
        .expect("origin-form path has a leading slash")
        .trim_end_matches('/');
    let mut components = Vec::new();
    for component in encoded.split('/') {
        let decoded = percent_decode_component(component)?;
        validate_component(&decoded)?;
        components.push(decoded);
    }
    let share = normalize_share_name(&components[0])?;
    // Share names are canonical in protocol paths. Reject aliases instead of
    // allowing two URLs to identify the same authority boundary.
    if components[0] != share {
        return Err(PathError::NonCanonicalShare);
    }
    let relative = components.iter().skip(1).collect::<PathBuf>();
    Ok(ParsedPath {
        share: Some(share),
        relative,
        components,
    })
}

fn percent_decode_component(encoded: &str) -> Result<String, PathError> {
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(PathError::BadPercentEncoding);
                }
                let high = hex(bytes[i + 1]).ok_or(PathError::BadPercentEncoding)?;
                let low = hex(bytes[i + 2]).ok_or(PathError::BadPercentEncoding)?;
                decoded.push((high << 4) | low);
                i += 3;
            }
            byte => {
                decoded.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| PathError::InvalidUtf8)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn validate_component(component: &str) -> Result<(), PathError> {
    if component.is_empty() {
        return Err(PathError::EmptyComponent);
    }
    if component == "." || component == ".." {
        return Err(PathError::Traversal);
    }
    if component.contains(['/', '\\']) {
        return Err(PathError::SeparatorInComponent);
    }
    if component
        .chars()
        .any(|c| c == '\0' || c.is_control() || c == ':')
    {
        return Err(PathError::UnsafeComponent);
    }
    if component.ends_with([' ', '.']) || is_windows_device_name(component) {
        return Err(PathError::UnsafeComponent);
    }
    Ok(())
}

fn is_windows_device_name(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

/// Percent-encode one WebDAV path component without permitting separators.
pub fn encode_path_component(component: &str) -> String {
    let mut out = String::with_capacity(component.len());
    for byte in component.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(*byte));
        } else {
            use std::fmt::Write;
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

pub(crate) fn href_for_components(components: &[String], directory: bool) -> String {
    let mut href = String::from("/");
    href.push_str(
        &components
            .iter()
            .map(|part| encode_path_component(part))
            .collect::<Vec<_>>()
            .join("/"),
    );
    if directory && !href.ends_with('/') {
        href.push('/');
    }
    href
}

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("invalid Taildrive share name")]
    InvalidShareName,
    #[error("request path exceeds the configured limit")]
    TooLong,
    #[error("request target must be an origin-form path without query or fragment")]
    NotOriginForm,
    #[error("path contains an empty component")]
    EmptyComponent,
    #[error("invalid percent encoding")]
    BadPercentEncoding,
    #[error("percent-decoded path is not UTF-8")]
    InvalidUtf8,
    #[error("path traversal is forbidden")]
    Traversal,
    #[error("encoded path separator is forbidden")]
    SeparatorInComponent,
    #[error("path component is unsafe or not portable")]
    UnsafeComponent,
    #[error("share name in URL is not canonical")]
    NonCanonicalShare,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_strict_and_portable() {
        let parsed = parse_request_path("/docs/a%20file.txt", 4096).unwrap();
        assert_eq!(parsed.share.as_deref(), Some("docs"));
        assert_eq!(parsed.relative, PathBuf::from("a file.txt"));
        for path in [
            "/docs/../secret",
            "/docs/%2e%2e/secret",
            "/docs/%2Fetc",
            "/docs/a%5Cb",
            "/docs//file",
            "/Docs/file",
            "/docs/CON",
            "/docs/file.",
            "http://peer/docs/file",
        ] {
            assert!(parse_request_path(path, 4096).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn share_names_match_upstream_rules() {
        assert_eq!(
            normalize_share_name(" My Docs (2) ").unwrap(),
            "my docs (2)"
        );
        for invalid in ["", "../x", "a-b", "é"] {
            assert!(normalize_share_name(invalid).is_err());
        }
    }
}
