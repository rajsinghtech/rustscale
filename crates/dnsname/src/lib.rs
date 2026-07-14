//! DNS name string utilities — port of Go's `tailscale.com/util/dnsname`.
//!
//! Provides the [`Fqdn`] type (always-dot-terminated, validated DNS names),
//! along with label/hostname sanitization, suffix operations, and the
//! canonical [`to_fqdn`] constructor. Faithfully ports the semantics of the
//! Go package: [`to_fqdn`] does NOT lowercase (case preservation matches Go);
//! callers that need case-insensitive comparison must lowercase themselves.

#![forbid(unsafe_code)]

use std::fmt;

/// Maximum length of a DNS label (RFC 1035).
const MAX_LABEL_LENGTH: usize = 63;

/// Maximum length of a DNS name including the trailing dot.
const MAX_NAME_LENGTH: usize = 254;

/// A fully-qualified DNS name or name suffix.
///
/// The inner `String` always ends with `'.'` (or is exactly `"."` for the
/// root). Construct via [`to_fqdn`] to get validation. Mirrors Go's
/// `dnsname.FQDN` (a `string` newtype).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fqdn {
    inner: String,
}

impl Fqdn {
    /// Returns the FQDN as a string with a trailing dot.
    pub fn with_trailing_dot(&self) -> &str {
        &self.inner
    }

    /// Returns the FQDN as a string with the trailing dot removed.
    ///
    /// For the root `"."` this returns `""`.
    pub fn without_trailing_dot(&self) -> &str {
        &self.inner[..self.inner.len() - 1]
    }

    /// Number of labels in this FQDN. The root `"."` has 0 labels.
    pub fn num_labels(&self) -> usize {
        if self.inner == "." {
            return 0;
        }
        self.inner.matches('.').count()
    }

    /// Returns `true` if `self` is an ancestor of (or equal to) `other`.
    ///
    /// A suffix FQDN like `"tailscale.com."` contains `"www.tailscale.com."`.
    /// The root `"."` contains every name.
    pub fn contains(&self, other: &Fqdn) -> bool {
        if self == other {
            return true;
        }
        let cmp = self.with_trailing_dot();
        if cmp == "." {
            // Root contains everything.
            return true;
        }
        // Prepend a dot so we match a full label boundary, not a substring.
        let needle = format!(".{cmp}");
        other.with_trailing_dot().ends_with(&needle)
    }

    /// Returns the parent domain by stripping the first label.
    ///
    /// For `"foo.bar.baz."` returns `"bar.baz."`. Returns an empty `Fqdn`
    /// (inner `""`) for the root or a single-label name like `"com."`.
    pub fn parent(&self) -> Fqdn {
        let s = self.with_trailing_dot();
        match s.split_once('.') {
            Some((_first, rest)) if !rest.is_empty() => Fqdn {
                inner: rest.to_string(),
            },
            _ => Fqdn::default(),
        }
    }

    /// Construct an `Fqdn` from an already-canonical string (with trailing
    /// dot). Does not validate.
    fn from_canonical(s: String) -> Self {
        Fqdn { inner: s }
    }
}

impl fmt::Display for Fqdn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}

impl AsRef<str> for Fqdn {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl From<Fqdn> for String {
    fn from(f: Fqdn) -> String {
        f.inner
    }
}

/// Errors returned by [`to_fqdn`], [`valid_label`], and [`valid_hostname`].
///
/// The `Display` output matches the Go error strings closely enough that the
/// Go test assertions (substring / suffix checks) port verbatim.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FqdnError {
    /// `"<name>" is too long to be a DNS name` or
    /// `"<label>" is too long, max length is 63 bytes`.
    #[error("{0}")]
    TooLong(String),
    /// `"<label>" is not a valid DNS label` (with optional reason) or
    /// `empty DNS label`.
    #[error("{0}")]
    InvalidLabel(String),
}

/// Parse `s` into an [`Fqdn`], normalizing the trailing dot and validating
/// label/length constraints.
///
/// Mirrors Go's `dnsname.ToFQDN`. The input may or may not have a trailing
/// dot, and may have a leading dot (which is stripped). The returned `Fqdn`
/// always has exactly one trailing dot (or is `"."` for root/empty input).
///
/// Case is preserved (matching Go) — `to_fqdn("Foo.com")` yields
/// `Fqdn("Foo.com.")`.
pub fn to_fqdn(s: &str) -> Result<Fqdn, FqdnError> {
    if s.is_empty() || s == "." {
        return Ok(Fqdn::from_canonical(String::from(".")));
    }

    // Strip a single leading dot.
    let s = s.strip_prefix('.').unwrap_or(s);
    let raw_input = s;

    // Compute the total length including the trailing dot that we will add
    // if one is not already present.
    let total_len = if s.ends_with('.') {
        s.len()
    } else {
        s.len() + 1
    };
    if total_len > MAX_NAME_LENGTH {
        return Err(FqdnError::TooLong(format!(
            "{s:?} is too long to be a DNS name"
        )));
    }

    // Validate each label (non-empty, ≤63 octets) in the dot-terminated form
    // with the trailing dot removed. Only labels followed by a dot are
    // checked here — the trailing label (no dot after it) is NOT validated
    // by Go's ToFQDN; ValidHostname handles it via ValidLabel.
    let inner = s.strip_suffix('.').unwrap_or(s);
    let mut start = 0;
    for (i, _) in inner.match_indices('.') {
        let label = &inner[start..i];
        if label.is_empty() || label.len() > MAX_LABEL_LENGTH {
            return Err(FqdnError::InvalidLabel(format!(
                "{label:?} is not a valid DNS label"
            )));
        }
        start = i + 1;
    }

    let canonical = if raw_input.ends_with('.') {
        raw_input.to_string()
    } else {
        format!("{raw_input}.")
    };
    Ok(Fqdn::from_canonical(canonical))
}

// ---------------------------------------------------------------------------
// Label / hostname helpers
// ---------------------------------------------------------------------------

/// Reports whether `label` is a valid DNS label per RFC 1123 hostname rules.
///
/// A label must be 1–63 octets, start and end with a letter or digit, and
/// contain only letters, digits, or hyphens in between. Mirrors Go's
/// `dnsname.ValidLabel`.
pub fn valid_label(label: &str) -> Result<(), FqdnError> {
    if label.is_empty() {
        return Err(FqdnError::InvalidLabel(String::from("empty DNS label")));
    }
    if label.len() > MAX_LABEL_LENGTH {
        return Err(FqdnError::TooLong(format!(
            "{label:?} is too long, max length is {MAX_LABEL_LENGTH} bytes"
        )));
    }
    let bytes = label.as_bytes();
    if !is_alphanum(bytes[0]) {
        return Err(FqdnError::InvalidLabel(format!(
            "{label:?} is not a valid DNS label: must start with a letter or number"
        )));
    }
    if !is_alphanum(bytes[bytes.len() - 1]) {
        return Err(FqdnError::InvalidLabel(format!(
            "{label:?} is not a valid DNS label: must end with a letter or number"
        )));
    }
    if bytes.len() < 2 {
        return Ok(());
    }
    for &c in &bytes[1..bytes.len() - 1] {
        if !is_dns_char(c) {
            return Err(FqdnError::InvalidLabel(format!(
                "{label:?} is not a valid DNS label: contains invalid character {:?}",
                c as char
            )));
        }
    }
    Ok(())
}

/// Sanitize `label` into a valid RFC 1035 DNS label.
///
/// Trims leading/trailing non-alphanumeric characters, converts internal
/// separators (` `, `.`, `@`, `_`) to hyphens, lowercases ASCII letters, and
/// truncates to 63 octets. Mirrors Go's `dnsname.SanitizeLabel`.
pub fn sanitize_label(label: &str) -> String {
    let bytes = label.as_bytes();
    let mut end = bytes.len().min(MAX_LABEL_LENGTH);
    let mut start = 0;

    while start < end && !is_alphanum(bytes[start]) {
        start += 1;
    }
    while start < end && !is_alphanum(bytes[end - 1]) {
        end -= 1;
    }

    let mut out = String::with_capacity(end - start);
    for (i, &c) in bytes[start..end].iter().enumerate() {
        let abs = i + start;
        let boundary = abs == start || abs == end - 1;
        if !boundary && is_separator(c) {
            out.push('-');
        } else if is_dns_char(c) {
            out.push(to_lower(c) as char);
        }
    }
    out
}

/// Whether `name` ends with the component(s) in `suffix`, ignoring any
/// trailing or leading dots. If `suffix` is empty, returns `false`.
///
/// Mirrors Go's `dnsname.HasSuffix`.
pub fn has_suffix(name: &str, suffix: &str) -> bool {
    let name = name.trim_end_matches('.');
    let suffix = suffix.trim_end_matches('.');
    let suffix = suffix.trim_start_matches('.');
    let name_base = name.strip_suffix(suffix).unwrap_or(name);
    name_base.len() < name.len() && name_base.ends_with('.')
}

/// Trim any trailing dots from `name` and remove `suffix` if present.
/// The result never has a trailing dot.
///
/// Mirrors Go's `dnsname.TrimSuffix`.
pub fn trim_suffix(name: &str, suffix: &str) -> String {
    if has_suffix(name, suffix) {
        let name = name.trim_end_matches('.');
        let suffix = suffix.trim_matches('.');
        let name = name.strip_suffix(suffix).unwrap_or(name);
        return name.trim_end_matches('.').to_string();
    }
    name.trim_end_matches('.').to_string()
}

/// Remove common local-domain suffixes (`.local`, `.localdomain`, `.lan`)
/// from `hostname`.
///
/// Mirrors Go's `dnsname.TrimCommonSuffixes`.
pub fn trim_common_suffixes(hostname: &str) -> String {
    let hostname = hostname.strip_suffix(".local").unwrap_or(hostname);
    let hostname = hostname.strip_suffix(".localdomain").unwrap_or(hostname);
    let hostname = hostname.strip_suffix(".lan").unwrap_or(hostname);
    hostname.to_string()
}

/// Sanitize `hostname` into a valid DNS label: first strips common local
/// suffixes, then applies [`sanitize_label`].
///
/// Mirrors Go's `dnsname.SanitizeHostname`.
pub fn sanitize_hostname(hostname: &str) -> String {
    let hostname = trim_common_suffixes(hostname);
    sanitize_label(&hostname)
}

/// Number of DNS labels in `hostname`. Empty string or `"."` returns 0.
///
/// Mirrors Go's `dnsname.NumLabels`.
pub fn num_labels(hostname: &str) -> usize {
    if hostname.is_empty() || hostname == "." {
        return 0;
    }
    hostname.matches('.').count()
}

/// Returns the first DNS label of `hostname` (everything before the first
/// dot, or the whole string if no dot).
///
/// Mirrors Go's `dnsname.FirstLabel`.
pub fn first_label(hostname: &str) -> &str {
    hostname.split('.').next().unwrap_or("")
}

/// Checks if `hostname` is a valid hostname.
///
/// Parses with [`to_fqdn`] and validates every label with [`valid_label`].
/// Mirrors Go's `dnsname.ValidHostname`.
pub fn valid_hostname(hostname: &str) -> Result<(), FqdnError> {
    let fqdn = to_fqdn(hostname)?;
    for label in fqdn.without_trailing_dot().split('.') {
        valid_label(label)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// byte classifiers (match Go's islower/isupper/isalpha/isalphanum/isdnschar)
// ---------------------------------------------------------------------------

fn is_lower(c: u8) -> bool {
    c.is_ascii_lowercase()
}

fn is_upper(c: u8) -> bool {
    c.is_ascii_uppercase()
}

fn is_alpha(c: u8) -> bool {
    is_lower(c) || is_upper(c)
}

fn is_alphanum(c: u8) -> bool {
    is_alpha(c) || c.is_ascii_digit()
}

fn is_dns_char(c: u8) -> bool {
    is_alphanum(c) || c == b'-'
}

fn is_separator(c: u8) -> bool {
    matches!(c, b' ' | b'.' | b'@' | b'_')
}

fn to_lower(c: u8) -> u8 {
    if is_upper(c) {
        c + b'a' - b'A'
    } else {
        c
    }
}

#[cfg(test)]
mod tests;
