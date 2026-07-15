use std::{str::FromStr, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{PolicyError, PolicyErrorKind, PolicyKey, ValueType};

/// A policy that can force a boolean preference or leave it to the user.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PreferenceOption {
    /// Keep the user's current choice.
    #[default]
    UserDecides,
    /// Force the preference off.
    Never,
    /// Force the preference on.
    Always,
}

impl PreferenceOption {
    /// Applies this policy to a user preference.
    pub const fn should_enable(self, user_choice: bool) -> bool {
        match self {
            Self::UserDecides => user_choice,
            Self::Never => false,
            Self::Always => true,
        }
    }

    /// Reports whether the corresponding choice should remain user-editable.
    pub const fn show_choice(self) -> bool {
        matches!(self, Self::UserDecides)
    }
}

impl FromStr for PreferenceOption {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "user-decides" => Ok(Self::UserDecides),
            "never" => Ok(Self::Never),
            "always" => Ok(Self::Always),
            _ => Err(()),
        }
    }
}

/// A policy controlling whether a user-interface component is visible.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Visibility {
    /// Show the component.
    #[default]
    Show,
    /// Hide the component.
    Hide,
}

impl Visibility {
    /// Reports whether the component should be shown.
    pub const fn show(self) -> bool {
        matches!(self, Self::Show)
    }
}

impl FromStr for Visibility {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "show" => Ok(Self::Show),
            "hide" => Ok(Self::Hide),
            _ => Err(()),
        }
    }
}

/// A raw value returned by a provider before definition-specific conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawValue {
    /// A boolean.
    Boolean(bool),
    /// An unsigned integer.
    Integer(u64),
    /// A string.
    String(String),
    /// A string list.
    StringList(Vec<String>),
}

/// A converted effective policy value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "Type", content = "Value")]
pub enum PolicyValue {
    /// A boolean.
    Boolean(bool),
    /// An unsigned integer.
    Integer(u64),
    /// A string.
    String(String),
    /// A string list.
    StringList(Vec<String>),
    /// A forced or user-controlled preference.
    PreferenceOption(PreferenceOption),
    /// User-interface visibility.
    Visibility(Visibility),
    /// A non-negative duration.
    Duration(Duration),
}

impl PolicyValue {
    pub(crate) fn convert(
        key: PolicyKey,
        expected: ValueType,
        raw: RawValue,
    ) -> Result<Self, PolicyError> {
        match (expected, raw) {
            (ValueType::Boolean, RawValue::Boolean(value)) => Ok(Self::Boolean(value)),
            (ValueType::Integer, RawValue::Integer(value)) => Ok(Self::Integer(value)),
            (ValueType::String, RawValue::String(value)) => Ok(Self::String(value)),
            (ValueType::StringList, RawValue::StringList(value)) => Ok(Self::StringList(value)),
            (ValueType::PreferenceOption, RawValue::String(value)) => value
                .parse()
                .map(Self::PreferenceOption)
                .map_err(|()| PolicyError::for_key(PolicyErrorKind::Parse, key)),
            (ValueType::Visibility, RawValue::String(value)) => value
                .parse()
                .map(Self::Visibility)
                .map_err(|()| PolicyError::for_key(PolicyErrorKind::Parse, key)),
            (ValueType::Duration, RawValue::String(value)) => parse_go_duration(&value)
                .map(Self::Duration)
                .map_err(|_| PolicyError::for_key(PolicyErrorKind::Parse, key)),
            _ => Err(PolicyError::for_key(PolicyErrorKind::TypeMismatch, key)),
        }
    }
}

/// Error returned when a policy duration is malformed, negative, or too large.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid policy duration")]
pub struct DurationParseError;

/// Parses the non-negative subset of Go's `time.ParseDuration` syntax.
///
/// Supported units are `ns`, `us`, `µs`, `μs`, `ms`, `s`, `m`, and `h`, and
/// multiple decimal components may be concatenated. Negative durations are
/// rejected because effective policy durations use [`Duration`].
pub fn parse_go_duration(input: &str) -> Result<Duration, DurationParseError> {
    if input == "0" || input == "+0" {
        return Ok(Duration::ZERO);
    }
    let input = input.strip_prefix('+').unwrap_or(input);
    if input.is_empty() || input.starts_with('-') {
        return Err(DurationParseError);
    }

    let mut rest = input;
    let mut total_nanos = 0_u128;
    while !rest.is_empty() {
        let integer_len = rest.bytes().take_while(u8::is_ascii_digit).count();
        let integer = &rest[..integer_len];
        rest = &rest[integer_len..];

        let mut fraction = "";
        if let Some(after_dot) = rest.strip_prefix('.') {
            let fraction_len = after_dot.bytes().take_while(u8::is_ascii_digit).count();
            if fraction_len == 0 {
                return Err(DurationParseError);
            }
            fraction = &after_dot[..fraction_len];
            rest = &after_dot[fraction_len..];
        }
        if integer.is_empty() && fraction.is_empty() {
            return Err(DurationParseError);
        }

        let (unit_nanos, after_unit) = duration_unit(rest).ok_or(DurationParseError)?;
        rest = after_unit;
        let integer_value = if integer.is_empty() {
            0
        } else {
            integer.parse::<u128>().map_err(|_| DurationParseError)?
        };
        let mut component = integer_value
            .checked_mul(unit_nanos)
            .ok_or(DurationParseError)?;
        if !fraction.is_empty() {
            let fraction_value = fraction.parse::<u128>().map_err(|_| DurationParseError)?;
            let denominator = 10_u128
                .checked_pow(fraction.len().try_into().map_err(|_| DurationParseError)?)
                .ok_or(DurationParseError)?;
            component = component
                .checked_add(
                    fraction_value
                        .checked_mul(unit_nanos)
                        .ok_or(DurationParseError)?
                        / denominator,
                )
                .ok_or(DurationParseError)?;
        }
        total_nanos = total_nanos
            .checked_add(component)
            .ok_or(DurationParseError)?;
    }

    let nanos = u64::try_from(total_nanos).map_err(|_| DurationParseError)?;
    Ok(Duration::from_nanos(nanos))
}

fn duration_unit(input: &str) -> Option<(u128, &str)> {
    const UNITS: [(&str, u128); 8] = [
        ("ms", 1_000_000),
        ("us", 1_000),
        ("µs", 1_000),
        ("μs", 1_000),
        ("ns", 1),
        ("s", 1_000_000_000),
        ("m", 60 * 1_000_000_000),
        ("h", 60 * 60 * 1_000_000_000),
    ];
    UNITS
        .into_iter()
        .find_map(|(unit, nanos)| input.strip_prefix(unit).map(|rest| (nanos, rest)))
}
