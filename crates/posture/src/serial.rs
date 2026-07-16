use std::collections::HashSet;

use crate::PostureError;

/// Collect serial numbers exposed by the current platform.
pub fn get_serial_numbers() -> Result<Vec<String>, PostureError> {
    get_serial_numbers_impl()
}

#[cfg(target_os = "linux")]
use crate::serial_linux::get_serial_numbers_impl;
#[cfg(target_os = "macos")]
use crate::serial_macos::get_serial_numbers_impl;
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
use crate::serial_stub::get_serial_numbers_impl;
#[cfg(target_os = "windows")]
use crate::serial_windows::get_serial_numbers_impl;

/// Whether a DMI serial is an empty or known placeholder value.
pub fn is_sentinel_serial(serial: &str) -> bool {
    let serial = serial.trim();
    serial.is_empty()
        || [
            "to be filled by o.e.m.",
            "default string",
            "invalid",
            "n/a",
            "none",
            "not available",
            "not specified",
            "system serial number",
            "unknown",
        ]
        .iter()
        .any(|sentinel| serial.eq_ignore_ascii_case(sentinel))
}

/// Remove duplicate serials while preserving their original order.
pub fn dedup_serials(serials: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::with_capacity(serials.len());
    serials
        .into_iter()
        .filter(|serial| seen.insert(serial.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_sentinel_values() {
        assert!(is_sentinel_serial("To Be Filled By O.E.M."));
        assert!(is_sentinel_serial("Not Specified"));
        assert!(is_sentinel_serial("none"));
        assert!(is_sentinel_serial("System Serial Number"));
        assert!(is_sentinel_serial("Default string"));
        assert!(is_sentinel_serial("unknown"));
        assert!(is_sentinel_serial("N/A"));
        assert!(is_sentinel_serial("  "));
        assert!(!is_sentinel_serial("ABC123456789"));
    }

    #[test]
    fn deduplicates_serials() {
        let serials = vec!["ABC123".into(), "DEF456".into(), "ABC123".into()];
        assert_eq!(dedup_serials(serials), vec!["ABC123", "DEF456"]);
    }
}
