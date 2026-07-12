//! macOS file quarantine extended attribute support.
//!
//! Sets the `com.apple.quarantine` extended attribute on downloaded files
//! so that macOS Gatekeeper/LSQuarantine treats them as downloaded from
//! the internet. On non-macOS platforms this is a no-op.
//!
//! Port of `tailscale.com/util/quarantine`.

use std::io;
use std::path::Path;

/// Set the `com.apple.quarantine` extended attribute on `path`, marking the
/// file as a downloaded file per macOS quarantine rules.
///
/// The attribute value follows the format:
/// `<quarantine-type>;<unix-timestamp-hex>;<agent-name>;<UUID>`
///
/// On non-macOS platforms this is a no-op and returns `Ok(())`.
pub fn set_on_file(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        set_on_file_darwin(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Ok(())
    }
}

/// Build a v4 UUID from 16 random bytes without external dependencies.
/// Format: xxxxxxxx-xxxx-4xxx-axxx-xxxxxxxxxxxx (lowercase hex).
#[cfg(any(target_os = "macos", test))]
fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut bytes);
    // Set version 4 (RFC 4122): top 4 bits of byte 6 = 0100
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // Set variant: top 2 bits of byte 8 = 10
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

#[cfg(target_os = "macos")]
fn set_on_file_darwin(path: &Path) -> io::Result<()> {
    let path_cstr = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null byte"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let uuid = uuid_v4();

    // kLSQuarantineTypeOtherDownload = "0001"
    // Format: <type>;<unix-timestamp-hex>;<agent>;<UUID>
    let attr_data = format!("0001;{now:x};Tailscale;{uuid}");

    let attr_name = std::ffi::CString::new("com.apple.quarantine")
        .expect("com.apple.quarantine is not null-terminated");

    let rv = unsafe {
        libc::setxattr(
            path_cstr.as_ptr(),
            attr_name.as_ptr(),
            attr_data.as_ptr().cast::<libc::c_void>(),
            attr_data.len(),
            0,
            0,
        )
    };
    if rv != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use std::io::Write;

    #[cfg(target_os = "macos")]
    #[test]
    fn test_set_on_file_creates_quarantine_xattr() {
        let dir = std::env::temp_dir();
        let mut tmppath = dir.clone();
        tmppath.push("rustscale_quarantine_test.txt");
        let mut f = std::fs::File::create(&tmppath).unwrap();
        write!(f, "hello").unwrap();
        drop(f);

        // Set quarantine
        set_on_file(&tmppath).unwrap();

        // Read back xattr
        let path_cstr = std::ffi::CString::new(tmppath.as_os_str().as_encoded_bytes()).unwrap();
        let attr_name = std::ffi::CString::new("com.apple.quarantine")
            .expect("com.apple.quarantine is not null-terminated");
        let mut buf = [0u8; 256];
        let len = unsafe {
            libc::getxattr(
                path_cstr.as_ptr(),
                attr_name.as_ptr(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                0,
                0,
            )
        };
        assert!(
            len > 0,
            "quarantine xattr should be present: {}",
            io::Error::last_os_error()
        );

        let val = std::str::from_utf8(&buf[..len as usize]).unwrap();
        let fields: Vec<&str> = val.split(';').collect();
        assert_eq!(
            fields.len(),
            4,
            "quarantine value should have 4 semicolon-separated fields: {val}"
        );
        // Field 0: hex flags (should parse as hex number)
        assert!(
            u64::from_str_radix(fields[0], 16).is_ok(),
            "field 0 should be hex flags: {}",
            fields[0]
        );
        // Field 1: hex timestamp (should parse as hex)
        assert!(
            u64::from_str_radix(fields[1], 16).is_ok(),
            "field 1 should be hex timestamp: {}",
            fields[1]
        );
        // Field 2: agent name
        assert_eq!(fields[2], "Tailscale");
        // Field 3: UUID (lowercase hex with dashes, 36 chars)
        assert_eq!(fields[3].len(), 36);

        std::fs::remove_file(&tmppath).ok();
    }

    #[test]
    fn test_uuid_v4_format() {
        let uuid = uuid_v4();
        assert_eq!(uuid.len(), 36);
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        // Version nibble in part[2] should be 4
        assert_eq!(&parts[2][..1], "4", "UUID version should be 4");
        // Variant nibble in part[3] first char should be 8, 9, a, or b
        let variant_first = parts[3].chars().next().unwrap();
        assert!(
            matches!(variant_first, '8' | '9' | 'a' | 'b'),
            "UUID variant should be RFC 4122 (8/b), got: {variant_first}"
        );
    }

    #[test]
    fn test_uuid_v4_unique() {
        let u1 = uuid_v4();
        let u2 = uuid_v4();
        assert_ne!(u1, u2, "two UUIDs should be different");
    }
}
