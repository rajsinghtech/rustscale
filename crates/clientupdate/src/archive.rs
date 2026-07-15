use std::io::{Cursor, Read};
use std::path::{Component, Path};

use flate2::read::MultiGzDecoder;

use crate::UpdateError;

pub(crate) const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
const MAX_UNCOMPRESSED_BYTES: usize = 512 * 1024 * 1024;
const MAX_ENTRY_BYTES: usize = 256 * 1024 * 1024;
const MAX_BINARY_BYTES: usize = 128 * 1024 * 1024;
const MAX_HEADERS: usize = 128;
const BLOCK: usize = 512;

#[derive(Debug)]
pub(crate) struct BinaryPayloads {
    pub rustscale: Vec<u8>,
    pub rustscaled: Vec<u8>,
}

/// Parse the deliberately small release archive subset used by release.yml.
///
/// This parser accepts only ustar regular files at the archive root plus the
/// root directory entry. It intentionally rejects extension records (PAX/GNU
/// long names), links, devices, FIFOs, and sparse files instead of delegating
/// path interpretation to a general-purpose extractor.
pub(crate) fn extract_binaries(compressed: &[u8]) -> Result<BinaryPayloads, UpdateError> {
    if compressed.len() > MAX_ARCHIVE_BYTES {
        return Err(unsafe_archive("compressed archive exceeds 256 MiB"));
    }

    let mut decoder = MultiGzDecoder::new(Cursor::new(compressed));
    let mut tar = Vec::new();
    decoder
        .by_ref()
        .take((MAX_UNCOMPRESSED_BYTES + 1) as u64)
        .read_to_end(&mut tar)
        .map_err(|error| unsafe_archive(format!("invalid gzip stream: {error}")))?;
    if tar.len() > MAX_UNCOMPRESSED_BYTES {
        return Err(unsafe_archive("expanded archive exceeds 512 MiB"));
    }

    parse_tar(&tar)
}

fn parse_tar(tar: &[u8]) -> Result<BinaryPayloads, UpdateError> {
    let mut offset = 0_usize;
    let mut headers = 0_usize;
    let mut zero_headers = 0_u8;
    let mut rustscale = None;
    let mut rustscaled = None;
    let mut total_payload = 0_usize;

    while offset + BLOCK <= tar.len() {
        let header = &tar[offset..offset + BLOCK];
        offset += BLOCK;
        if header.iter().all(|byte| *byte == 0) {
            zero_headers = zero_headers.saturating_add(1);
            if zero_headers == 2 {
                if tar[offset..].iter().any(|byte| *byte != 0) {
                    return Err(unsafe_archive("non-zero data follows the tar terminator"));
                }
                return finish(rustscale, rustscaled);
            }
            continue;
        }
        if zero_headers != 0 {
            return Err(unsafe_archive("tar contains an isolated zero header"));
        }

        headers += 1;
        if headers > MAX_HEADERS {
            return Err(unsafe_archive("archive contains too many metadata entries"));
        }
        verify_header_checksum(header)?;
        let magic = &header[257..263];
        if magic != b"ustar\0" && magic != b"ustar " {
            return Err(unsafe_archive(
                "archive is not in the supported ustar format",
            ));
        }
        if header[345..500].iter().any(|byte| *byte != 0) {
            return Err(unsafe_archive("ustar path prefixes are not permitted"));
        }

        let name = parse_text_field(&header[0..100], "path")?;
        validate_path(name)?;
        let size = parse_octal(&header[124..136], "size")?;
        if size > MAX_ENTRY_BYTES {
            return Err(unsafe_archive(format!("entry {name:?} exceeds 256 MiB")));
        }
        total_payload = total_payload
            .checked_add(size)
            .ok_or_else(|| unsafe_archive("archive size overflow"))?;
        if total_payload > MAX_UNCOMPRESSED_BYTES {
            return Err(unsafe_archive("archive payload exceeds 512 MiB"));
        }

        let kind = header[156];
        match kind {
            b'5' => {
                if size != 0 || !matches!(name, "." | "./") {
                    return Err(unsafe_archive("only the root directory entry is permitted"));
                }
            }
            0 | b'0' => {
                let normalized = normalize_top_level(name)?;
                let end = offset
                    .checked_add(size)
                    .ok_or_else(|| unsafe_archive("entry offset overflow"))?;
                if end > tar.len() {
                    return Err(unsafe_archive(format!("entry {name:?} is truncated")));
                }
                let payload = &tar[offset..end];
                match normalized {
                    "rustscale" => set_binary(&mut rustscale, payload, normalized)?,
                    "rustscaled" => set_binary(&mut rustscaled, payload, normalized)?,
                    _ => {}
                }
            }
            // This includes hardlinks/symlinks, devices, FIFOs, GNU sparse,
            // GNU long-name records, and local/global PAX headers.
            other => {
                return Err(unsafe_archive(format!(
                    "unsupported tar entry type 0x{other:02x} for {name:?}"
                )));
            }
        }

        let padded = size
            .checked_add(BLOCK - 1)
            .map(|value| value / BLOCK * BLOCK)
            .ok_or_else(|| unsafe_archive("entry padding overflow"))?;
        offset = offset
            .checked_add(padded)
            .ok_or_else(|| unsafe_archive("entry offset overflow"))?;
        if offset > tar.len() {
            return Err(unsafe_archive(format!("entry {name:?} is truncated")));
        }
    }

    Err(unsafe_archive("tar is missing its two-block terminator"))
}

fn set_binary(slot: &mut Option<Vec<u8>>, payload: &[u8], name: &str) -> Result<(), UpdateError> {
    if slot.is_some() {
        return Err(unsafe_archive(format!("duplicate {name} entry")));
    }
    if payload.is_empty() || payload.len() > MAX_BINARY_BYTES {
        return Err(unsafe_archive(format!(
            "{name} must be between 1 byte and 128 MiB"
        )));
    }
    *slot = Some(payload.to_vec());
    Ok(())
}

fn finish(
    rustscale: Option<Vec<u8>>,
    rustscaled: Option<Vec<u8>>,
) -> Result<BinaryPayloads, UpdateError> {
    Ok(BinaryPayloads {
        rustscale: rustscale.ok_or_else(|| unsafe_archive("archive is missing rustscale"))?,
        rustscaled: rustscaled.ok_or_else(|| unsafe_archive("archive is missing rustscaled"))?,
    })
}

fn validate_path(name: &str) -> Result<(), UpdateError> {
    if name.is_empty()
        || name.len() > 100
        || name
            .bytes()
            .any(|byte| byte == b'\n' || byte == b'\r' || byte == 0 || !byte.is_ascii_graphic())
    {
        return Err(unsafe_archive(
            "archive path contains unsupported characters",
        ));
    }
    let path = Path::new(name);
    if path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(unsafe_archive(format!("unsafe archive path {name:?}")));
    }
    Ok(())
}

fn normalize_top_level(name: &str) -> Result<&str, UpdateError> {
    let normalized = name.strip_prefix("./").unwrap_or(name);
    if normalized.is_empty() || normalized.contains('/') || matches!(normalized, "." | "..") {
        return Err(unsafe_archive(format!(
            "archive file is not top-level: {name:?}"
        )));
    }
    Ok(normalized)
}

fn parse_text_field<'a>(field: &'a [u8], label: &str) -> Result<&'a str, UpdateError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(unsafe_archive(format!("malformed tar {label} field")));
    }
    std::str::from_utf8(&field[..end])
        .map_err(|error| unsafe_archive(format!("tar {label} is not UTF-8: {error}")))
}

fn parse_octal(field: &[u8], label: &str) -> Result<usize, UpdateError> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(unsafe_archive(format!(
            "base-256 tar {label} values are not supported"
        )));
    }
    let text = std::str::from_utf8(field)
        .map_err(|error| unsafe_archive(format!("invalid tar {label}: {error}")))?
        .trim_matches(['\0', ' ']);
    if text.is_empty() {
        return Ok(0);
    }
    if !text.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(unsafe_archive(format!("invalid octal tar {label}")));
    }
    usize::from_str_radix(text, 8)
        .map_err(|error| unsafe_archive(format!("invalid tar {label}: {error}")))
}

fn verify_header_checksum(header: &[u8]) -> Result<(), UpdateError> {
    let expected = parse_octal(&header[148..156], "checksum")?;
    let actual: usize = header[..148]
        .iter()
        .chain([b' '; 8].iter())
        .chain(header[156..].iter())
        .map(|byte| usize::from(*byte))
        .sum();
    if actual != expected {
        return Err(unsafe_archive(format!(
            "tar header checksum mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn unsafe_archive(message: impl Into<String>) -> UpdateError {
    UpdateError::UnsafeArchive(message.into())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{write::GzEncoder, Compression};

    use super::*;

    fn archive(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (name, kind, body) in entries {
            let mut header = [0_u8; BLOCK];
            header[..name.len()].copy_from_slice(name.as_bytes());
            write_octal(&mut header[100..108], 0o755);
            write_octal(&mut header[108..116], 0);
            write_octal(&mut header[116..124], 0);
            write_octal(&mut header[124..136], body.len());
            write_octal(&mut header[136..148], 0);
            header[148..156].fill(b' ');
            header[156] = *kind;
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let sum: usize = header.iter().map(|byte| usize::from(*byte)).sum();
            write_octal(&mut header[148..156], sum);
            tar.extend_from_slice(&header);
            tar.extend_from_slice(body);
            tar.resize(tar.len().div_ceil(BLOCK) * BLOCK, 0);
        }
        tar.extend_from_slice(&[0_u8; BLOCK * 2]);
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(&tar).unwrap();
        gzip.finish().unwrap()
    }

    fn write_octal(field: &mut [u8], value: usize) {
        field.fill(b'0');
        let text = format!("{value:o}");
        let start = field.len() - text.len() - 1;
        field[start..start + text.len()].copy_from_slice(text.as_bytes());
        field[field.len() - 1] = 0;
    }

    #[test]
    fn extracts_only_required_regular_top_level_binaries() {
        let bytes = archive(&[
            ("./", b'5', b""),
            ("./rustscale", b'0', b"cli"),
            ("./rustscaled", b'0', b"daemon"),
            ("./LICENSE", b'0', b"license"),
        ]);
        let payloads = extract_binaries(&bytes).unwrap();
        assert_eq!(payloads.rustscale, b"cli");
        assert_eq!(payloads.rustscaled, b"daemon");
    }

    #[test]
    fn rejects_links_devices_fifos_sparse_and_pax() {
        for kind in *b"12346SxgLK" {
            let bytes = archive(&[("rustscale", kind, b"cli"), ("rustscaled", b'0', b"daemon")]);
            assert!(extract_binaries(&bytes).is_err(), "accepted type {kind}");
        }
    }

    #[test]
    fn rejects_duplicates_newlines_nested_and_parent_paths() {
        for entries in [
            vec![
                ("rustscale", b'0', b"a".as_slice()),
                ("rustscale", b'0', b"b".as_slice()),
                ("rustscaled", b'0', b"d".as_slice()),
            ],
            vec![
                ("rustscale\nother", b'0', b"a".as_slice()),
                ("rustscaled", b'0', b"d".as_slice()),
            ],
            vec![
                ("bin/rustscale", b'0', b"a".as_slice()),
                ("rustscaled", b'0', b"d".as_slice()),
            ],
            vec![
                ("../rustscale", b'0', b"a".as_slice()),
                ("rustscaled", b'0', b"d".as_slice()),
            ],
        ] {
            assert!(extract_binaries(&archive(&entries)).is_err());
        }
    }

    #[test]
    fn rejects_bad_checksum_truncation_and_missing_terminator() {
        let valid = archive(&[("rustscale", b'0', b"cli"), ("rustscaled", b'0', b"daemon")]);
        let mut decoded = Vec::new();
        MultiGzDecoder::new(Cursor::new(&valid))
            .read_to_end(&mut decoded)
            .unwrap();
        decoded[0] ^= 1;
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(&decoded).unwrap();
        assert!(extract_binaries(&gzip.finish().unwrap()).is_err());

        assert!(parse_tar(&decoded[..BLOCK]).is_err());
        assert!(parse_tar(&decoded[..decoded.len() - BLOCK * 2]).is_err());
    }
}
