//! QR code rendering for the `up --qr` / `login --qr` CLI flags.
//!
//! Ports the subset of Go's `util/qrcodes` package needed by the CLI:
//! - Terminal rendering with unicode half-block characters (Go's "small"
//!   format, analogous to `qrcode.QRCode.ToSmallString`).
//! - PNG encoding as a `data:image/png;base64,...` data URL for `--json`
//!   output (analogous to Go's `qrcodes.EncodePNG`).
//!
//! The [`qrcode`] crate handles matrix generation; the PNG encoder is
//! hand-rolled (1-bit grayscale PNG via [`flate2`] zlib + [`crc32fast`]
//! chunk CRCs) to avoid pulling in the heavy `image` crate.

use std::io::Write;

use base64::Engine as _;

/// Render `data` as a terminal QR code using unicode half-block characters
/// (▀ ▄ █ space). Each terminal row encodes two QR module rows, matching
/// Go's "small" format (`qrcode.ToSmallString`).
///
/// Returns the rendered string (without trailing newline).
pub fn render_terminal(data: &str) -> Result<String, QrError> {
    let qr = qrcode::QrCode::new(data).map_err(QrError::Encode)?;
    let width = qr.width();
    let modules: Vec<bool> = (0..width * width)
        .map(|i| {
            let y = i / width;
            let x = i % width;
            qr[(x, y)] == qrcode::Color::Dark
        })
        .collect();

    let mut out = String::with_capacity(width * (width / 2 + 1) * 4);
    for y in (0..width).step_by(2) {
        for x in 0..width {
            let top = modules[y * width + x];
            let bottom = if y + 1 < width {
                modules[(y + 1) * width + x]
            } else {
                false
            };
            out.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
    }
    Ok(out)
}

/// Encode `data` as a PNG image and return it as a
/// `data:image/png;base64,...` data URL (for `--json` output).
///
/// The PNG is a 1-bit grayscale image with a 4-pixel quiet zone (matching
/// Go's default). Each QR module is 1 pixel (scaled up by the terminal
/// font; Go uses 128px for the PNG but 1px-per-module is sufficient for
/// a scannable data URL).
pub fn render_png_data_url(data: &str) -> Result<String, QrError> {
    let png = render_png_bytes(data)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&png);
    Ok(format!("data:image/png;base64,{b64}"))
}

/// Encode `data` as a raw PNG byte vector (1-bit grayscale, quiet zone 4).
pub fn render_png_bytes(data: &str) -> Result<Vec<u8>, QrError> {
    let qr = qrcode::QrCode::new(data).map_err(QrError::Encode)?;
    let qw = qr.width();
    let quiet = 4;
    let total = qw + 2 * quiet;

    // Build the 1-bit bitmap: 1 = dark, 0 = light.
    // PNG scanline: 1 filter byte + ceil(total/8) pixel bytes.
    let row_bytes = total.div_ceil(8);
    let mut raw = Vec::with_capacity(total * (row_bytes + 1));
    for y in 0..total {
        raw.push(0u8); // filter: None
        for byte_idx in 0..row_bytes {
            let mut byte = 0u8;
            for bit in 0..8 {
                let x = byte_idx * 8 + bit;
                if x >= total {
                    break;
                }
                // In the quiet zone → light (0). Inside → check QR module.
                let dark = if x >= quiet && x < quiet + qw && y >= quiet && y < quiet + qw {
                    qr[(x - quiet, y - quiet)] == qrcode::Color::Dark
                } else {
                    false
                };
                // 1-bit grayscale: 0 = black (dark), 1 = white (light).
                // In PNG 1-bit, the high bit is the leftmost pixel.
                if !dark {
                    byte |= 0x80u8 >> bit;
                }
            }
            raw.push(byte);
        }
    }

    // zlib-compress the raw scanline data.
    let compressed = {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&raw).map_err(QrError::Io)?;
        encoder.finish().map_err(QrError::Io)?
    };

    // Assemble the PNG file.
    let mut png = Vec::with_capacity(64 + compressed.len());
    // PNG signature.
    png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    // IHDR chunk.
    write_chunk(&mut png, *b"IHDR", &ihdr_payload(total, total));
    // IDAT chunk.
    write_chunk(&mut png, *b"IDAT", &compressed);
    // IEND chunk.
    write_chunk(&mut png, *b"IEND", &[]);

    Ok(png)
}

/// Build the 13-byte IHDR payload for a 1-bit grayscale image.
fn ihdr_payload(width: usize, height: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(13);
    p.extend_from_slice(&(width as u32).to_be_bytes());
    p.extend_from_slice(&(height as u32).to_be_bytes());
    p.push(1); // bit depth
    p.push(0); // color type: grayscale
    p.push(0); // compression method: deflate
    p.push(0); // filter method: standard
    p.push(0); // interlace method: none
    p
}

/// Write a PNG chunk: length + type + data + CRC.
fn write_chunk(out: &mut Vec<u8>, chunk_type: [u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&chunk_type);
    out.extend_from_slice(data);
    let mut crc_data = Vec::with_capacity(4 + data.len());
    crc_data.extend_from_slice(&chunk_type);
    crc_data.extend_from_slice(data);
    let crc = crc32fast::hash(&crc_data);
    out.extend_from_slice(&crc.to_be_bytes());
}

/// QR code rendering errors.
#[derive(Debug, thiserror::Error)]
pub enum QrError {
    #[error("QR encode: {0}")]
    Encode(#[from] qrcode::types::QrError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_terminal_known_url() {
        let url = "https://login.tailscale.com/a/0123456789abcdef";
        let out = render_terminal(url).expect("render");
        // The output should be non-empty and contain half-block characters.
        assert!(!out.is_empty());
        assert!(
            out.contains('█') || out.contains('▀') || out.contains('▄'),
            "should contain at least one block char"
        );
        // Every line should have the same width (QR is square + quiet zone).
        let lines: Vec<&str> = out.lines().collect();
        assert!(!lines.is_empty());
        let w = lines[0].chars().count();
        assert!(w > 0);
        for line in &lines {
            assert_eq!(
                line.chars().count(),
                w,
                "all lines must have the same width"
            );
        }
    }

    #[test]
    fn render_terminal_deterministic() {
        let url = "https://login.tailscale.com/a/test";
        let a = render_terminal(url).expect("render");
        let b = render_terminal(url).expect("render");
        assert_eq!(a, b, "same input must produce identical output");
    }

    #[test]
    fn render_png_bytes_valid_header() {
        let url = "https://login.tailscale.com/a/test";
        let png = render_png_bytes(url).expect("png");
        // PNG signature.
        assert_eq!(&png[..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        // IHDR chunk type.
        assert_eq!(&png[12..16], b"IHDR");
        // Should end with IEND chunk (4-byte length=0 + "IEND" + 4-byte CRC).
        assert_eq!(&png[png.len() - 8..png.len() - 4], b"IEND");
    }

    #[test]
    fn render_png_data_url_prefix() {
        let url = "https://login.tailscale.com/a/test";
        let data_url = render_png_data_url(url).expect("data url");
        assert!(
            data_url.starts_with("data:image/png;base64,"),
            "must be a PNG data URL"
        );
        // The base64 part should decode back to a valid PNG.
        let b64 = &data_url["data:image/png;base64,".len()..];
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("valid base64");
        assert_eq!(
            &decoded[..8],
            &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        );
    }

    #[test]
    fn render_terminal_empty_input_succeeds() {
        // The qrcode crate can encode an empty string (produces a minimal QR).
        // We just verify it doesn't panic and returns a string.
        let out = render_terminal("").expect("empty string is valid QR data");
        assert!(!out.is_empty());
    }
}
