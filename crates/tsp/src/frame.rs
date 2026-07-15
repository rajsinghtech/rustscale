use std::io::Read as _;

use bytes::{Buf, BytesMut};
use rustscale_tailcfg::MapResponse;

/// Errors while parsing a framed, zstd-compressed map response.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("map response has a zero-length frame")]
    ZeroLength,
    #[error("map response encoded size {size} exceeds max {max}")]
    EncodedTooLarge { size: usize, max: usize },
    #[error("map response decoded size exceeds max {max}")]
    DecodedTooLarge { max: usize },
    #[error("truncated map response frame header ({received} of 4 bytes)")]
    TruncatedHeader { received: usize },
    #[error("truncated map response frame ({received} of {expected} bytes)")]
    TruncatedPayload { received: usize, expected: usize },
    #[error("decompressing map response: {0}")]
    Decompress(#[source] std::io::Error),
    #[error("decoding map response JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Incremental parser for little-endian length-prefixed zstd map frames.
///
/// Both the encoded frame and its decoded JSON are independently capped by
/// `max_message_size`. Feed arbitrary transport chunks with [`push`](Self::push),
/// call [`next_response`](Self::next_response) until it returns `None`, and call
/// [`finish`](Self::finish) at end-of-stream to detect truncation.
pub struct FrameDecoder {
    input: BytesMut,
    max_message_size: usize,
}

impl FrameDecoder {
    pub fn new(max_message_size: usize) -> Self {
        assert!(max_message_size > 0, "max message size must be non-zero");
        Self {
            input: BytesMut::new(),
            max_message_size,
        }
    }

    /// Append bytes received from the HTTP response body.
    pub fn push(&mut self, data: &[u8]) {
        self.input.extend_from_slice(data);
    }

    /// Decode one complete response, or return `None` if more bytes are needed.
    pub fn next_response(&mut self) -> Result<Option<MapResponse>, FrameError> {
        if self.input.len() < 4 {
            return Ok(None);
        }
        let size =
            u32::from_le_bytes(self.input[..4].try_into().expect("four-byte prefix")) as usize;
        if size == 0 {
            return Err(FrameError::ZeroLength);
        }
        if size > self.max_message_size {
            return Err(FrameError::EncodedTooLarge {
                size,
                max: self.max_message_size,
            });
        }
        if self.input.len() < 4 + size {
            return Ok(None);
        }

        self.input.advance(4);
        let compressed = self.input.split_to(size);
        let mut decoder = zstd::stream::read::Decoder::new(compressed.as_ref())
            .map_err(FrameError::Decompress)?;
        let read_limit = u64::try_from(self.max_message_size)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut decoded = Vec::new();
        decoder
            .by_ref()
            .take(read_limit)
            .read_to_end(&mut decoded)
            .map_err(FrameError::Decompress)?;
        if decoded.len() > self.max_message_size {
            return Err(FrameError::DecodedTooLarge {
                max: self.max_message_size,
            });
        }

        Ok(Some(serde_json::from_slice(&decoded)?))
    }

    /// Validate that the transport ended exactly at a frame boundary.
    pub fn finish(&self) -> Result<(), FrameError> {
        if self.input.is_empty() {
            return Ok(());
        }
        if self.input.len() < 4 {
            return Err(FrameError::TruncatedHeader {
                received: self.input.len(),
            });
        }
        let expected =
            u32::from_le_bytes(self.input[..4].try_into().expect("four-byte prefix")) as usize;
        if expected == 0 {
            return Err(FrameError::ZeroLength);
        }
        if expected > self.max_message_size {
            return Err(FrameError::EncodedTooLarge {
                size: expected,
                max: self.max_message_size,
            });
        }
        Err(FrameError::TruncatedPayload {
            received: self.input.len() - 4,
            expected,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_frame(raw: &[u8]) -> Vec<u8> {
        let compressed = zstd::bulk::compress(raw, 1).unwrap();
        let mut wire = Vec::with_capacity(4 + compressed.len());
        wire.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        wire.extend_from_slice(&compressed);
        wire
    }

    #[test]
    fn parses_frames_across_every_chunk_boundary() {
        let wire = wire_frame(br#"{"Domain":"example.test"}"#);
        for split in 0..=wire.len() {
            let mut decoder = FrameDecoder::new(4096);
            decoder.push(&wire[..split]);
            let first = decoder.next_response().unwrap();
            decoder.push(&wire[split..]);
            let response = first.or_else(|| decoder.next_response().unwrap()).unwrap();
            assert_eq!(response.Domain, "example.test", "split {split}");
            assert!(decoder.next_response().unwrap().is_none());
            decoder.finish().unwrap();
        }
    }

    #[test]
    fn parses_multiple_frames_with_per_frame_budget() {
        let payload = "a".repeat(900);
        let mut wire = wire_frame(
            serde_json::to_string(&MapResponse {
                Domain: format!("{payload}-one"),
                ..Default::default()
            })
            .unwrap()
            .as_bytes(),
        );
        wire.extend_from_slice(&wire_frame(
            serde_json::to_string(&MapResponse {
                Domain: format!("{payload}-two"),
                ..Default::default()
            })
            .unwrap()
            .as_bytes(),
        ));

        let mut decoder = FrameDecoder::new(1024);
        decoder.push(&wire);
        assert!(decoder
            .next_response()
            .unwrap()
            .unwrap()
            .Domain
            .ends_with("-one"));
        assert!(decoder
            .next_response()
            .unwrap()
            .unwrap()
            .Domain
            .ends_with("-two"));
        decoder.finish().unwrap();
    }

    #[test]
    fn rejects_zero_length_and_oversized_encoded_frames() {
        let mut zero = FrameDecoder::new(16);
        zero.push(&0_u32.to_le_bytes());
        assert!(matches!(zero.next_response(), Err(FrameError::ZeroLength)));

        let mut oversized = FrameDecoder::new(16);
        oversized.push(&17_u32.to_le_bytes());
        assert!(matches!(
            oversized.next_response(),
            Err(FrameError::EncodedTooLarge { size: 17, max: 16 })
        ));
    }

    #[test]
    fn rejects_oversized_decoded_frame() {
        let raw = serde_json::to_vec(&MapResponse {
            Domain: "a".repeat(2048),
            ..Default::default()
        })
        .unwrap();
        let wire = wire_frame(&raw);
        assert!(wire.len() < 1024);
        let mut decoder = FrameDecoder::new(1024);
        decoder.push(&wire);
        assert!(matches!(
            decoder.next_response(),
            Err(FrameError::DecodedTooLarge { max: 1024 })
        ));
    }

    #[test]
    fn rejects_malformed_compression_and_json() {
        let mut malformed = FrameDecoder::new(1024);
        malformed.push(&4_u32.to_le_bytes());
        malformed.push(b"nope");
        assert!(matches!(
            malformed.next_response(),
            Err(FrameError::Decompress(_))
        ));

        let wire = wire_frame(b"not json");
        let mut invalid_json = FrameDecoder::new(1024);
        invalid_json.push(&wire);
        assert!(matches!(
            invalid_json.next_response(),
            Err(FrameError::Json(_))
        ));
    }

    #[test]
    fn reports_truncated_headers_and_payloads() {
        for size in 1..4 {
            let mut decoder = FrameDecoder::new(1024);
            decoder.push(&[0xaa; 3][..size]);
            assert!(decoder.next_response().unwrap().is_none());
            assert!(matches!(
                decoder.finish(),
                Err(FrameError::TruncatedHeader { received }) if received == size
            ));
        }

        let mut decoder = FrameDecoder::new(1024);
        decoder.push(&10_u32.to_le_bytes());
        decoder.push(b"short");
        assert!(decoder.next_response().unwrap().is_none());
        assert!(matches!(
            decoder.finish(),
            Err(FrameError::TruncatedPayload {
                received: 5,
                expected: 10
            })
        ));
    }
}
