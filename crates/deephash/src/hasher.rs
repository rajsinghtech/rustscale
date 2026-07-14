use sha2::{Digest, Sha256};

use crate::Sum;

const BLOCK_SIZE: usize = 64;

/// Buffered SHA-256 input for structural hashing.
pub struct Hasher {
    inner: Sha256,
    buffer: [u8; BLOCK_SIZE],
    used: usize,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    /// Create a new buffered SHA-256 hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
            buffer: [0; BLOCK_SIZE],
            used: 0,
        }
    }

    /// Hash raw bytes without a length prefix.
    pub fn hash_bytes(&mut self, mut bytes: &[u8]) {
        if self.used != 0 {
            let copied = (BLOCK_SIZE - self.used).min(bytes.len());
            self.buffer[self.used..self.used + copied].copy_from_slice(&bytes[..copied]);
            self.used += copied;
            bytes = &bytes[copied..];
            if self.used == BLOCK_SIZE {
                self.flush();
            }
        }

        let whole_blocks = bytes.len() / BLOCK_SIZE * BLOCK_SIZE;
        if whole_blocks != 0 {
            self.inner.update(&bytes[..whole_blocks]);
            bytes = &bytes[whole_blocks..];
        }
        if !bytes.is_empty() {
            self.buffer[..bytes.len()].copy_from_slice(bytes);
            self.used = bytes.len();
        }
    }

    /// Hash string bytes without a length prefix.
    pub fn hash_string(&mut self, value: &str) {
        self.hash_bytes(value.as_bytes());
    }

    /// Hash an unsigned 8-bit integer in little-endian representation.
    pub fn hash_uint8(&mut self, value: u8) {
        self.hash_bytes(&[value]);
    }

    /// Hash an unsigned 16-bit integer in little-endian representation.
    pub fn hash_uint16(&mut self, value: u16) {
        self.hash_bytes(&value.to_le_bytes());
    }

    /// Hash an unsigned 32-bit integer in little-endian representation.
    pub fn hash_uint32(&mut self, value: u32) {
        self.hash_bytes(&value.to_le_bytes());
    }

    /// Hash an unsigned 64-bit integer in little-endian representation.
    pub fn hash_uint64(&mut self, value: u64) {
        self.hash_bytes(&value.to_le_bytes());
    }

    /// Hash a checksum as four little-endian 64-bit words.
    pub fn hash_sum(&mut self, sum: &Sum) {
        for chunk in sum.as_bytes().chunks_exact(8) {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(chunk);
            self.hash_uint64(u64::from_le_bytes(bytes));
        }
    }

    /// Finish this hash and reset the hasher for reuse.
    #[must_use]
    pub fn finalize(&mut self) -> Sum {
        self.flush();
        let output = self.inner.finalize_reset();
        self.used = 0;
        Sum(output.into())
    }

    /// Reset this hasher without producing a digest.
    pub fn reset(&mut self) {
        self.inner.reset();
        self.used = 0;
    }

    fn flush(&mut self) {
        if self.used != 0 {
            self.inner.update(&self.buffer[..self.used]);
            self.used = 0;
        }
    }
}
