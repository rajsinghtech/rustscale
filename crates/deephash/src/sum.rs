use std::fmt;

/// A SHA-256 structural checksum.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sum(pub(crate) [u8; 32]);

impl Sum {
    /// XOR another checksum into this one.
    pub fn xor(&mut self, other: &Self) {
        for (left, right) in self.0.iter_mut().zip(other.0) {
            *left ^= right;
        }
    }

    /// Append this checksum's hexadecimal representation to `buf`.
    pub fn append_to(&self, buf: &mut Vec<u8>) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        buf.reserve(self.0.len() * 2);
        for byte in self.0 {
            buf.push(HEX[usize::from(byte >> 4)]);
            buf.push(HEX[usize::from(byte & 0x0f)]);
        }
    }

    /// Return the checksum bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
