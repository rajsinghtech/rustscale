use std::{
    collections::VecDeque,
    io::{self, ErrorKind},
    sync::Mutex,
    time::Instant,
};

/// A bounded, non-blocking in-memory FIFO byte buffer.
///
/// `MemConn` uses Tokio's bounded duplex streams for transport. This type is
/// available for tests that need direct control over a simple bounded buffer.
#[derive(Debug)]
pub struct MemBuf {
    name: String,
    max_buf: usize,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    buf: VecDeque<u8>,
    closed: bool,
    blocked: bool,
    read_deadline: Option<Instant>,
    write_deadline: Option<Instant>,
}

impl MemBuf {
    /// Creates an empty FIFO whose capacity is `max_buf` bytes.
    #[must_use]
    pub fn new(name: &str, max_buf: usize) -> Self {
        Self {
            name: name.to_owned(),
            max_buf,
            state: Mutex::new(State {
                buf: VecDeque::with_capacity(max_buf),
                closed: false,
                blocked: false,
                read_deadline: None,
                write_deadline: None,
            }),
        }
    }

    /// Returns this buffer's diagnostic name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Attempts to read bytes without waiting.
    pub fn read(&self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.lock().expect("MemBuf mutex poisoned");
        check_deadline(state.read_deadline)?;
        if state.blocked {
            return Err(would_block("buffer is blocked"));
        }
        if state.buf.is_empty() {
            return if state.closed {
                Ok(0)
            } else {
                Err(would_block("buffer is empty"))
            };
        }
        let count = output.len().min(state.buf.len());
        for byte in &mut output[..count] {
            *byte = state.buf.pop_front().expect("buffer length was checked");
        }
        Ok(count)
    }

    /// Attempts to write bytes without waiting.
    pub fn write(&self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.lock().expect("MemBuf mutex poisoned");
        check_deadline(state.write_deadline)?;
        if state.closed {
            return Err(io::Error::new(ErrorKind::BrokenPipe, "buffer is closed"));
        }
        if state.blocked {
            return Err(would_block("buffer is blocked"));
        }
        let available = self.max_buf.saturating_sub(state.buf.len());
        if available == 0 {
            return Err(would_block("buffer is full"));
        }
        let count = available.min(input.len());
        state.buf.extend(&input[..count]);
        Ok(count)
    }

    /// Closes the buffer. Pending bytes remain readable before EOF.
    pub fn close(&self) {
        self.state.lock().expect("MemBuf mutex poisoned").closed = true;
    }

    /// Prevents reads and writes until [`Self::unblock`] is called.
    pub fn block(&self) {
        self.state.lock().expect("MemBuf mutex poisoned").blocked = true;
    }

    /// Allows reads and writes again.
    pub fn unblock(&self) {
        self.state.lock().expect("MemBuf mutex poisoned").blocked = false;
    }

    /// Sets the deadline checked by future reads.
    pub fn set_read_deadline(&self, deadline: Option<Instant>) {
        self.state
            .lock()
            .expect("MemBuf mutex poisoned")
            .read_deadline = deadline;
    }

    /// Sets the deadline checked by future writes.
    pub fn set_write_deadline(&self, deadline: Option<Instant>) {
        self.state
            .lock()
            .expect("MemBuf mutex poisoned")
            .write_deadline = deadline;
    }
}

fn check_deadline(deadline: Option<Instant>) -> io::Result<()> {
    if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
        return Err(io::Error::new(
            ErrorKind::TimedOut,
            "buffer deadline expired",
        ));
    }
    Ok(())
}

fn would_block(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::WouldBlock, message)
}
