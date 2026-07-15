use std::{
    collections::{HashMap, VecDeque},
    future::{poll_fn, Future},
    io::{self, ErrorKind},
    pin::Pin,
    sync::{Mutex, MutexGuard},
    task::{Context, Poll, Waker},
    time::Instant,
};

use tokio::time::Sleep;

/// A bounded in-memory FIFO used as one direction of a connection.
///
/// Reads wait while the pipe is empty and writes apply backpressure while it
/// is full. Closing preserves buffered bytes for readers and rejects future
/// writes. A blocked pipe stalls both its reader and writer, matching the
/// fault-injection behavior of Tailscale's `memnet.Pipe`.
#[derive(Debug)]
pub struct MemPipe {
    name: String,
    max_buf: usize,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    buf: VecDeque<u8>,
    closed: bool,
    blocked: bool,
    read_deadline: Option<Instant>,
    write_deadline: Option<Instant>,
    next_waiter_id: u64,
    readers: HashMap<u64, Waiter>,
    writers: HashMap<u64, Waiter>,
}

#[derive(Debug)]
struct Waiter {
    waker: Waker,
    timer: Option<Pin<Box<Sleep>>>,
}

#[derive(Clone, Copy)]
enum WaitKind {
    Read,
    Write,
}

struct WaitRegistration<'a> {
    pipe: &'a MemPipe,
    kind: WaitKind,
    id: Option<u64>,
}

impl Drop for WaitRegistration<'_> {
    fn drop(&mut self) {
        let Some(id) = self.id else {
            return;
        };
        let mut state = self.pipe.lock_state();
        match self.kind {
            WaitKind::Read => state.readers.remove(&id),
            WaitKind::Write => state.writers.remove(&id),
        };
    }
}

impl MemPipe {
    /// Creates an empty FIFO with a fixed byte capacity.
    #[must_use]
    pub fn new(name: impl Into<String>, max_buf: usize) -> Self {
        Self {
            name: name.into(),
            max_buf,
            state: Mutex::new(State {
                buf: VecDeque::with_capacity(max_buf),
                ..State::default()
            }),
        }
    }

    /// Returns the diagnostic name of this pipe.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reads at least one byte, waiting for data, EOF, a deadline, or close.
    ///
    /// An empty output slice completes immediately. Once closed, buffered data
    /// is drained before reads return `0` (EOF).
    pub async fn read(&self, output: &mut [u8]) -> io::Result<usize> {
        let mut waiter = WaitRegistration {
            pipe: self,
            kind: WaitKind::Read,
            id: None,
        };
        poll_fn(|cx| self.poll_read(cx, output, &mut waiter.id)).await
    }

    /// Writes all of `input`, waiting whenever the fixed-capacity buffer is
    /// full. An empty input completes immediately.
    pub async fn write(&self, input: &[u8]) -> io::Result<usize> {
        let mut waiter = WaitRegistration {
            pipe: self,
            kind: WaitKind::Write,
            id: None,
        };
        let mut written = 0;
        while written < input.len() {
            written += poll_fn(|cx| self.poll_write(cx, &input[written..], &mut waiter.id)).await?;
        }
        Ok(written)
    }

    /// Closes the pipe and wakes every waiter.
    ///
    /// This operation is idempotent. Buffered bytes remain readable.
    pub fn close(&self) {
        let (readers, writers) = {
            let mut state = self.lock_state();
            state.closed = true;
            state.blocked = false;
            (
                std::mem::take(&mut state.readers),
                std::mem::take(&mut state.writers),
            )
        };
        wake_all(readers);
        wake_all(writers);
    }

    /// Blocks reads and writes until [`Self::unblock`] is called.
    pub fn block(&self) -> io::Result<()> {
        let (readers, writers) = {
            let mut state = self.lock_state();
            if state.closed {
                return Err(pipe_error(
                    ErrorKind::BrokenPipe,
                    &self.name,
                    "block: closed",
                ));
            }
            if state.blocked {
                return Err(pipe_error(
                    ErrorKind::AlreadyExists,
                    &self.name,
                    "block: already blocked",
                ));
            }
            state.blocked = true;
            (
                std::mem::take(&mut state.readers),
                std::mem::take(&mut state.writers),
            )
        };
        wake_all(readers);
        wake_all(writers);
        Ok(())
    }

    /// Resumes reads and writes stalled by [`Self::block`].
    pub fn unblock(&self) -> io::Result<()> {
        let (readers, writers) = {
            let mut state = self.lock_state();
            if state.closed {
                return Err(pipe_error(
                    ErrorKind::BrokenPipe,
                    &self.name,
                    "unblock: closed",
                ));
            }
            if !state.blocked {
                return Err(pipe_error(
                    ErrorKind::InvalidInput,
                    &self.name,
                    "unblock: already unblocked",
                ));
            }
            state.blocked = false;
            (
                std::mem::take(&mut state.readers),
                std::mem::take(&mut state.writers),
            )
        };
        wake_all(readers);
        wake_all(writers);
        Ok(())
    }

    /// Sets or clears the absolute deadline for reads and wakes a pending read.
    pub fn set_read_deadline(&self, deadline: Option<Instant>) {
        let readers = {
            let mut state = self.lock_state();
            state.read_deadline = deadline;
            std::mem::take(&mut state.readers)
        };
        wake_all(readers);
    }

    /// Sets or clears the absolute deadline for writes and wakes a pending write.
    pub fn set_write_deadline(&self, deadline: Option<Instant>) {
        let writers = {
            let mut state = self.lock_state();
            state.write_deadline = deadline;
            std::mem::take(&mut state.writers)
        };
        wake_all(writers);
    }

    pub(crate) fn poll_read(
        &self,
        cx: &mut Context<'_>,
        output: &mut [u8],
        waiter_id: &mut Option<u64>,
    ) -> Poll<io::Result<usize>> {
        let mut state = self.lock_state();
        if output.is_empty() {
            clear_waiter(&mut state.readers, waiter_id);
            return Poll::Ready(Ok(0));
        }

        if deadline_elapsed(state.read_deadline) {
            clear_waiter(&mut state.readers, waiter_id);
            let readers = std::mem::take(&mut state.readers);
            drop(state);
            wake_all(readers);
            return Poll::Ready(Err(deadline_error("read")));
        }
        if !state.blocked && !state.buf.is_empty() {
            clear_waiter(&mut state.readers, waiter_id);
            let count = output.len().min(state.buf.len());
            for byte in &mut output[..count] {
                *byte = state.buf.pop_front().expect("buffer length was checked");
            }
            let writers = std::mem::take(&mut state.writers);
            drop(state);
            wake_all(writers);
            return Poll::Ready(Ok(count));
        }
        if !state.blocked && state.closed {
            clear_waiter(&mut state.readers, waiter_id);
            return Poll::Ready(Ok(0));
        }
        let read_deadline = state.read_deadline;
        if poll_waiter(
            &mut state,
            WaitKind::Read,
            waiter_id,
            cx.waker(),
            read_deadline,
            cx,
        )
        .is_ready()
        {
            clear_waiter(&mut state.readers, waiter_id);
            let readers = std::mem::take(&mut state.readers);
            drop(state);
            wake_all(readers);
            return Poll::Ready(Err(deadline_error("read")));
        }
        Poll::Pending
    }

    pub(crate) fn poll_write(
        &self,
        cx: &mut Context<'_>,
        input: &[u8],
        waiter_id: &mut Option<u64>,
    ) -> Poll<io::Result<usize>> {
        let mut state = self.lock_state();
        if input.is_empty() {
            clear_waiter(&mut state.writers, waiter_id);
            return Poll::Ready(Ok(0));
        }

        if state.closed {
            clear_waiter(&mut state.writers, waiter_id);
            return Poll::Ready(Err(pipe_error(
                ErrorKind::BrokenPipe,
                &self.name,
                "write: closed",
            )));
        }
        if deadline_elapsed(state.write_deadline) {
            clear_waiter(&mut state.writers, waiter_id);
            let writers = std::mem::take(&mut state.writers);
            drop(state);
            wake_all(writers);
            return Poll::Ready(Err(deadline_error("write")));
        }
        if state.blocked || state.buf.len() == self.max_buf {
            let write_deadline = state.write_deadline;
            if poll_waiter(
                &mut state,
                WaitKind::Write,
                waiter_id,
                cx.waker(),
                write_deadline,
                cx,
            )
            .is_ready()
            {
                clear_waiter(&mut state.writers, waiter_id);
                let writers = std::mem::take(&mut state.writers);
                drop(state);
                wake_all(writers);
                return Poll::Ready(Err(deadline_error("write")));
            }
            return Poll::Pending;
        }

        clear_waiter(&mut state.writers, waiter_id);
        let count = input.len().min(self.max_buf - state.buf.len());
        state.buf.extend(&input[..count]);
        let readers = std::mem::take(&mut state.readers);
        drop(state);
        wake_all(readers);
        Poll::Ready(Ok(count))
    }

    fn lock_state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn poll_deadline(
    timer: &mut Option<Pin<Box<Sleep>>>,
    deadline: Option<Instant>,
    cx: &mut Context<'_>,
) -> Poll<()> {
    let Some(deadline) = deadline else {
        *timer = None;
        return Poll::Pending;
    };
    let timer = timer.get_or_insert_with(|| {
        Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
            deadline,
        )))
    });
    timer.as_mut().poll(cx)
}

fn deadline_elapsed(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| deadline <= Instant::now())
}

fn poll_waiter(
    state: &mut State,
    kind: WaitKind,
    waiter_id: &mut Option<u64>,
    waker: &Waker,
    deadline: Option<Instant>,
    cx: &mut Context<'_>,
) -> Poll<()> {
    let id = waiter_id.unwrap_or_else(|| {
        let id = state.next_waiter_id;
        state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
        *waiter_id = Some(id);
        id
    });
    let waiters = match kind {
        WaitKind::Read => &mut state.readers,
        WaitKind::Write => &mut state.writers,
    };
    let waiter = waiters.entry(id).or_insert_with(|| Waiter {
        waker: waker.clone(),
        timer: None,
    });
    if !waiter.waker.will_wake(waker) {
        waiter.waker.clone_from(waker);
    }
    poll_deadline(&mut waiter.timer, deadline, cx)
}

fn clear_waiter(waiters: &mut HashMap<u64, Waiter>, waiter_id: &mut Option<u64>) {
    if let Some(id) = waiter_id.take() {
        waiters.remove(&id);
    }
}

fn wake_all(waiters: HashMap<u64, Waiter>) {
    for waiter in waiters.into_values() {
        waiter.waker.wake();
    }
}

fn deadline_error(operation: &str) -> io::Error {
    io::Error::new(
        ErrorKind::TimedOut,
        format!("memnet {operation} deadline elapsed"),
    )
}

fn pipe_error(kind: ErrorKind, name: &str, detail: &str) -> io::Error {
    io::Error::new(kind, format!("memnet pipe {name:?}: {detail}"))
}

#[cfg(test)]
mod tests {
    use std::{
        io::ErrorKind,
        sync::Arc,
        time::{Duration, Instant},
    };

    use super::MemPipe;

    const DEADLINE: Duration = Duration::from_secs(1);
    const TEST_TIMEOUT: Duration = Duration::from_secs(3);

    #[tokio::test]
    async fn canceling_latest_waiter_does_not_strand_other_deadlines() {
        let read_pipe = Arc::new(MemPipe::new("cancel-read", 1));
        let first_pipe = Arc::clone(&read_pipe);
        let first_reader = tokio::spawn(async move {
            let mut byte = [0];
            first_pipe.read(&mut byte).await
        });
        while read_pipe.lock_state().readers.len() != 1 {
            tokio::task::yield_now().await;
        }

        read_pipe.set_read_deadline(Some(Instant::now() + DEADLINE));
        while !read_pipe
            .lock_state()
            .readers
            .values()
            .all(|waiter| waiter.timer.is_some())
            || read_pipe.lock_state().readers.len() != 1
        {
            tokio::task::yield_now().await;
        }
        let latest_pipe = Arc::clone(&read_pipe);
        let latest_reader = tokio::spawn(async move {
            let mut byte = [0];
            latest_pipe.read(&mut byte).await
        });
        while read_pipe.lock_state().readers.len() != 2 {
            tokio::task::yield_now().await;
        }
        latest_reader.abort();
        let _ = latest_reader.await;
        assert_eq!(read_pipe.lock_state().readers.len(), 1);

        let error = tokio::time::timeout(TEST_TIMEOUT, first_reader)
            .await
            .expect("first reader was stranded after latest reader cancellation")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);

        let write_pipe = Arc::new(MemPipe::new("cancel-write", 1));
        write_pipe.write(b"x").await.unwrap();
        let first_pipe = Arc::clone(&write_pipe);
        let first_writer = tokio::spawn(async move { first_pipe.write(b"first").await });
        while write_pipe.lock_state().writers.len() != 1 {
            tokio::task::yield_now().await;
        }

        write_pipe.set_write_deadline(Some(Instant::now() + DEADLINE));
        while !write_pipe
            .lock_state()
            .writers
            .values()
            .all(|waiter| waiter.timer.is_some())
            || write_pipe.lock_state().writers.len() != 1
        {
            tokio::task::yield_now().await;
        }
        let latest_pipe = Arc::clone(&write_pipe);
        let latest_writer = tokio::spawn(async move { latest_pipe.write(b"latest").await });
        while write_pipe.lock_state().writers.len() != 2 {
            tokio::task::yield_now().await;
        }
        latest_writer.abort();
        let _ = latest_writer.await;
        assert_eq!(write_pipe.lock_state().writers.len(), 1);

        let error = tokio::time::timeout(TEST_TIMEOUT, first_writer)
            .await
            .expect("first writer was stranded after latest writer cancellation")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }
}
