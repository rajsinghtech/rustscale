use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_os = "windows")]
use std::sync::LazyLock;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use crate::{
    dedup_serials, is_sentinel_serial, CollectionContext, PostureError, MAX_SERIALS, MAX_SERIAL_LEN,
};

#[cfg(target_os = "windows")]
const WMI_TIMEOUT: Duration = Duration::from_secs(2);
const SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(target_os = "windows")]
const MAX_WMI_WORKERS: usize = 2;

const SERIAL_QUERIES: [&str; 3] = [
    "SELECT SerialNumber FROM Win32_BIOS",
    "SELECT SerialNumber FROM Win32_BaseBoard",
    "SELECT SerialNumber FROM Win32_SystemEnclosure",
];

#[cfg(target_os = "windows")]
static WMI_WORKERS: LazyLock<Arc<WorkerLimiter>> =
    LazyLock::new(|| Arc::new(WorkerLimiter::new(MAX_WMI_WORKERS)));

#[cfg(target_os = "windows")]
#[derive(Debug, serde::Deserialize)]
#[allow(non_snake_case)]
struct SerialRow {
    SerialNumber: Option<String>,
}

trait WmiSerialSource {
    fn serial_rows(&self) -> Result<[Vec<Option<String>>; 3], PostureError>;
}

#[cfg(target_os = "windows")]
struct SystemWmiSource;

#[cfg(target_os = "windows")]
impl WmiSerialSource for SystemWmiSource {
    fn serial_rows(&self) -> Result<[Vec<Option<String>>; 3], PostureError> {
        let connection =
            wmi::WMIConnection::new().map_err(|_| PostureError::Io(std::io::ErrorKind::Other))?;
        let query = |query: &str| {
            connection
                .raw_query::<SerialRow>(query)
                .map(|rows| rows.into_iter().map(|row| row.SerialNumber).collect())
                .map_err(|_| PostureError::Io(std::io::ErrorKind::Other))
        };
        Ok([
            query(SERIAL_QUERIES[0])?,
            query(SERIAL_QUERIES[1])?,
            query(SERIAL_QUERIES[2])?,
        ])
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn get_serial_numbers_impl(
    context: &CollectionContext,
) -> Result<Vec<String>, PostureError> {
    let context = context.bounded(WMI_TIMEOUT);
    run_supervised_with_limiter(&context, WMI_WORKERS.clone(), || {
        collect_from_source(&SystemWmiSource)
    })
}

fn collect_from_source(source: &dyn WmiSerialSource) -> Result<Vec<String>, PostureError> {
    normalize_serial_rows(source.serial_rows()?)
}

fn normalize_serial_rows(
    rows_by_class: [Vec<Option<String>>; 3],
) -> Result<Vec<String>, PostureError> {
    let row_count = rows_by_class.iter().try_fold(0_usize, |total, rows| {
        total
            .checked_add(rows.len())
            .ok_or(PostureError::InvalidData)
    })?;
    if row_count > MAX_SERIALS {
        return Err(PostureError::InvalidData);
    }

    let mut serials = Vec::with_capacity(row_count);
    for rows in rows_by_class {
        for serial in rows.into_iter().flatten() {
            let serial = serial.trim();
            if is_sentinel_serial(serial) {
                continue;
            }
            if serial.len() > MAX_SERIAL_LEN || serial.chars().any(char::is_control) {
                return Err(PostureError::InvalidData);
            }
            serials.push(serial.to_owned());
        }
    }

    let serials = dedup_serials(serials);
    if serials.is_empty() {
        Err(PostureError::CollectionFailed)
    } else {
        Ok(serials)
    }
}

struct WorkerLimiter {
    active: AtomicUsize,
    maximum: usize,
}

impl WorkerLimiter {
    const fn new(maximum: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            maximum,
        }
    }

    fn acquire(self: &Arc<Self>) -> Result<WorkerPermit, PostureError> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.maximum).then_some(active + 1)
            })
            .map_err(|_| PostureError::WorkerCapacity)?;
        Ok(WorkerPermit {
            limiter: self.clone(),
        })
    }
}

struct WorkerPermit {
    limiter: Arc<WorkerLimiter>,
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn run_supervised_with_limiter<T, F>(
    context: &CollectionContext,
    limiter: Arc<WorkerLimiter>,
    work: F,
) -> Result<T, PostureError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, PostureError> + Send + 'static,
{
    context.check()?;
    let permit = limiter.acquire()?;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("rustscale-posture-wmi".into())
        .spawn(move || {
            let result = work();
            drop(permit);
            let _ = sender.send(result);
        })?;

    loop {
        let wait = context.wait_slice(SUPERVISOR_POLL_INTERVAL)?;
        match receiver.recv_timeout(wait) {
            Ok(result) => {
                context.check()?;
                return result;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(PostureError::WorkerTerminated);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use tokio_util::sync::CancellationToken;

    use super::*;

    struct FixtureSource([Vec<Option<String>>; 3]);

    impl WmiSerialSource for FixtureSource {
        fn serial_rows(&self) -> Result<[Vec<Option<String>>; 3], PostureError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn queries_three_smbios_backed_classes_in_upstream_order() {
        assert_eq!(
            SERIAL_QUERIES,
            [
                "SELECT SerialNumber FROM Win32_BIOS",
                "SELECT SerialNumber FROM Win32_BaseBoard",
                "SELECT SerialNumber FROM Win32_SystemEnclosure",
            ]
        );
        let source = FixtureSource([
            vec![Some(" product-東京 ".into())],
            vec![Some("baseboard-é".into()), Some("product-東京".into())],
            vec![Some("châssis".into())],
        ]);
        assert_eq!(
            collect_from_source(&source),
            Ok(vec![
                "product-東京".into(),
                "baseboard-é".into(),
                "châssis".into(),
            ])
        );
    }

    #[test]
    fn missing_placeholders_duplicates_and_malformed_values_are_bounded() {
        let source = FixtureSource([
            vec![None, Some("To Be Filled By O.E.M.".into())],
            vec![Some("serial".into()), Some("serial".into())],
            vec![Some("Default string".into())],
        ]);
        assert_eq!(collect_from_source(&source), Ok(vec!["serial".into()]));

        let malformed =
            FixtureSource([vec![Some("serial\0suffix".into())], Vec::new(), Vec::new()]);
        assert_eq!(
            collect_from_source(&malformed),
            Err(PostureError::InvalidData)
        );

        let too_many = FixtureSource([
            vec![Some("x".into()); MAX_SERIALS + 1],
            Vec::new(),
            Vec::new(),
        ]);
        assert_eq!(
            collect_from_source(&too_many),
            Err(PostureError::InvalidData)
        );
    }

    #[test]
    fn cancellation_returns_promptly_while_worker_retains_its_permit() {
        let limiter = Arc::new(WorkerLimiter::new(1));
        let cancellation = CancellationToken::new();
        let context = CollectionContext::new(
            Some(Instant::now() + Duration::from_secs(5)),
            cancellation.clone(),
        );
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let cancel_thread = std::thread::spawn(move || {
            entered_rx.recv().unwrap();
            cancellation.cancel();
        });

        let started = Instant::now();
        let result = run_supervised_with_limiter(&context, limiter.clone(), move || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok::<_, PostureError>(())
        });
        assert_eq!(result, Err(PostureError::Cancelled));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(limiter.active.load(Ordering::Acquire), 1);
        assert_eq!(limiter.acquire().err(), Some(PostureError::WorkerCapacity));

        release_tx.send(()).unwrap();
        cancel_thread.join().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while limiter.active.load(Ordering::Acquire) != 0 {
            assert!(Instant::now() < deadline, "worker did not release permit");
            std::thread::yield_now();
        }
    }

    #[test]
    fn noncooperative_workers_are_globally_bounded_and_future_calls_fail_closed() {
        let limiter = Arc::new(WorkerLimiter::new(2));
        let releases = Arc::new(Mutex::new(Vec::new()));

        for _ in 0..2 {
            // Acquire directly to model workers that outlive cancelled callers.
            let permit = limiter.acquire().unwrap();
            let (release_tx, release_rx) = mpsc::sync_channel(1);
            releases.lock().unwrap().push(release_tx);
            std::thread::spawn(move || {
                release_rx.recv().unwrap();
                drop(permit);
            });
        }

        assert_eq!(limiter.active.load(Ordering::Acquire), 2);
        assert_eq!(limiter.acquire().err(), Some(PostureError::WorkerCapacity));
        for release in releases.lock().unwrap().drain(..) {
            release.send(()).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        while limiter.active.load(Ordering::Acquire) != 0 {
            assert!(Instant::now() < deadline, "fixture workers remained stuck");
            std::thread::yield_now();
        }
    }
}
