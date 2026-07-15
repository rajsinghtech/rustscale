use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Size of each unframed data block on the wire.
pub const BLOCK_SIZE: usize = 2 * 1024 * 1024;
/// Smallest test accepted by either endpoint.
pub const MIN_DURATION: Duration = Duration::from_secs(5);
/// Upstream's default test duration.
pub const DEFAULT_DURATION: Duration = MIN_DURATION;
/// Largest test accepted by either endpoint.
pub const MAX_DURATION: Duration = Duration::from_secs(30);
/// Target reporting interval.
pub const INCREMENT: Duration = Duration::from_secs(1);
/// Final intervals no longer than this are omitted.
pub const MIN_INTERVAL: Duration = Duration::from_millis(10);
/// Default TCP port used by the standalone upstream speedtest command.
pub const DEFAULT_PORT: u16 = 20333;
/// Tailscale speedtest protocol version.
pub const PROTOCOL_VERSION: i32 = 2;
/// Largest JSON control frame, excluding its newline delimiter.
pub const MAX_CONTROL_FRAME_SIZE: usize = 1024;
/// Maximum number of interval and total results from one bounded test.
pub const MAX_RESULT_COUNT: usize = 40;

/// Data-flow direction from the perspective of an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Download,
    Upload,
}

impl Serialize for Direction {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(match self {
            Self::Download => 0,
            Self::Upload => 1,
        })
    }
}

impl<'de> Deserialize<'de> for Direction {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match i64::deserialize(deserializer)? {
            0 => Ok(Self::Download),
            1 => Ok(Self::Upload),
            value => Err(serde::de::Error::custom(format!(
                "invalid speedtest direction: {value}"
            ))),
        }
    }
}

impl Direction {
    pub(crate) const fn reverse(self) -> Self {
        match self {
            Self::Download => Self::Upload,
            Self::Upload => Self::Download,
        }
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Download => "download",
            Self::Upload => "upload",
        })
    }
}

/// Client-to-server newline-delimited JSON handshake.
///
/// The declaration order is wire-significant for byte-for-byte parity with
/// Go's `encoding/json` output for the upstream struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub version: i32,
    #[serde(rename = "time")]
    pub test_duration_ns: i64,
    pub direction: Direction,
}

#[allow(clippy::ref_option)] // serde's skip_serializing_if callback receives &T.
fn response_error_is_empty(error: &Option<String>) -> bool {
    error.as_deref().is_none_or(str::is_empty)
}

/// Server-to-client newline-delimited JSON handshake response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigResponse {
    /// An absent, null, or empty error means that the test was accepted.
    #[serde(default, skip_serializing_if = "response_error_is_empty")]
    pub error: Option<String>,
}

/// One throughput interval or the total summary.
#[derive(Debug, Clone)]
pub struct Result {
    pub bytes: u64,
    pub interval_start: tokio::time::Instant,
    pub interval_end: tokio::time::Instant,
    pub is_total: bool,
}

impl Result {
    /// Duration of this result interval.
    pub fn interval(&self) -> Duration {
        self.interval_end.duration_since(self.interval_start)
    }

    /// Duration of this result interval in seconds.
    pub fn interval_secs(&self) -> f64 {
        self.interval().as_secs_f64()
    }

    /// Transferred data in decimal megabytes, matching upstream.
    pub fn megabytes(&self) -> f64 {
        self.bytes as f64 / 1_000_000.0
    }

    /// Transferred data in decimal megabits, matching upstream.
    pub fn megabits(&self) -> f64 {
        self.megabytes() * 8.0
    }

    /// Bandwidth in decimal megabits per second.
    pub fn mbits_per_sec(&self) -> f64 {
        self.megabits() / self.interval_secs()
    }
}
