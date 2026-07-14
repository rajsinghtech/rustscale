use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const BLOCK_SIZE: usize = 2_097_152;
pub const MIN_DURATION: Duration = Duration::from_secs(5);
pub const DEFAULT_DURATION: Duration = Duration::from_secs(5);
pub const MAX_DURATION: Duration = Duration::from_secs(30);
pub const INCREMENT: Duration = Duration::from_secs(1);
pub const MIN_INTERVAL: Duration = Duration::from_millis(10);
pub const DEFAULT_PORT: u16 = 20333;
pub const PROTOCOL_VERSION: i32 = 2;

/// Data-flow direction from the perspective of the endpoint running a test.
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
        let value = match self {
            Self::Download => 0_u8,
            Self::Upload => 1_u8,
        };
        serializer.serialize_u8(value)
    }
}

impl<'de> Deserialize<'de> for Direction {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
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

/// Client-to-server handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub version: i32,
    #[serde(rename = "time")]
    pub test_duration_ns: u64,
    pub direction: Direction,
}

/// Server-to-client handshake response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
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
    /// Duration of this result interval in seconds.
    pub fn interval_secs(&self) -> f64 {
        self.interval_end
            .duration_since(self.interval_start)
            .as_secs_f64()
    }

    /// Transferred data in decimal megabytes.
    pub fn megabytes(&self) -> f64 {
        self.bytes as f64 / 1_000_000.0
    }

    /// Transferred data in decimal megabits.
    pub fn megabits(&self) -> f64 {
        self.megabytes() * 8.0
    }

    /// Bandwidth in decimal megabits per second.
    pub fn mbits_per_sec(&self) -> f64 {
        let secs = self.interval_secs();
        if secs <= 0.0 {
            0.0
        } else {
            self.megabits() / secs
        }
    }
}
