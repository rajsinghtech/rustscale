//! `log` facade adapter for [`crate::LogTail`].

use std::io::Write;

use ::log::{LevelFilter, Log, Metadata, Record};

use crate::LogTail;

/// Mirrors `log` facade records to stderr and the logtail buffer.
#[derive(Clone)]
pub struct LogtailLogger {
    logtail: LogTail,
    level: LevelFilter,
}

impl LogtailLogger {
    /// Create an adapter with the supplied maximum level.
    pub fn new(logtail: LogTail, level: LevelFilter) -> Self {
        Self { logtail, level }
    }
}

impl Log for LogtailLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.level >= metadata.level().to_level_filter()
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let text = format!("{} {}: {}", record.level(), record.target(), record.args());
        let _ = writeln!(std::io::stderr(), "{text}");
        self.logtail.write(&text);
    }

    fn flush(&self) {
        self.logtail.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_buffered_with_level_gating() {
        let logtail = LogTail::new(crate::Config::default());
        let logger = LogtailLogger::new(logtail.clone(), LevelFilter::Warn);
        let info = Record::builder()
            .args(format_args!("info message"))
            .level(::log::Level::Info)
            .target("test")
            .build();
        logger.log(&info);
        assert_eq!(logtail.buffered_count(), 0);

        let warning = Record::builder()
            .args(format_args!("warning message"))
            .level(::log::Level::Warn)
            .target("test")
            .build();
        logger.log(&warning);
        assert_eq!(logtail.buffered_count(), 1);
    }
}
