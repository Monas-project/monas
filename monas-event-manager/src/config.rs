//! Subscriber configuration

use std::time::Duration;

/// Configuration for event subscribers
#[derive(Debug, Clone)]
pub struct SubscriberConfig {
    /// Maximum number of retries
    pub max_retries: u32,
    /// Retry delay in seconds
    pub retry_delay_secs: u64,
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
}

impl Default for SubscriberConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay_secs: 5,
            connection_timeout_secs: 30,
            heartbeat_interval_secs: 10,
        }
    }
}

impl SubscriberConfig {
    /// Returns the retry delay as a `Duration`
    pub fn retry_delay(&self) -> Duration {
        Duration::from_secs(self.retry_delay_secs)
    }

    /// Returns the connection timeout as a `Duration`
    pub fn connection_timeout(&self) -> Duration {
        Duration::from_secs(self.connection_timeout_secs)
    }

    /// Returns the heartbeat interval as a `Duration`
    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.heartbeat_interval_secs)
    }
}