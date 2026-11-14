use std::path::PathBuf;
use std::time::Duration;

/// Selection of the SDK's local persistence backend.
///
/// Determines how the CEK store and share (Share) repository held locally by `MonasController`
/// are persisted.
///
/// - `InMemory`: in-process memory only. Data is lost on restart.
///   For development, testing, and PoC use. If used in a production gateway, existing content
///   becomes undecryptable the moment it restarts.
/// - `Sled { dir }`: opens a sled DB under the given directory and stores CEKs and Shares there.
///   The intended production setup, able to retain CEKs across process restarts.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum PersistenceConfig {
    /// In-memory backend. Default for tests.
    #[default]
    InMemory,
    /// sled-backed backend. Opens the DB under the given directory.
    Sled { dir: PathBuf },
}

/// SDK configuration.
///
/// Holds the State Node URL, HTTP timeout, and local persistence backend.
/// Signing and delegation are done by the in-SDK `AccountService`, not via HTTP to an account
/// process.
/// Marked `#[non_exhaustive]`, so adding fields in the future is SemVer-compatible.
///
/// # Example
/// ```ignore
/// use std::path::PathBuf;
/// use std::time::Duration;
/// use monas_sdk::{MonasConfig, MonasController, PersistenceConfig};
///
/// let config = MonasConfig::new("http://127.0.0.1:8080")
///     .with_request_timeout(Duration::from_secs(30))
///     .with_persistence_dir(PathBuf::from("/var/lib/monas-sdk"));
/// let controller = MonasController::with_config(config).expect("open persistence");
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MonasConfig {
    /// State Node base URL
    pub state_node_url: String,
    /// Timeout for the whole HTTP call (total cap on connect + read + write)
    pub request_timeout: Duration,
    /// Local persistence backend (CEK + Share)
    pub persistence: PersistenceConfig,
    /// Allowed skew of the `X-Request-Timestamp` forwarded from the gateway.
    ///
    /// The SDK verifies `|now - ts| <= skew` in `prepare_state_node_*_auth` before signing. If
    /// out of range it returns `ApiError::Unauthorized`, placing a replay defense line in the SDK.
    /// The State Node should also do a window check, but verifying on both sides is safer.
    pub request_timestamp_skew: Duration,
}

/// Default timeout for `MonasConfig`.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timestamp skew for `MonasConfig` (60 seconds).
///
/// Tolerates realistic inter-node clock sync error (a few seconds to tens of seconds) while
/// rejecting timestamps that are off by several minutes or more.
pub const DEFAULT_REQUEST_TIMESTAMP_SKEW: Duration = Duration::from_secs(60);

impl MonasConfig {
    /// Create a `MonasConfig` with minimal settings. Timeout is `DEFAULT_REQUEST_TIMEOUT`,
    /// persistence is `InMemory` (default for tests), and skew is `DEFAULT_REQUEST_TIMESTAMP_SKEW`.
    pub fn new(state_node_url: impl Into<String>) -> Self {
        Self {
            state_node_url: state_node_url.into(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            persistence: PersistenceConfig::InMemory,
            request_timestamp_skew: DEFAULT_REQUEST_TIMESTAMP_SKEW,
        }
    }

    /// Replace the request timeout.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Switch the persistence backend to sled.
    ///
    /// Opens a sled DB under the given directory and stores CEKs and Shares there.
    /// A production gateway must pass the persistence location explicitly via this method.
    pub fn with_persistence_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.persistence = PersistenceConfig::Sled { dir: dir.into() };
        self
    }

    /// Replace the persistence backend with an arbitrary `PersistenceConfig`.
    pub fn with_persistence(mut self, persistence: PersistenceConfig) -> Self {
        self.persistence = persistence;
        self
    }

    /// Replace the allowed skew for `X-Request-Timestamp`.
    pub fn with_request_timestamp_skew(mut self, skew: Duration) -> Self {
        self.request_timestamp_skew = skew;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_uses_default_timeout() {
        let cfg = MonasConfig::new("http://a");
        assert_eq!(cfg.request_timeout, DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(cfg.state_node_url, "http://a");
    }

    #[test]
    fn with_request_timeout_overrides() {
        let cfg = MonasConfig::new("http://a").with_request_timeout(Duration::from_secs(1));
        assert_eq!(cfg.request_timeout, Duration::from_secs(1));
    }
}
