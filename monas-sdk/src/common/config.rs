use std::time::Duration;

/// SDK の設定値。
///
/// State Node / Account の接続先 URL と、HTTP 呼び出しのリクエストタイムアウトを保持する。
/// `#[non_exhaustive]` を付けているため、将来フィールドを追加しても SemVer 非破壊。
///
/// # Example
/// ```ignore
/// use std::time::Duration;
/// use monas_sdk::{MonasConfig, MonasController};
///
/// let config = MonasConfig::new("http://127.0.0.1:8080", "http://127.0.0.1:4002")
///     .with_request_timeout(Duration::from_secs(30));
/// let controller = MonasController::with_config(config);
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MonasConfig {
    /// State Node のベース URL
    pub state_node_url: String,
    /// Account (issuer) のベース URL
    pub account_url: String,
    /// HTTP 呼び出し全体のタイムアウト (connect + read + write の合計上限)
    pub request_timeout: Duration,
}

/// `MonasConfig` の既定タイムアウト。
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

impl MonasConfig {
    /// 最小限の設定で `MonasConfig` を生成する。タイムアウトは `DEFAULT_REQUEST_TIMEOUT`。
    pub fn new(state_node_url: impl Into<String>, account_url: impl Into<String>) -> Self {
        Self {
            state_node_url: state_node_url.into(),
            account_url: account_url.into(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }

    /// リクエストタイムアウトを差し替える。
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_uses_default_timeout() {
        let cfg = MonasConfig::new("http://a", "http://b");
        assert_eq!(cfg.request_timeout, DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(cfg.state_node_url, "http://a");
        assert_eq!(cfg.account_url, "http://b");
    }

    #[test]
    fn with_request_timeout_overrides() {
        let cfg =
            MonasConfig::new("http://a", "http://b").with_request_timeout(Duration::from_secs(1));
        assert_eq!(cfg.request_timeout, Duration::from_secs(1));
    }
}
