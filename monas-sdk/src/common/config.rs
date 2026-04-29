use std::path::PathBuf;
use std::time::Duration;

/// SDK のローカル persistence backend 選択。
///
/// `MonasController` がローカルに持つ CEK ストアと共有 (Share) リポジトリの
/// 永続化方式を決定する。
///
/// - `InMemory`: プロセス内メモリのみ。再起動でデータが揮発する。
///   開発・テスト・PoC 用途。本番 gateway で使うと、再起動した瞬間に
///   既存コンテンツが復号不能になる。
/// - `Sled { dir }`: 指定ディレクトリ配下に sled DB を開いて CEK と Share を保存する。
///   プロセス再起動を跨いで CEK を保持できる本番想定の構成。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PersistenceConfig {
    /// In-memory backend. テスト用既定値。
    InMemory,
    /// sled-backed backend. 指定ディレクトリ配下に DB を開く。
    Sled { dir: PathBuf },
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self::InMemory
    }
}

/// SDK の設定値。
///
/// State Node / Account の接続先 URL、HTTP タイムアウト、ローカル persistence backend を保持する。
/// `#[non_exhaustive]` を付けているため、将来フィールドを追加しても SemVer 非破壊。
///
/// # Example
/// ```ignore
/// use std::path::PathBuf;
/// use std::time::Duration;
/// use monas_sdk::{MonasConfig, MonasController, PersistenceConfig};
///
/// let config = MonasConfig::new("http://127.0.0.1:8080", "http://127.0.0.1:4002")
///     .with_request_timeout(Duration::from_secs(30))
///     .with_persistence_dir(PathBuf::from("/var/lib/monas-sdk"));
/// let controller = MonasController::with_config(config).expect("open persistence");
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
    /// ローカル persistence backend (CEK + Share)
    pub persistence: PersistenceConfig,
    /// Gateway 側から転送された `X-Request-Timestamp` の許容ズレ幅。
    ///
    /// SDK は `prepare_state_node_*_auth` で `|now - ts| <= skew` を検証してから
    /// 署名する。範囲外なら `ApiError::Unauthorized` を返し、リプレイ防御線を SDK に置く。
    /// State Node 側でも window check されているはずだが、両側で検証する方が安全。
    pub request_timestamp_skew: Duration,
}

/// `MonasConfig` の既定タイムアウト。
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// `MonasConfig` の既定 timestamp skew (60 秒)。
///
/// ノード間時刻同期の現実的な誤差 (数秒〜数十秒) を許容しつつ、
/// 数分以上ずれた timestamp は受け付けない。
pub const DEFAULT_REQUEST_TIMESTAMP_SKEW: Duration = Duration::from_secs(60);

impl MonasConfig {
    /// 最小限の設定で `MonasConfig` を生成する。タイムアウトは `DEFAULT_REQUEST_TIMEOUT`、
    /// persistence は `InMemory` (テスト用既定値)、skew は `DEFAULT_REQUEST_TIMESTAMP_SKEW`。
    pub fn new(state_node_url: impl Into<String>, account_url: impl Into<String>) -> Self {
        Self {
            state_node_url: state_node_url.into(),
            account_url: account_url.into(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            persistence: PersistenceConfig::InMemory,
            request_timestamp_skew: DEFAULT_REQUEST_TIMESTAMP_SKEW,
        }
    }

    /// リクエストタイムアウトを差し替える。
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// persistence backend を sled に切り替える。
    ///
    /// 指定ディレクトリ配下に sled DB を開いて CEK と Share を保存する。
    /// 本番 gateway はこのメソッドで明示的に永続化先を渡すこと。
    pub fn with_persistence_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.persistence = PersistenceConfig::Sled { dir: dir.into() };
        self
    }

    /// persistence backend を任意の `PersistenceConfig` に差し替える。
    pub fn with_persistence(mut self, persistence: PersistenceConfig) -> Self {
        self.persistence = persistence;
        self
    }

    /// `X-Request-Timestamp` の許容 skew を差し替える。
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
