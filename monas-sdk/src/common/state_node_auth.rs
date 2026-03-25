/// State Node 連携で利用する認証コンテキスト。
///
/// Gateway が受け取ったヘッダを SDK へ透過し、State Node 呼び出し時に再設定する。
#[derive(Debug, Clone, Default)]
pub struct StateNodeAuthContext {
    pub authorization: Option<String>,
    pub request_signature: Option<String>,
    pub request_timestamp: Option<u64>,
}
