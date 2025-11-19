use crate::application_service::content_service::{
    ContentCreatedOperation, StateNodeClient, StateNodeClientError,
};

/// v1 用のダミー StateNodeClient 実装。
/// 実際には何も送信せず、ログ出力だけ行う。
#[derive(Clone, Default)]
pub struct NoopStateNodeClient;

impl StateNodeClient for NoopStateNodeClient {
    fn send_content_created(
        &self,
        _operation: &ContentCreatedOperation,
    ) -> Result<(), StateNodeClientError> {
        // TODO: 将来的にHTTPクライアントでstate-nodeのAPIを呼ぶ実装に差し替える。
        Ok(())
    }
}
