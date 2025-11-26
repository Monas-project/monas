use crate::application_service::content_service::{
    ContentCreatedOperation, ContentDeletedOperation, ContentUpdatedOperation, StateNodeClient,
    StateNodeClientError,
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

    fn send_content_updated(
        &self,
        _operation: &ContentUpdatedOperation,
    ) -> Result<(), StateNodeClientError> {
        // TODO: 将来的にHTTPクライアントでstate-nodeのAPIを呼ぶ実装に差し替える。
        Ok(())
    }

    fn send_content_deleted(
        &self,
        _operation: &ContentDeletedOperation,
    ) -> Result<(), StateNodeClientError> {
        // TODO: 将来的にHTTPクライアントでstate-nodeのAPIを呼ぶ実装に差し替える。
        Ok(())
    }
}
