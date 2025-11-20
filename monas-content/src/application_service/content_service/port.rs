use crate::domain::{content::Content, content_id::ContentId, encryption::ContentEncryptionKey};

/// コンテンツを永続化するポート。
pub trait ContentRepository {
    fn save(&self, content_id: &ContentId, content: &Content)
        -> Result<(), ContentRepositoryError>;
    fn find_by_id(&self, content_id: &ContentId)
        -> Result<Option<Content>, ContentRepositoryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ContentRepositoryError {
    #[error("storage error: {0}")]
    Storage(String),
}

/// CEK（コンテンツ暗号化鍵）を保存・取得・削除するためのポート。
///
/// - 実装は infra 層（インメモリ / sled / その他のKVS など）に置く。
/// - application 層では、このポート越しにのみ CEK にアクセスする。
pub trait ContentEncryptionKeyStore {
    fn save(
        &self,
        content_id: &ContentId,
        key: &ContentEncryptionKey,
    ) -> Result<(), ContentEncryptionKeyStoreError>;

    fn load(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<ContentEncryptionKey>, ContentEncryptionKeyStoreError>;

    fn delete(&self, content_id: &ContentId) -> Result<(), ContentEncryptionKeyStoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ContentEncryptionKeyStoreError {
    #[error("storage error: {0}")]
    Storage(String),
}

/// state-node へ Operation を送信するポート。
pub trait StateNodeClient {
    fn send_content_created(
        &self,
        operation: &ContentCreatedOperation,
    ) -> Result<(), StateNodeClientError>;
    fn send_content_updated(
        &self,
        operation: &ContentUpdatedOperation,
    ) -> Result<(), StateNodeClientError>;
    fn send_content_deleted(
        &self,
        operation: &ContentDeletedOperation,
    ) -> Result<(), StateNodeClientError>;
}

#[derive(Debug, thiserror::Error)]
pub enum StateNodeClientError {
    #[error("network error: {0}")]
    Network(String),
}

/// state-node に送る「コンテンツ作成」Operation のDTO（アプリケーション層側の表現）。
pub struct ContentCreatedOperation {
    pub content_id: ContentId,
    pub hash: String,
    pub path: String,
    pub public_key: String,
    // TODO: 必要に応じて nodes や license などを追加。
}

/// state-node に送る「コンテンツ削除」Operation のDTO（アプリケーション層側の表現）。
pub struct ContentDeletedOperation {
    pub content_id: ContentId,
    pub path: String,
}

/// state-node に送る「コンテンツ更新」Operation のDTO（アプリケーション層側の表現）。
pub struct ContentUpdatedOperation {
    pub content_id: ContentId,
    pub hash: String,
    pub path: String,
}
