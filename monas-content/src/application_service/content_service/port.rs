use crate::domain::{
    content::encryption::ContentEncryptionKey, content::Content, content_id::ContentId,
};

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
