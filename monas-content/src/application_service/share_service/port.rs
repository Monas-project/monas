use crate::application_service::content_service::{
    ContentEncryptionKeyStoreError, ContentRepositoryError,
};
use crate::domain::content_id::ContentId;
use crate::domain::share::{KeyId, Share, ShareError};

/// 共有状態（ACL）を永続化するためのポート。
///
/// - key: `content_id`
/// - value: そのコンテンツに対する `Share`
pub trait ShareRepository {
    fn load(&self, content_id: &ContentId) -> Result<Option<Share>, ShareRepositoryError>;

    fn save(&self, share: &Share) -> Result<(), ShareRepositoryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ShareRepositoryError {
    #[error("storage error: {0}")]
    Storage(String),
}

/// KeyId と HPKE 用公開鍵バイト列を管理するためのポート。
///
/// - 実装は、ローカルのキーストア / State Node / 外部 KMS などを想定。
pub trait PublicKeyDirectory {
    /// 新しい公開鍵を登録し、対応する KeyId を返す。
    fn register_public_key(&self, public_key: &[u8]) -> Result<KeyId, PublicKeyDirectoryError>;

    /// 既存の KeyId から公開鍵バイト列を取得する。
    fn find_public_key(&self, key_id: &KeyId) -> Result<Option<Vec<u8>>, PublicKeyDirectoryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum PublicKeyDirectoryError {
    #[error("lookup error: {0}")]
    Lookup(String),
}

/// Share 用アプリケーションサービスで発生しうるエラー。
#[derive(Debug, thiserror::Error)]
pub enum ShareApplicationError {
    #[error("content not found")]
    ContentNotFound,

    #[error("content is deleted")]
    ContentDeleted,

    #[error("missing encrypted content for content")]
    MissingEncryptedContent,

    #[error("missing CEK for content")]
    MissingContentEncryptionKey,

    #[error("share domain error: {0:?}")]
    Share(ShareError),

    #[error("content repository error: {0}")]
    ContentRepository(ContentRepositoryError),

    #[error("CEK store error: {0}")]
    ContentEncryptionKeyStore(ContentEncryptionKeyStoreError),

    #[error("share repository error: {0}")]
    ShareRepository(ShareRepositoryError),

    #[error("public key directory error: {0}")]
    PublicKeyDirectory(PublicKeyDirectoryError),

    #[error("missing public key for key_id")]
    MissingPublicKey,

    #[error("key wrapping error: {0}")]
    KeyWrapping(String),
}
