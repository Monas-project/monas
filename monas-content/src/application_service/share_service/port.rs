use crate::application_service::content_service::{
    ContentEncryptionKeyStoreError, ContentRepositoryError,
};
use crate::domain::content_id::ContentId;
use crate::domain::share::{KeyId, Share, ShareError};

/// 共有状態（ACL）を永続化するためのポート。
///
/// - key: コンテンツの系列ID(`Content::series_id`)。`Share::content_id` もこの値。
/// - value: そのコンテンツ(ファイル)に対する `Share`
///
/// 共有設定はファイル単位で 1 つ。plainCid(平文のコンテンツアドレス)ごとに
/// 持つと、本文を以前と同じ内容に戻したときにその plainCid に残っていた古い
/// 設定を拾ってしまう(降格・取り消しが戻る)。
pub trait ShareRepository {
    fn load(&self, series_id: &ContentId) -> Result<Option<Share>, ShareRepositoryError>;

    fn save(&self, share: &Share) -> Result<(), ShareRepositoryError>;

    /// 系列IDで保存するようになる前の、plainCid をキーにした共有設定を読む。
    ///
    /// 既存の永続化データを一度だけ移すためにだけ使う
    /// (`ShareService` が系列IDのキーに無いときに読み、系列IDで保存し直す)。
    /// 旧形式のデータを持ち得ない実装(インメモリ等)は既定の `None` のままでよい。
    fn load_legacy(
        &self,
        _plain_content_id: &ContentId,
    ) -> Result<Option<Share>, ShareRepositoryError> {
        Ok(None)
    }
}

/// `Arc<dyn ShareRepository + Send + Sync>` を `ShareService` の型パラメータに
/// 直接渡せるようにする blanket impl。
impl<T: ShareRepository + ?Sized> ShareRepository for std::sync::Arc<T> {
    fn load(&self, series_id: &ContentId) -> Result<Option<Share>, ShareRepositoryError> {
        (**self).load(series_id)
    }

    fn save(&self, share: &Share) -> Result<(), ShareRepositoryError> {
        (**self).save(share)
    }

    fn load_legacy(
        &self,
        plain_content_id: &ContentId,
    ) -> Result<Option<Share>, ShareRepositoryError> {
        (**self).load_legacy(plain_content_id)
    }
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
    /// 公開鍵から KeyId を計算する（副作用なし）。
    ///
    /// - この操作は永続化を行わず、KeyId の計算のみを行う。
    /// - 検証や事前計算に使用する。
    fn compute_key_id(&self, public_key: &[u8]) -> KeyId;

    /// 新しい公開鍵を登録し、対応する KeyId を返す。
    fn register_public_key(&self, public_key: &[u8]) -> Result<KeyId, PublicKeyDirectoryError>;

    /// 既存の KeyId から公開鍵バイト列を取得する。
    fn find_public_key(&self, key_id: &KeyId) -> Result<Option<Vec<u8>>, PublicKeyDirectoryError>;

    /// 指定された KeyId の公開鍵を削除する。
    ///
    /// - 補償トランザクション（ロールバック）に使用する。
    /// - 存在しない KeyId を削除しようとしてもエラーにならない（冪等）。
    fn delete_public_key(&self, key_id: &KeyId) -> Result<(), PublicKeyDirectoryError>;
}

/// `Arc<dyn PublicKeyDirectory + Send + Sync>` を `ShareService` の型パラメータに
/// 直接渡せるようにする blanket impl。
impl<T: PublicKeyDirectory + ?Sized> PublicKeyDirectory for std::sync::Arc<T> {
    fn compute_key_id(&self, public_key: &[u8]) -> KeyId {
        (**self).compute_key_id(public_key)
    }

    fn register_public_key(&self, public_key: &[u8]) -> Result<KeyId, PublicKeyDirectoryError> {
        (**self).register_public_key(public_key)
    }

    fn find_public_key(&self, key_id: &KeyId) -> Result<Option<Vec<u8>>, PublicKeyDirectoryError> {
        (**self).find_public_key(key_id)
    }

    fn delete_public_key(&self, key_id: &KeyId) -> Result<(), PublicKeyDirectoryError> {
        (**self).delete_public_key(key_id)
    }
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
