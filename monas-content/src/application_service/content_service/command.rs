use crate::domain::content::provider::StorageProvider;
use crate::domain::{content::metadata::Metadata, content_id::ContentId};

/// コンテンツ作成ユースケースの入力。
#[derive(Debug)]
pub struct CreateContentCommand {
    /// コンテンツ名
    pub name: String,
    /// 論理パス
    pub path: String,
    /// コンテンツの生データ
    pub raw_content: Vec<u8>,
    /// 保存先のストレージプロバイダー。
    /// `None` の場合はデフォルトプロバイダーに保存される。
    pub provider: Option<StorageProvider>,
}

/// コンテンツ作成ユースケースの出力。
#[derive(Debug)]
pub struct CreateContentResult {
    pub content_id: ContentId,
    pub metadata: Metadata,
    /// コンテンツ暗号化に用いた鍵から導出される公開情報など。
    /// 具体的な意味づけは後続の設計で決める。
    pub public_key: String,
    pub encrypted_content: Vec<u8>,
}

/// コンテンツ更新ユースケースの入力。
#[derive(Debug)]
pub struct UpdateContentCommand {
    pub content_id: ContentId,
    pub new_name: Option<String>,
    pub new_raw_content: Option<Vec<u8>>,
    pub provider: Option<StorageProvider>,
}

/// コンテンツ更新ユースケースの出力。
#[derive(Debug)]
pub struct UpdateContentResult {
    pub content_id: ContentId,
    pub series_id: ContentId,
    pub metadata: Metadata,
    pub encrypted_content: Vec<u8>,
}

/// コンテンツ削除ユースケースの入力。
#[derive(Debug)]
pub struct DeleteContentCommand {
    pub content_id: ContentId,
    pub provider: Option<StorageProvider>,
}

/// コンテンツ削除ユースケースの出力。
#[derive(Debug)]
pub struct DeleteContentResult {
    pub content_id: ContentId,
}

/// 削除済みコンテンツ復元ユースケースの入力。
#[derive(Debug)]
pub struct RestoreDeletedContentCommand {
    pub content_id: ContentId,
    pub name: String,
    pub path: String,
    pub raw_content: Vec<u8>,
    pub provider: Option<StorageProvider>,
}

/// 削除済みコンテンツ復元ユースケースの出力。
#[derive(Debug)]
pub struct RestoreDeletedContentResult {
    pub content_id: ContentId,
    pub metadata: Metadata,
    pub encrypted_content: Vec<u8>,
}

/// コンテンツ取得（fetch）ユースケースの出力。
///
/// - `content_id` は現在のコンテンツ本体を識別する ID（コンテンツアドレス）を表す。
/// - `series_id` は論理的に同一なコンテンツ系列を識別する ID を表す。
/// - `raw_content` は復号済みのコンテンツバイト列を表す。
#[derive(Debug)]
pub struct FetchContentResult {
    pub content_id: ContentId,
    pub series_id: ContentId,
    pub metadata: Metadata,
    pub raw_content: Vec<u8>,
}

/// コンテンツ再暗号化ユースケースの入力。
#[derive(Debug)]
pub struct ReencryptContentCommand {
    pub content_id: ContentId,
}

/// コンテンツ再暗号化ユースケースの出力。
#[derive(Debug)]
pub struct ReencryptContentResult {
    pub encrypted_id: ContentId,
    pub raw_id: ContentId,
    pub metadata: Metadata,
    pub encrypted_content: Vec<u8>,
}
