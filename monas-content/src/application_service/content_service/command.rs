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
    /// 作成した版の plainCid。
    pub content_id: ContentId,
    /// ファイルのキー。以後の操作はこれで対象を指定する。
    pub series_id: ContentId,
    pub metadata: Metadata,
    /// コンテンツ暗号化に用いた鍵から導出される公開情報など。
    /// 具体的な意味づけは後続の設計で決める。
    pub public_key: String,
    pub encrypted_content: Vec<u8>,
}

/// コンテンツ更新ユースケースの入力。
#[derive(Debug)]
pub struct UpdateContentCommand {
    /// 対象ファイルのキー(`series_id`)。
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
    /// 対象ファイルのキー(`series_id`)。
    pub content_id: ContentId,
    pub provider: Option<StorageProvider>,
}

/// コンテンツ削除ユースケースの出力。
#[derive(Debug)]
pub struct DeleteContentResult {
    pub content_id: ContentId,
}

/// コンテンツ取得（fetch）ユースケースの出力。
///
/// - `content_id` は今の版の本文を識別する ID（plainCid）を表す。
/// - `series_id` はファイルのキー(作成時に決まり、以後変わらない)を表す。
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
    /// 対象ファイルのキー(`series_id`)。
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
