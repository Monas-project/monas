use crate::domain::{content_id::ContentId, metadata::Metadata};

/// コンテンツ作成ユースケースの入力。
#[derive(Debug)]
pub struct CreateContentCommand {
    pub name: String,
    pub path: String,
    pub raw_content: Vec<u8>,
}

/// コンテンツ作成ユースケースの出力。
#[derive(Debug)]
pub struct CreateContentResult {
    pub content_id: ContentId,
    pub metadata: Metadata,
    /// コンテンツ暗号化に用いた鍵から導出される公開情報など。
    /// 具体的な意味づけは後続の設計で決める。
    pub public_key: String,
}

/// コンテンツ更新ユースケースの入力。
#[derive(Debug)]
pub struct UpdateContentCommand {
    pub content_id: ContentId,
    pub new_name: Option<String>,
    pub new_raw_content: Option<Vec<u8>>,
}

/// コンテンツ更新ユースケースの出力。
#[derive(Debug)]
pub struct UpdateContentResult {
    pub content_id: ContentId,
    pub metadata: Metadata,
}

/// コンテンツ削除ユースケースの入力。
#[derive(Debug)]
pub struct DeleteContentCommand {
    pub content_id: ContentId,
}

/// コンテンツ削除ユースケースの出力。
#[derive(Debug)]
pub struct DeleteContentResult {
    pub content_id: ContentId,
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
