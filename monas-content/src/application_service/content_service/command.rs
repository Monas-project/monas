use crate::domain::{
    content_id::ContentId,
    metadata::Metadata,
};

/// コンテンツ作成ユースケースの入力。
pub struct CreateContentCommand {
    pub name: String,
    pub path: String,
    pub raw_content: Vec<u8>,
}

/// コンテンツ作成ユースケースの出力。
pub struct CreateContentResult {
    pub content_id: ContentId,
    pub metadata: Metadata,
    /// コンテンツ暗号化に用いた鍵から導出される公開情報など。
    /// 具体的な意味づけは後続の設計で決める。
    pub public_key: String,
}

/// コンテンツ更新ユースケースの入力。
pub struct UpdateContentCommand {
    pub content_id: ContentId,
    pub new_name: Option<String>,
    pub new_raw_content: Option<Vec<u8>>,
}

/// コンテンツ更新ユースケースの出力。
pub struct UpdateContentResult {
    pub content_id: ContentId,
    pub metadata: Metadata,
}

/// コンテンツ削除ユースケースの入力。
pub struct DeleteContentCommand {
    pub content_id: ContentId,
}

/// コンテンツ削除ユースケースの出力。
pub struct DeleteContentResult {
    pub content_id: ContentId,
}


