use serde::{Deserialize, Serialize};

/// State Nodeへのコンテンツ作成リクエスト
#[derive(Debug, Serialize)]
pub struct StateNodeCreateContentRequest {
    /// Base64エンコードされたコンテンツデータ
    pub data: String,
}

/// State Nodeからのコンテンツ作成レスポンス
#[derive(Debug, Deserialize)]
pub struct StateNodeCreateContentResponse {
    pub content_id: String,
    pub member_nodes: Vec<String>,
}

/// State Nodeへのコンテンツ更新リクエスト
#[derive(Debug, Serialize)]
pub struct StateNodeUpdateContentRequest {
    /// Base64エンコードされたコンテンツデータ
    pub data: String,
}

/// State Nodeからのコンテンツ更新レスポンス
#[derive(Debug, Deserialize)]
pub struct StateNodeUpdateContentResponse {
    pub content_id: String,
    pub updated: bool,
}

/// State Nodeからのコンテンツ履歴レスポンス
#[derive(Debug, Deserialize)]
pub struct StateNodeContentHistoryResponse {
    pub content_id: String,
    pub versions: Vec<String>,
}

/// State Nodeからのコンテンツデータレスポンス
#[derive(Debug, Deserialize)]
pub struct StateNodeContentDataResponse {
    pub content_id: String,
    /// Base64(Standard)エンコードされたデータ
    pub data: String,
    pub version: Option<String>,
}

/// State Nodeのエラーレスポンス
#[derive(Debug, Deserialize)]
pub struct StateNodeErrorResponse {
    pub error: String,
}
