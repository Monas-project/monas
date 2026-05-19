use serde::{Deserialize, Serialize};

/// State Nodeへのコンテンツ作成リクエスト
#[derive(Debug, Serialize)]
pub struct StateNodeCreateContentRequest {
    /// Base64エンコードされたコンテンツデータ
    pub data: String,
}

/// State Nodeからのコンテンツ作成レスポンス（`POST /content` → 201 Created）
#[derive(Debug, Deserialize)]
pub struct StateNodeCreateContentResponse {
    #[serde(default)]
    pub content_id: String,
}

/// State Nodeへのコンテンツ更新リクエスト
#[derive(Debug, Serialize)]
pub struct StateNodeUpdateContentRequest {
    /// Base64エンコードされたコンテンツデータ
    pub data: String,
}

/// State Nodeからのコンテンツ更新レスポンス（`PUT /content/:id`）
#[derive(Debug, Deserialize)]
pub struct StateNodeUpdateContentResponse {
    #[serde(default)]
    pub content_id: String,
    #[serde(default)]
    pub updated: bool,
}

/// State Nodeからのコンテンツ削除レスポンス（`DELETE /content/:id`）
#[derive(Debug, Deserialize)]
pub struct StateNodeDeleteContentResponse {
    #[serde(default)]
    pub content_id: String,
    #[serde(default)]
    pub deleted: bool,
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
