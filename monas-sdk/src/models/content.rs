use serde::{Deserialize, Serialize};

/// コンテンツのメタデータ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

// ============================================
// create_content
// ============================================

/// コンテンツ作成リクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContentInput {
    /// コンテンツデータ（base64url）
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ContentMetadata>,
}

/// コンテンツ作成レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContentOutput {
    /// このファイルのキー。端末だけで使う値で、以後の owner 側の操作
    /// (取得・更新・削除・共有・取り消し・権限変更・state の取り込み)は
    /// これで対象を指定する。state node や受信者には渡さない。
    pub file_id: String,
    /// 作成した版の plainCid(本文の SHA-256)。
    pub content_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_content_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

// ============================================
// get_content
// ============================================

/// コンテンツ取得リクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetContentInput {
    /// 対象ファイルのキー(`CreateContentOutput::file_id`)。
    pub file_id: String,
}

/// コンテンツ取得レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetContentOutput {
    /// 今の版の plainCid。
    pub content_id: String,
    /// 復号されたコンテンツ（base64url）
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ContentMetadata>,
}

// ============================================
// update_content
// ============================================

/// コンテンツ更新リクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateContentInput {
    /// 対象ファイルのキー(`CreateContentOutput::file_id`)
    pub file_id: String,
    /// State Node へ送る系列ID
    pub remote_content_id: String,
    /// 新しいコンテンツデータ（base64url）
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ContentMetadata>,
}

/// コンテンツ更新レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateContentOutput {
    /// 対象ファイルのキー(入力と同じ。編集では変わらない)
    pub file_id: String,
    /// 更新前の版の plainCid
    pub previous_version_id: String,
    /// 更新後の版の plainCid
    pub version_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

// ============================================
// delete_content
// ============================================

/// コンテンツ削除リクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteContentInput {
    /// 対象ファイルのキー(`CreateContentOutput::file_id`)
    pub file_id: String,
    /// State Node へ送る系列ID
    pub remote_content_id: String,
}

/// コンテンツ削除レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteContentOutput {
    pub content_id: String,
    pub deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_metadata_serialization() {
        let metadata = ContentMetadata {
            name: Some("test.txt".into()),
            content_type: Some("text/plain".into()),
            created_at: None,
            updated_at: None,
        };
        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("\"name\":\"test.txt\""));
        assert!(json.contains("\"content_type\":\"text/plain\""));
        assert!(!json.contains("created_at"));
        assert!(!json.contains("updated_at"));
    }

    #[test]
    fn test_create_content_input() {
        let input = CreateContentInput {
            content: "SGVsbG8gV29ybGQ=".into(),
            metadata: Some(ContentMetadata {
                name: Some("hello.txt".into()),
                content_type: Some("text/plain".into()),
                created_at: None,
                updated_at: None,
            }),
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"content\":\"SGVsbG8gV29ybGQ=\""));
        assert!(json.contains("\"name\":\"hello.txt\""));
    }

    #[test]
    fn test_create_content_output() {
        let output = CreateContentOutput {
            file_id: "file".into(),
            content_id: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi".into(),
            remote_content_id: Some("bafkreiabc".into()),
            created_at: Some("2025-12-05T12:34:56Z".into()),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"content_id\""));
        assert!(json.contains("\"remote_content_id\":\"bafkreiabc\""));
        assert!(json.contains("\"created_at\":\"2025-12-05T12:34:56Z\""));
    }

    #[test]
    fn test_get_content_input_minimal() {
        let json = r#"{"file_id": "test_id"}"#;
        let input: GetContentInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.file_id, "test_id");
    }

    #[test]
    fn test_get_content_output() {
        let output = GetContentOutput {
            content_id: "test_id".into(),
            content: "SGVsbG8gV29ybGQ=".into(),
            metadata: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"content_id\":\"test_id\""));
        assert!(json.contains("\"content\":\"SGVsbG8gV29ybGQ=\""));
        assert!(!json.contains("metadata"));
    }

    #[test]
    fn test_update_content_input() {
        let input = UpdateContentInput {
            file_id: "file".into(),
            remote_content_id: "bafkremote".into(),
            content: "bmV3IGNvbnRlbnQ=".into(),
            metadata: None,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"file_id\":\"file\""));
        assert!(json.contains("\"remote_content_id\":\"bafkremote\""));
        assert!(json.contains("\"content\":\"bmV3IGNvbnRlbnQ=\""));
    }

    #[test]
    fn test_update_content_output() {
        let output = UpdateContentOutput {
            file_id: "file".into(),
            previous_version_id: "prev_version".into(),
            version_id: "new_version".into(),
            updated_at: Some("2025-12-05T12:34:56Z".into()),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"file_id\":\"file\""));
        assert!(json.contains("\"previous_version_id\":\"prev_version\""));
        assert!(json.contains("\"version_id\":\"new_version\""));
        assert!(json.contains("\"updated_at\":\"2025-12-05T12:34:56Z\""));
    }

    #[test]
    fn test_delete_content_output() {
        let output = DeleteContentOutput {
            content_id: "test_id".into(),
            deleted: true,
            deleted_at: Some("2025-12-05T12:34:56Z".into()),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"deleted\":true"));
        assert!(json.contains("\"deleted_at\":\"2025-12-05T12:34:56Z\""));
    }
}
