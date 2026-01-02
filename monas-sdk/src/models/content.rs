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
    pub content_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

// ============================================
// get_content
// ============================================

/// コンテンツ取得リクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetContentInput {
    pub content_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// コンテンツ取得レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetContentOutput {
    pub content_id: String,
    /// 復号されたコンテンツ（base64url）
    pub content: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ContentMetadata>,
}

// ============================================
// update_content
// ============================================

/// コンテンツ更新リクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateContentInput {
    pub content_id: String,
    /// 新しいコンテンツデータ（base64url）
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ContentMetadata>,
}

/// コンテンツ更新レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateContentOutput {
    pub content_id: String,
    pub new_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

// ============================================
// delete_content
// ============================================

/// コンテンツ削除リクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteContentInput {
    pub content_id: String,
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
            content_id: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi".into(),
            created_at: Some("2025-12-05T12:34:56Z".into()),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"content_id\""));
        assert!(json.contains("\"created_at\":\"2025-12-05T12:34:56Z\""));
    }

    #[test]
    fn test_get_content_input_minimal() {
        let json = r#"{"content_id": "test_id"}"#;
        let input: GetContentInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.content_id, "test_id");
        assert!(input.version.is_none());
    }

    #[test]
    fn test_get_content_output() {
        let output = GetContentOutput {
            content_id: "test_id".into(),
            content: "SGVsbG8gV29ybGQ=".into(),
            version: "v1".into(),
            metadata: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"content_id\":\"test_id\""));
        assert!(json.contains("\"content\":\"SGVsbG8gV29ybGQ=\""));
        assert!(json.contains("\"version\":\"v1\""));
        assert!(!json.contains("metadata"));
    }

    #[test]
    fn test_update_content_input() {
        let input = UpdateContentInput {
            content_id: "test_id".into(),
            content: "bmV3IGNvbnRlbnQ=".into(),
            metadata: None,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"content_id\":\"test_id\""));
        assert!(json.contains("\"content\":\"bmV3IGNvbnRlbnQ=\""));
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
