use serde::{Deserialize, Serialize};

/// Content metadata
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

/// Content creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContentInput {
    /// Content data (base64url)
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ContentMetadata>,
}

/// Content creation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContentOutput {
    /// Key of this file. A value used only on the device; subsequent owner-side operations
    /// (get, update, delete, share, revoke, permission change, state pull) specify the target
    /// with this. Never passed to the state node or recipients.
    pub file_id: String,
    /// plainCid of the created version (SHA-256 of the body).
    pub content_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_content_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

// ============================================
// get_content
// ============================================

/// Content get request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetContentInput {
    /// Key of the target file (`CreateContentOutput::file_id`).
    pub file_id: String,
}

/// Content get response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetContentOutput {
    /// plainCid of the current version.
    pub content_id: String,
    /// Decrypted content (base64url)
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ContentMetadata>,
}

// ============================================
// update_content
// ============================================

/// Content update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateContentInput {
    /// Key of the target file (`CreateContentOutput::file_id`)
    pub file_id: String,
    /// Series ID sent to the State Node
    pub remote_content_id: String,
    /// New content data (base64url)
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ContentMetadata>,
}

/// Content update response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateContentOutput {
    /// Key of the target file (same as the input; does not change on edit)
    pub file_id: String,
    /// plainCid of the version before the update
    pub previous_version_id: String,
    /// plainCid of the version after the update
    pub version_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

// ============================================
// delete_content
// ============================================

/// Content deletion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteContentInput {
    /// Key of the target file (`CreateContentOutput::file_id`)
    pub file_id: String,
    /// Series ID sent to the State Node
    pub remote_content_id: String,
}

/// Content deletion response
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
