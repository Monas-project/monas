use serde::{Deserialize, Serialize};

// ============================================
// get_latest_version
// ============================================

/// 最新バージョン取得リクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLatestVersionInput {
    pub content_id: String,
}

/// 最新バージョン取得レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLatestVersionOutput {
    pub content_id: String,
    pub latest_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

// ============================================
// get_history
// ============================================

/// 履歴取得リクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHistoryInput {
    pub content_id: String,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    100
}

/// 履歴取得レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHistoryOutput {
    pub content_id: String,
    pub versions: Vec<String>,
}

// ============================================
// verify_integrity
// ============================================

/// 整合性検証リクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyIntegrityInput {
    pub content_id: String,
    /// 検証するコンテンツ（base64url）
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<String>,
}

/// 整合性検証レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyIntegrityOutput {
    pub valid: bool,
    pub computed_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_latest_version() {
        let output = GetLatestVersionOutput {
            content_id: "test_id".into(),
            latest_version: "v123".into(),
            updated_at: Some("2025-12-05T12:34:56Z".into()),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"latest_version\":\"v123\""));
    }

    #[test]
    fn test_get_history_input_default_limit() {
        let json = r#"{"content_id": "test_id"}"#;
        let input: GetHistoryInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.limit, 100);
    }

    #[test]
    fn test_get_history_input_custom_limit() {
        let json = r#"{"content_id": "test_id", "limit": 50}"#;
        let input: GetHistoryInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.limit, 50);
    }

    #[test]
    fn test_get_history_output() {
        let output = GetHistoryOutput {
            content_id: "test_id".into(),
            versions: vec!["v1".into(), "v2".into()],
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"versions\""));
        assert!(json.contains("\"v1\""));
        assert!(json.contains("\"v2\""));
    }

    #[test]
    fn test_verify_integrity_output_valid() {
        let output = VerifyIntegrityOutput {
            valid: true,
            computed_hash: "abc123".into(),
            reason: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"valid\":true"));
        assert!(!json.contains("reason"));
    }

    #[test]
    fn test_verify_integrity_output_invalid() {
        let output = VerifyIntegrityOutput {
            valid: false,
            computed_hash: "abc123".into(),
            reason: Some("hash mismatch".into()),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"valid\":false"));
        assert!(json.contains("\"reason\":\"hash mismatch\""));
    }
}
