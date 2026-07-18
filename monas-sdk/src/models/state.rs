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
// read_content_from_state_node
// ============================================

/// State Node からの検証付き read リクエスト。
///
/// - `content_id`: State Node 側の content id（remote id）。履歴・版データの取得と
///   読み取り署名（`read:{content_id}:{timestamp}`）のバインドに使う。
/// - `local_content_id`: SDK ローカルの content id（plain CID）。CEK の引き当てと
///   復号後の整合性チェック（平文から再計算した plain CID との一致）に使う。
///   local↔remote の対応表は存在しないため、呼び出し側が両方を渡す
///   （`VerifyIntegrityInput` と同じ設計）。
/// - `version`: 読む版 CID。省略時は State Node の履歴から最新版を読む。
///   最新読みのときのみ単調性チェック（ロールバック検出）が働く。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadContentFromStateNodeInput {
    pub content_id: String,
    pub local_content_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// State Node からの検証付き read レスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadContentFromStateNodeOutput {
    pub content_id: String,
    pub local_content_id: String,
    /// 実際に読まれた版 CID（CID 再計算で検証済み）
    pub version: String,
    /// 復号済みの平文（base64url）
    pub content: String,
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
    /// SDK ローカルの版ID。指定すると、State Node が返す暗号文をローカルに
    /// 保存された暗号文とバイト比較して検証する（State Node は暗号文を保持
    /// するため、平文である `content` とは直接比較できない）。未指定の場合は
    /// 従来どおり `content` のバイト列と直接比較する。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_content_id: Option<String>,
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
