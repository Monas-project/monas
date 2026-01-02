use serde::{Deserialize, Serialize};

use super::content::ContentMetadata;

/// 権限の種類
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Read,
    Write,
}

/// KeyEnvelope（暗号化されたCEK + 関連データ）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEnvelope {
    /// HPKEのカプセル化された公開鍵（base64url）
    pub enc: String,
    /// 暗号化されたCEK（base64url）
    pub wrapped_cek: String,
    /// 暗号化されたコンテンツ（base64url）
    pub ciphertext: String,
}

// ============================================
// share_content
// ============================================

/// コンテンツ共有リクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareContentInput {
    pub content_id: String,
    /// 送信者の公開鍵（base64url） - sender_key_idを計算するために使用
    pub sender_public_key: String,
    /// 共有先の公開鍵（base64url）
    pub recipient_public_key: String,
    #[serde(default = "default_permissions")]
    pub permissions: Vec<Permission>,
}

fn default_permissions() -> Vec<Permission> {
    vec![Permission::Read]
}

/// コンテンツ共有レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareContentOutput {
    pub content_id: String,
    pub recipient_public_key: String,
    pub sender_key_id: String,
    pub recipient_key_id: String,
    pub key_envelope: KeyEnvelope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_at: Option<String>,
}

// ============================================
// revoke_share
// ============================================

/// 共有取り消しリクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeShareInput {
    pub content_id: String,
    pub recipient_public_key: String,
}

/// 共有取り消しレスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeShareOutput {
    pub content_id: String,
    pub recipient_public_key: String,
    pub revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

// ============================================
// get_shared_content
// ============================================

/// 共有コンテンツ取得リクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSharedContentInput {
    pub content_id: String,
    pub private_key: String,
    pub sender_key_id: String,
    pub recipient_key_id: String,
    pub key_envelope: KeyEnvelope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// 共有コンテンツ取得レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSharedContentOutput {
    pub content_id: String,
    /// 復号されたコンテンツ（base64url）
    pub content: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ContentMetadata>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_serialization() {
        let read = Permission::Read;
        assert_eq!(serde_json::to_string(&read).unwrap(), "\"read\"");

        let write = Permission::Write;
        assert_eq!(serde_json::to_string(&write).unwrap(), "\"write\"");
    }

    #[test]
    fn test_key_envelope() {
        let envelope = KeyEnvelope {
            enc: "enc_data".into(),
            wrapped_cek: "wrapped_cek_data".into(),
            ciphertext: "ciphertext_data".into(),
        };
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("\"enc\":\"enc_data\""));
        assert!(json.contains("\"wrapped_cek\":\"wrapped_cek_data\""));
        assert!(json.contains("\"ciphertext\":\"ciphertext_data\""));
    }

    #[test]
    fn test_share_content_input_default_permissions() {
        let json = r#"{
            "content_id": "test_id",
            "sender_public_key": "sender_pub",
            "recipient_public_key": "recipient_key"
        }"#;
        let input: ShareContentInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.permissions, vec![Permission::Read]);
    }

    #[test]
    fn test_share_content_input_with_permissions() {
        let json = r#"{
            "content_id": "test_id",
            "sender_public_key": "sender_pub",
            "recipient_public_key": "recipient_key",
            "permissions": ["read", "write"]
        }"#;
        let input: ShareContentInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.permissions, vec![Permission::Read, Permission::Write]);
    }

    #[test]
    fn test_share_content_output() {
        let output = ShareContentOutput {
            content_id: "test_id".into(),
            recipient_public_key: "recipient_key".into(),
            sender_key_id: "sender_key_id".into(),
            recipient_key_id: "recipient_key_id".into(),
            key_envelope: KeyEnvelope {
                enc: "enc".into(),
                wrapped_cek: "cek".into(),
                ciphertext: "ct".into(),
            },
            shared_at: Some("2025-12-05T12:34:56Z".into()),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"content_id\":\"test_id\""));
        assert!(json.contains("\"key_envelope\""));
    }

    #[test]
    fn test_revoke_share_output() {
        let output = RevokeShareOutput {
            content_id: "test_id".into(),
            recipient_public_key: "recipient_key".into(),
            revoked: true,
            revoked_at: Some("2025-12-05T12:34:56Z".into()),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"revoked\":true"));
    }

    #[test]
    fn test_get_shared_content_input() {
        let input = GetSharedContentInput {
            content_id: "test_id".into(),
            private_key: "test_key".into(),
            sender_key_id: "sender_key_id".into(),
            recipient_key_id: "recipient_key_id".into(),
            key_envelope: KeyEnvelope {
                enc: "enc".into(),
                wrapped_cek: "cek".into(),
                ciphertext: "ct".into(),
            },
            version: None,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"content_id\":\"test_id\""));
        assert!(json.contains("\"key_envelope\""));
        assert!(!json.contains("version"));
    }
}
