use serde::{Deserialize, Serialize};

use super::content::ContentMetadata;

/// 権限の種類
///
/// `#[non_exhaustive]` のため、将来 variant 追加時に下流の `match` が壊れないよう
/// 必ず `_ =>` のフォールスルーを入れること。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
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
    /// CEK の鍵世代。rotation(revoke)のたびに +1 される。wrap の AAD に
    /// 束縛されているため書き換えると復号自体が失敗する。受信者は記録済み
    /// 世代より古い envelope を拒否する(旧 CEK への巻き戻し replay 防止)。
    #[serde(default)]
    pub key_epoch: u64,
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
    /// 送信者の秘密鍵（base64url）。KeyEnvelope の HPKE Auth モード wrap
    /// (送信者認証)に用いる。SDK には保存されない。
    pub sender_private_key: String,
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
    /// 送信者の公開鍵（base64url）。受信者はこれを `decrypt_shared_content` に
    /// 渡し、初回処理時に TOFU でピン留めする(以後の envelope 検証の根になる)。
    pub sender_public_key: String,
    pub sender_key_id: String,
    pub recipient_key_id: String,
    pub key_envelope: KeyEnvelope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_access: Option<DelegatedAccessToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_at: Option<String>,
}

/// delegated token の発行結果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedAccessToken {
    pub delegated_token: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub jti: String,
}

// ============================================
// revoke_share
// ============================================

/// 共有取り消しリクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeShareInput {
    /// SDK ローカルの版ID（ACL・CEK・再暗号化はローカルIDで処理される）
    pub content_id: String,
    /// State Node へ送る系列ID。未指定の場合は `content_id` を使う（後方互換）。
    /// State Node はローカル版IDを知らないため、State Node に登録済みの
    /// コンテンツでは必ず指定すること（`UpdateContentInput` と同じ区別）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_content_id: Option<String>,
    /// 送信者の公開鍵（base64url） - sender_key_idを計算するために使用
    pub sender_public_key: String,
    /// 送信者の秘密鍵（base64url）。残存受信者向け KeyEnvelope 再発行の
    /// HPKE Auth モード wrap に用いる。SDK には保存されない。
    pub sender_private_key: String,
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
    /// 取り消し後も共有が残っている受信者向けに、ローテーション後の CEK で
    /// 再発行された KeyEnvelope。呼び出し側(owner)はこれを各受信者へ配布し、
    /// 受信者は `decrypt_shared_content` で処理することでローカル保存済み CEK が
    /// 新しいものへ更新される(state node 経由の read が引き続き復号できる)。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reissued_envelopes: Vec<ReissuedKeyEnvelope>,
    /// state node が設定した新しい `min_valid_issued_at`（Unix 秒）。
    /// これより前に発行された委譲 Token はすべて失効している。
    /// state node 連携なしで実行した場合は `None`。
    ///
    /// CEK ローテーションと違い、これは「取り消した相手がまだ書き込めるか」を
    /// 決める。残存受信者には、この時刻より後に発行した Token を配り直す必要がある。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_invalidated_at: Option<u64>,
}

/// revoke 後に残存受信者向けへ再発行された KeyEnvelope。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReissuedKeyEnvelope {
    /// 再発行先の受信者 key id(base64url)
    pub recipient_key_id: String,
    pub key_envelope: KeyEnvelope,
}

// ============================================
// decrypt_shared_content
// ============================================

/// 共有コンテンツ復号リクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptSharedContentInput {
    pub content_id: String,
    pub private_key: String,
    /// 送信者の公開鍵（base64url）。HPKE Auth モードの unwrap に用いる。
    /// この content で初めての envelope 処理なら TOFU でピン留めされ、
    /// 以後はピン済みの鍵と一致しない場合は拒否される。
    pub sender_public_key: String,
    pub recipient_key_id: String,
    pub key_envelope: KeyEnvelope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// 共有コンテンツ復号レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptSharedContentOutput {
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
            key_epoch: 0,
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
            "sender_private_key": "sender_priv",
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
            "sender_private_key": "sender_priv",
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
            sender_public_key: "sender_public_key".into(),
            sender_key_id: "sender_key_id".into(),
            recipient_key_id: "recipient_key_id".into(),
            key_envelope: KeyEnvelope {
                enc: "enc".into(),
                wrapped_cek: "cek".into(),
                ciphertext: "ct".into(),
                key_epoch: 0,
            },
            delegated_access: Some(DelegatedAccessToken {
                delegated_token: "jwt".into(),
                issued_at: 1,
                expires_at: 2,
                jti: "jti".into(),
            }),
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
            reissued_envelopes: vec![],
            token_invalidated_at: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"revoked\":true"));
        // 空の envelope リストは serialize されない(後方互換)
        assert!(!json.contains("reissued_envelopes"));
        // state node 連携なしなら失効時刻も出さない
        assert!(!json.contains("token_invalidated_at"));
    }

    #[test]
    fn test_revoke_share_output_reports_token_invalidation() {
        let output = RevokeShareOutput {
            content_id: "test_id".into(),
            recipient_public_key: "recipient_key".into(),
            revoked: true,
            revoked_at: None,
            reissued_envelopes: vec![],
            token_invalidated_at: Some(1_700_000_000),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"token_invalidated_at\":1700000000"));
    }

    #[test]
    fn test_revoke_share_output_with_reissued_envelopes() {
        let output = RevokeShareOutput {
            content_id: "test_id".into(),
            recipient_public_key: "recipient_key".into(),
            revoked: true,
            revoked_at: None,
            reissued_envelopes: vec![ReissuedKeyEnvelope {
                recipient_key_id: "surviving-recipient".into(),
                key_envelope: KeyEnvelope {
                    enc: "enc".into(),
                    wrapped_cek: "wrapped".into(),
                    ciphertext: "cipher".into(),
                    key_epoch: 1,
                },
            }],
            token_invalidated_at: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"reissued_envelopes\""));
        assert!(json.contains("\"recipient_key_id\":\"surviving-recipient\""));
    }

    #[test]
    fn test_decrypt_shared_content_input() {
        let input = DecryptSharedContentInput {
            content_id: "test_id".into(),
            private_key: "test_key".into(),
            sender_public_key: "sender_public_key".into(),
            recipient_key_id: "recipient_key_id".into(),
            key_envelope: KeyEnvelope {
                enc: "enc".into(),
                wrapped_cek: "cek".into(),
                ciphertext: "ct".into(),
                key_epoch: 0,
            },
            version: None,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"content_id\":\"test_id\""));
        assert!(json.contains("\"key_envelope\""));
        assert!(!json.contains("version"));
    }
}
