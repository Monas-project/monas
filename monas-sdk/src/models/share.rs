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
    /// State Node へ登録済みの系列ID(`UpdateContentInput` / `RevokeShareInput` と
    /// 同じ区別)。委譲 Token の resource はこれで発行される: State Node は
    /// `monas://content/<系列ID>` で capability を照合するので、ローカル版ID
    /// で発行した Token は受信者の read/write に使えない。未指定なら
    /// `content_id`(State Node 未登録のローカル専用コンテンツ向け)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_content_id: Option<String>,
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
    /// revoke は再暗号化の前に State Node の head をローカルへ取り込む
    /// (write を委譲した受信者の版を巻き戻さないため)。その取り込みに失敗
    /// したときの理由。revoke 自体はローカルの版で続行している — 取り消しは
    /// 書き手に妨げられてはならない — ので、呼び出し側はこれを見て
    /// 「head が失われたかもしれない」と扱うこと。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_pull_error: Option<String>,
    /// 失効境界(`token_invalidated_at`)がどこまで届いたか。
    ///
    /// State Node の認可はメンバーごとのローカル判断なので、境界を受け取って
    /// いないメンバーは次回 sync まで**失効済み Token の書き込みを受理する**。
    /// revoke 自体はそれを待たない(書き手に取り消しを妨げさせない)ため、
    /// 呼び出し側は「全員に届いた」と「N 台にまだ届いていない」を
    /// ここで区別する。state node 連携なしの場合は `None`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_invalidation_reach: Option<TokenInvalidationReach>,
}

/// revoke の失効境界がメンバーへどこまで伝わったか。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenInvalidationReach {
    /// 境界を受け取り、以後それで認可するメンバー。
    pub notified_members: Vec<String>,
    /// 届かなかったメンバーと最後のエラー。空 = 既知の全メンバーに届いた
    /// (`relayed` でない限り)。
    pub unreached_members: Vec<UnreachedMember>,
    /// State Node が commit せず relay した。上の2つは不明。
    pub relayed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnreachedMember {
    pub node_id: String,
    pub error: String,
}

/// revoke 後に残存受信者向けへ再発行された KeyEnvelope。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReissuedKeyEnvelope {
    /// 再発行先の受信者 key id(base64url)
    pub recipient_key_id: String,
    pub key_envelope: KeyEnvelope,
    /// 再発行した委譲 Token。revoke は State Node の `min_valid_issued_at` を
    /// 進めるので、残存受信者が持っていた Token も一緒に失効している。
    /// 新しい envelope と一緒に届けなければ、その受信者は復号はできても
    /// State Node からは読めない。発行に失敗した場合は `None`(envelope の
    /// 再発行自体は成立している)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_access: Option<DelegatedAccessToken>,
}

// ============================================
// decrypt_shared_content
// ============================================

/// 共有コンテンツ復号リクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptSharedContentInput {
    pub content_id: String,
    /// State Node の系列ID。送信者ピン(TOFU の送信者鍵・鍵世代・CEK)は
    /// これをキーに保存する。`content_id` は owner 側の版IDで編集のたびに
    /// 変わるので、版IDでピンすると「編集前の古い envelope」が新しい世代の
    /// 記録と別の場所に落ちて replay 検出をすり抜ける。未指定なら
    /// `content_id`(State Node 未登録のローカル専用コンテンツ向け)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_content_id: Option<String>,
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

/// 共有を受けた側がコンテンツを更新するリクエスト。
///
/// 受信者はローカルに content レコードを持たない(持つのは envelope から
/// 取り出した CEK と送信者ピンだけ)。新しい平文をその CEK で暗号化し、
/// owner の Content Network(`remote_content_id`)へ write 委譲 Token 付きで
/// PUT する。State Node は Token の `aud` 鍵(この端末の account 鍵)で
/// 署名を検証し、Token の capability で書き込みを許可する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSharedContentInput {
    /// State Node の系列ID(owner の share package の `remote_content_id`)。
    pub remote_content_id: String,
    /// 新しい平文(base64url)。
    pub content: String,
}

/// 共有を受けた側の更新レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSharedContentOutput {
    pub remote_content_id: String,
    /// 新しい平文の content id(plain CID)。owner 側の版IDと同じ規則で
    /// 導出されるので、以後この版を読むときの `local_content_id` になる。
    pub version_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
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
            head_pull_error: None,
            token_invalidation_reach: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"revoked\":true"));
        assert!(!json.contains("head_pull_error"));
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
            head_pull_error: None,
            token_invalidation_reach: None,
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

                delegated_access: None,
            }],
            token_invalidated_at: None,
            head_pull_error: None,
            token_invalidation_reach: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"reissued_envelopes\""));
        assert!(json.contains("\"recipient_key_id\":\"surviving-recipient\""));
    }

    #[test]
    fn test_decrypt_shared_content_input() {
        let input = DecryptSharedContentInput {
            content_id: "test_id".into(),
            remote_content_id: None,
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
