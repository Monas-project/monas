use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::common::{
    decode_base64url, encode_base64url, generate_trace_id, ApiError, ApiResponse,
    StateNodeAuthContext,
};
use crate::models::share::{
    DecryptSharedContentInput, DecryptSharedContentOutput, DelegatedAccessToken, KeyEnvelope,
    Permission, RevokeShareInput, RevokeShareOutput, ShareContentInput, ShareContentOutput,
};

use monas_content::application_service::content_service::{
    ContentEncryptionKeyStore, ContentRepository, DecryptWithCekError, ReencryptContentCommand,
    ReencryptError,
};
use monas_content::application_service::share_service::{
    GrantShareCommand, RevokeShareCommand, ShareApplicationError, ShareRepository, ShareService,
};
use monas_content::domain::content::{Content, ContentEncryptionKey};
use monas_content::domain::content_id::ContentId;
use monas_content::domain::share::{
    key_envelope::{KeyEnvelope as DomainKeyEnvelope, KeyWrapAlgorithm, WrappedRecipientKey},
    KeyId, Permission as DomainPermission, Share,
};
use monas_content::infrastructure::{
    key_store::InMemoryContentEncryptionKeyStore, key_wrapping::HpkeV1KeyWrapping,
    public_key_directory::InMemoryPublicKeyDirectory, share_repository::InMemoryShareRepository,
    MultiStorageRepository,
};

use super::MonasController;

const DEFAULT_DELEGATION_TTL_SECS: u64 = 3600;

#[derive(Debug, Serialize)]
struct IssueDelegatedTokenRequest {
    recipient_public_key_base64: String,
    content_id: String,
    capabilities: Vec<String>,
    ttl_secs: u64,
}

#[derive(Debug, Deserialize)]
struct IssueDelegatedTokenResponse {
    delegated_token: String,
    issued_at: u64,
    expires_at: u64,
    jti: String,
}

/// ShareServiceの型エイリアス（可読性向上のため）
pub(super) type ShareServiceInstance = ShareService<
    InMemoryShareRepository,
    MultiStorageRepository,
    InMemoryContentEncryptionKeyStore,
    InMemoryPublicKeyDirectory,
    HpkeV1KeyWrapping,
>;

#[derive(Clone)]
struct RevokeShareLocalSnapshot {
    share: Share,
    content: Content,
    cek: ContentEncryptionKey,
}

impl MonasController {
    fn map_reencrypt_error(e: ReencryptError) -> ApiError {
        match e {
            ReencryptError::ContentNotFound => ApiError::NotFound("Content not found".into()),
            ReencryptError::ContentDeleted => ApiError::NotFound("Content is deleted".into()),
            ReencryptError::MissingContentEncryptionKey => {
                ApiError::Internal("Missing content encryption key".into())
            }
            ReencryptError::Domain(err) => ApiError::Internal(format!("Domain error: {err:?}")),
            ReencryptError::ContentRepository(err) => {
                ApiError::Internal(format!("Content repository error: {err}"))
            }
            ReencryptError::KeyStore(err) => ApiError::Internal(format!("Key store error: {err}")),
            ReencryptError::MissingEncryptedContent => {
                ApiError::Internal("Missing encrypted content".into())
            }
        }
    }

    fn validate_non_empty(field: &'static str, value: &str) -> Result<(), ApiError> {
        if value.is_empty() {
            return Err(ApiError::Validation(format!("{field} must not be empty")));
        }
        Ok(())
    }

    fn decode_base64url_field(field: &'static str, value: &str) -> Result<Vec<u8>, ApiError> {
        decode_base64url(value)
            .map_err(|e| ApiError::Validation(format!("Invalid {field} base64url: {e}")))
    }

    fn encode_key_id_base64url(key_id: &KeyId) -> String {
        encode_base64url(key_id.as_bytes())
    }

    /// 公開鍵からKeyIdを計算
    fn compute_key_id_from_public_key(public_key: &[u8]) -> KeyId {
        let digest = Sha256::digest(public_key);
        let id_bytes = digest[..16].to_vec();
        KeyId::new(id_bytes)
    }

    /// SDKモデルのPermission一覧を、ShareService用のPermissionへ集約する
    ///
    /// - monas-content 側では Write が Read を内包するため、Writeが1つでもあればWriteを返す
    fn resolve_permission(permissions: &[Permission]) -> Result<DomainPermission, ApiError> {
        if permissions.is_empty() {
            return Err(ApiError::Validation("permissions must not be empty".into()));
        }
        if permissions.iter().any(|p| matches!(p, Permission::Write)) {
            return Ok(DomainPermission::Write);
        }
        Ok(DomainPermission::Read)
    }

    fn to_key_envelope(domain_envelope: &DomainKeyEnvelope) -> KeyEnvelope {
        let recipient = domain_envelope.recipient();
        KeyEnvelope {
            enc: encode_base64url(recipient.enc()),
            wrapped_cek: encode_base64url(recipient.wrapped_cek()),
            ciphertext: encode_base64url(domain_envelope.ciphertext()),
        }
    }

    fn permission_to_capabilities(permission: DomainPermission) -> Result<Vec<String>, ApiError> {
        match permission {
            DomainPermission::Read => Ok(vec!["read".to_string()]),
            DomainPermission::Write => Ok(vec!["write".to_string()]),
            // Owner 権限の委譲は現フェーズ対象外。SDK境界で拒否する。
            DomainPermission::Owner => Err(ApiError::Validation(
                "owner permission is not supported for delegation".into(),
            )),
        }
    }

    fn issue_delegated_token(
        &self,
        content_id: &str,
        recipient_public_key_bytes: &[u8],
        permission: DomainPermission,
    ) -> Result<DelegatedAccessToken, ApiError> {
        let issuer_url = format!("{}/issuer/delegate", self.account_url);
        let req = IssueDelegatedTokenRequest {
            recipient_public_key_base64: BASE64_STANDARD.encode(recipient_public_key_bytes),
            content_id: content_id.to_string(),
            capabilities: Self::permission_to_capabilities(permission)?,
            ttl_secs: DEFAULT_DELEGATION_TTL_SECS,
        };

        let mut response = self
            .agent
            .post(&issuer_url)
            .send_json(req)
            .map_err(|e| ApiError::from_ureq_error("Failed to call issuer API", e))?;

        let body: IssueDelegatedTokenResponse = response
            .body_mut()
            .read_json()
            .map_err(|e| ApiError::Internal(format!("Invalid issuer API response: {e}")))?;

        Ok(DelegatedAccessToken {
            delegated_token: body.delegated_token,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            jti: body.jti,
        })
    }

    /// ShareApplicationErrorをApiErrorにマッピング
    fn map_share_error(e: ShareApplicationError) -> ApiError {
        match e {
            ShareApplicationError::ContentNotFound => {
                ApiError::NotFound("Content not found for sharing".into())
            }
            ShareApplicationError::ContentDeleted => {
                ApiError::NotFound("Content is deleted".into())
            }
            ShareApplicationError::MissingEncryptedContent => {
                ApiError::Internal("Missing encrypted content".into())
            }
            ShareApplicationError::MissingContentEncryptionKey => {
                ApiError::Internal("Missing content encryption key".into())
            }
            ShareApplicationError::Share(err) => {
                ApiError::Internal(format!("Share domain error: {err:?}"))
            }
            ShareApplicationError::ContentRepository(err) => {
                ApiError::Internal(format!("Content repository error: {err}"))
            }
            ShareApplicationError::ContentEncryptionKeyStore(err) => {
                ApiError::Internal(format!("Key store error: {err}"))
            }
            ShareApplicationError::ShareRepository(err) => {
                ApiError::Internal(format!("Share repository error: {err}"))
            }
            ShareApplicationError::PublicKeyDirectory(err) => {
                ApiError::Internal(format!("Public key directory error: {err}"))
            }
            ShareApplicationError::MissingPublicKey => {
                ApiError::NotFound("Missing public key".into())
            }
            ShareApplicationError::KeyWrapping(msg) => {
                ApiError::Internal(format!("Key wrapping error: {msg}"))
            }
        }
    }

    fn capture_revoke_share_snapshot(
        &self,
        content_id: &ContentId,
    ) -> Result<RevokeShareLocalSnapshot, ApiError> {
        let share = self
            .share_service
            .share_repository
            .load(content_id)
            .map_err(|e| ApiError::Internal(format!("Share repository error: {e}")))?
            .ok_or_else(|| ApiError::NotFound("Content not found for sharing".into()))?;

        let content = self
            .share_service
            .content_repository
            .find_by_id(content_id)
            .map_err(|e| ApiError::Internal(format!("Content repository error: {e}")))?
            .ok_or_else(|| ApiError::NotFound("Content not found".into()))?;

        let cek = self
            .share_service
            .cek_store
            .load(content_id)
            .map_err(|e| ApiError::Internal(format!("Key store error: {e}")))?
            .ok_or_else(|| ApiError::Internal("Missing content encryption key".into()))?;

        Ok(RevokeShareLocalSnapshot {
            share,
            content,
            cek,
        })
    }

    fn restore_revoke_share_snapshot(
        &self,
        snapshot: &RevokeShareLocalSnapshot,
    ) -> Result<(), ApiError> {
        self.share_service
            .share_repository
            .save(&snapshot.share)
            .map_err(|e| ApiError::Internal(format!("Share repository restore error: {e}")))?;

        let content_id = snapshot.content.raw_id().clone();
        self.share_service
            .content_repository
            .save(&content_id, &snapshot.content)
            .map_err(|e| ApiError::Internal(format!("Content repository restore error: {e}")))?;

        self.share_service
            .cek_store
            .save(&content_id, &snapshot.cek)
            .map_err(|e| ApiError::Internal(format!("Key store restore error: {e}")))?;

        Ok(())
    }

    /// コンテンツを他のユーザーと共有する
    ///
    /// 処理フロー:
    /// 1. 入力のバリデーション
    /// 2. ContentIdに変換
    /// 3. 送信者の公開鍵をデコードしてsender_key_idを計算
    /// 4. 共有先の公開鍵をデコード
    /// 5. Permissionを変換
    /// 6. ShareService::grant_shareを呼び出し（パーミッション追加とKeyEnvelope生成）
    /// 7. 委譲トークン発行に失敗した場合は revoke_share（ドメイン）で ACL を巻き戻す
    /// 8. KeyEnvelopeをSDK形式に変換
    /// 9. 結果を返却
    pub fn share_content(&self, input: ShareContentInput) -> ApiResponse<ShareContentOutput> {
        let trace_id = generate_trace_id();

        // 1. 入力のバリデーション
        for (field, value) in [
            ("content_id", input.content_id.as_str()),
            ("sender_public_key", input.sender_public_key.as_str()),
            ("recipient_public_key", input.recipient_public_key.as_str()),
        ] {
            if let Err(e) = Self::validate_non_empty(field, value) {
                return ApiResponse::error(e, trace_id);
            }
        }

        // 2. ContentIdに変換
        let content_id = ContentId::new(input.content_id.clone());

        // 3. 送信者の公開鍵をデコードしてsender_key_idを計算
        let sender_public_key_bytes =
            match Self::decode_base64url_field("sender_public_key", &input.sender_public_key) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };

        let sender_key_id = Self::compute_key_id_from_public_key(&sender_public_key_bytes);

        // 4. 共有先の公開鍵をデコード
        let recipient_public_key_bytes =
            match Self::decode_base64url_field("recipient_public_key", &input.recipient_public_key)
            {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };

        // sender_key_idのコピーを保存（後でbase64エンコードするため）
        let sender_key_id_for_output = sender_key_id.clone();

        // 5. Permissionを変換（Writeが含まれるならWrite、そうでなければRead）
        let permission = match Self::resolve_permission(&input.permissions) {
            Ok(p) => p,
            Err(e) => return ApiResponse::error(e, trace_id),
        };

        // 6. ShareService::grant_shareを呼び出し
        // これにより、以下が実行されます：
        // - 共有相手へのパーミッション追加（ShareRepositoryにACL保存）
        // - KeyEnvelopeの生成
        let cmd = GrantShareCommand {
            content_id: content_id.clone(),
            sender_key_id,
            recipient_public_key: recipient_public_key_bytes.clone(),
            permission: permission.clone(),
        };

        let result = match self.share_service.grant_share(cmd) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(Self::map_share_error(e), trace_id);
            }
        };

        let delegated_access = match self.issue_delegated_token(
            &input.content_id,
            &recipient_public_key_bytes,
            permission,
        ) {
            Ok(token) => token,
            Err(e) => {
                let rollback_cmd = RevokeShareCommand {
                    content_id: content_id.clone(),
                    sender_key_id: sender_key_id_for_output.clone(),
                    recipient_key_id: result.recipient_key_id.clone(),
                };
                if let Err(rb) = self.share_service.revoke_share(rollback_cmd) {
                    return ApiResponse::error(
                        ApiError::Internal(format!(
                            "Delegated token issuance failed; rollback (revoke_share) also failed: {rb} (original: {e})"
                        )),
                        trace_id,
                    );
                }
                return ApiResponse::error(e, trace_id);
            }
        };

        // 7. KeyEnvelopeをSDK形式に変換
        let key_envelope = Self::to_key_envelope(&result.envelope);

        // sender_key_idとrecipient_key_idをbase64urlエンコード
        let sender_key_id_b64 = Self::encode_key_id_base64url(&sender_key_id_for_output);
        let recipient_key_id_b64 = Self::encode_key_id_base64url(&result.recipient_key_id);

        // TODO: State NodeにShareを送信
        // Shareを作成し、State Nodeに送信する必要がある

        let output = ShareContentOutput {
            content_id: input.content_id,
            recipient_public_key: input.recipient_public_key,
            sender_key_id: sender_key_id_b64,
            recipient_key_id: recipient_key_id_b64,
            key_envelope,
            delegated_access: Some(delegated_access),
            shared_at: Some(Utc::now().to_rfc3339()),
        };

        ApiResponse::success(output, trace_id)
    }

    /// コンテンツの共有を取り消す。
    ///
    /// `auth` は State Node へ送る `PUT /content/:id`（再暗号化後の同期）に転送する認証ヘッダ。本番では `Some` が必要。
    ///
    /// 処理フロー:
    /// 1. 入力のバリデーション
    /// 2. ContentIdに変換
    /// 3. 共有先の公開鍵をデコードしてrecipient_key_idを計算
    /// 4. ShareService::revoke_shareを呼び出し（ACLの更新）
    /// 5. State Node に更新を送信
    /// 6. 結果を返却
    pub fn revoke_share(
        &self,
        input: RevokeShareInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<RevokeShareOutput> {
        let trace_id = generate_trace_id();

        // 1. 入力のバリデーション
        for (field, value) in [
            ("content_id", input.content_id.as_str()),
            ("sender_public_key", input.sender_public_key.as_str()),
            ("recipient_public_key", input.recipient_public_key.as_str()),
        ] {
            if let Err(e) = Self::validate_non_empty(field, value) {
                return ApiResponse::error(e, trace_id);
            }
        }

        // 2. ContentIdに変換
        let content_id = ContentId::new(input.content_id.clone());

        let snapshot = match self.capture_revoke_share_snapshot(&content_id) {
            Ok(snapshot) => snapshot,
            Err(e) => return ApiResponse::error(e, trace_id),
        };

        let sender_public_key_bytes =
            match Self::decode_base64url_field("sender_public_key", &input.sender_public_key) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };
        let sender_key_id = Self::compute_key_id_from_public_key(&sender_public_key_bytes);

        // 3. 共有先の公開鍵をデコードしてrecipient_key_idを計算
        let recipient_public_key_bytes =
            match Self::decode_base64url_field("recipient_public_key", &input.recipient_public_key)
            {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };

        let recipient_key_id = Self::compute_key_id_from_public_key(&recipient_public_key_bytes);

        // 4. ShareService::revoke_shareを呼び出し
        let cmd = RevokeShareCommand {
            content_id,
            sender_key_id,
            recipient_key_id,
        };

        let result = match self.share_service.revoke_share(cmd) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(Self::map_share_error(e), trace_id);
            }
        };

        // revoke後に再暗号し、State Nodeのバージョンを進める
        let reencryption = match self.content_service.reencrypt(ReencryptContentCommand {
            content_id: ContentId::new(input.content_id.clone()),
        }) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(Self::map_reencrypt_error(e), trace_id);
            }
        };

        if let Some(response) = self.send_update_to_state_node(
            &input.content_id,
            &reencryption.encrypted_content,
            auth,
            trace_id.clone(),
        ) {
            if let Err(restore_err) = self.restore_revoke_share_snapshot(&snapshot) {
                let remote_message = response
                    .error
                    .as_ref()
                    .map(|e| format!("{e:?}"))
                    .unwrap_or_else(|| "unknown state node update failure".into());
                return ApiResponse::error(
                    ApiError::Internal(format!(
                        "State Node revoke sync failed and local rollback also failed: remote={remote_message}, restore={restore_err}"
                    )),
                    trace_id,
                );
            }
            return response;
        }

        let output = RevokeShareOutput {
            content_id: result.content_id.as_str().to_string(),
            recipient_public_key: input.recipient_public_key,
            revoked: true,
            revoked_at: Some(Utc::now().to_rfc3339()),
        };

        ApiResponse::success(output, trace_id)
    }

    /// 共有されたコンテンツ payload を復号する
    ///
    /// 処理フロー:
    /// 1. 入力のバリデーション
    /// 2. ContentIdに変換
    /// 3. sender_key_idとrecipient_key_idをデコード
    /// 4. 秘密鍵をデコード
    /// 5. KeyEnvelopeの各フィールドをデコード
    /// 6. KeyEnvelopeをmonas-content形式に変換
    /// 7. ShareService::unwrap_cek_from_envelopeを呼び出してCEKを取得
    /// 8. ContentService::decrypt_with_cekを呼び出してコンテンツを復号
    /// 9. 結果を返却
    pub fn decrypt_shared_content(
        &self,
        input: DecryptSharedContentInput,
    ) -> ApiResponse<DecryptSharedContentOutput> {
        let trace_id = generate_trace_id();

        // 1. 入力のバリデーション
        for (field, value) in [
            ("content_id", input.content_id.as_str()),
            ("sender_key_id", input.sender_key_id.as_str()),
            ("recipient_key_id", input.recipient_key_id.as_str()),
            ("private_key", input.private_key.as_str()),
            ("key_envelope.enc", input.key_envelope.enc.as_str()),
            (
                "key_envelope.wrapped_cek",
                input.key_envelope.wrapped_cek.as_str(),
            ),
            (
                "key_envelope.ciphertext",
                input.key_envelope.ciphertext.as_str(),
            ),
        ] {
            if let Err(e) = Self::validate_non_empty(field, value) {
                return ApiResponse::error(e, trace_id);
            }
        }

        // 2. ContentIdに変換
        let content_id = ContentId::new(input.content_id.clone());

        // 3. sender_key_idとrecipient_key_idをデコード
        let sender_key_id_bytes =
            match Self::decode_base64url_field("sender_key_id", &input.sender_key_id) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };
        let sender_key_id = KeyId::new(sender_key_id_bytes);

        let recipient_key_id_bytes =
            match Self::decode_base64url_field("recipient_key_id", &input.recipient_key_id) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };
        let recipient_key_id = KeyId::new(recipient_key_id_bytes);

        // 4. 秘密鍵をデコード
        let private_key_bytes =
            match Self::decode_base64url_field("private_key", &input.private_key) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };

        // 5. KeyEnvelopeの各フィールドをデコード
        let enc = match Self::decode_base64url_field("key_envelope.enc", &input.key_envelope.enc) {
            Ok(v) => v,
            Err(e) => return ApiResponse::error(e, trace_id),
        };
        let wrapped_cek = match Self::decode_base64url_field(
            "key_envelope.wrapped_cek",
            &input.key_envelope.wrapped_cek,
        ) {
            Ok(v) => v,
            Err(e) => return ApiResponse::error(e, trace_id),
        };
        let ciphertext = match Self::decode_base64url_field(
            "key_envelope.ciphertext",
            &input.key_envelope.ciphertext,
        ) {
            Ok(v) => v,
            Err(e) => return ApiResponse::error(e, trace_id),
        };

        // 6. KeyEnvelopeをmonas-content形式に変換
        let wrapped_recipient = WrappedRecipientKey::new(recipient_key_id, enc, wrapped_cek);
        let domain_envelope = DomainKeyEnvelope::new(
            content_id.clone(),
            KeyWrapAlgorithm::HpkeV1,
            sender_key_id,
            wrapped_recipient,
            ciphertext.clone(),
        );

        // 7. ShareService::unwrap_cek_from_envelopeを呼び出してCEKを取得
        let cek = match self
            .share_service
            .unwrap_cek_from_envelope(&domain_envelope, &private_key_bytes)
        {
            Ok(cek) => cek,
            Err(e) => {
                return ApiResponse::error(Self::map_share_error(e), trace_id);
            }
        };

        // 8. ContentService::decrypt_with_cekを呼び出してコンテンツを復号
        let raw_content: Vec<u8> =
            match self
                .content_service
                .decrypt_with_cek(content_id.clone(), cek, ciphertext)
            {
                Ok(content) => content,
                Err(e) => {
                    let error_msg = match e {
                        DecryptWithCekError::ContentIdMismatch { expected, actual } => {
                            format!(
                                "Content ID mismatch: expected {}, actual {}",
                                expected, actual
                            )
                        }
                        DecryptWithCekError::Domain(_) => "Failed to decrypt content".to_string(),
                    };
                    return ApiResponse::error(ApiError::Internal(error_msg), trace_id);
                }
            };

        let content_base64url = encode_base64url(&raw_content);

        let output = DecryptSharedContentOutput {
            content_id: input.content_id,
            content: content_base64url,
            version: input.version.unwrap_or_default(),
            metadata: None, // TODO: メタデータを取得する機能を実装
        };

        ApiResponse::success(output, trace_id)
    }
}
