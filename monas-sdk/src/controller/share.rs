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
    Permission, ReissuedKeyEnvelope, RevokeShareInput, RevokeShareOutput, ShareContentInput,
    ShareContentOutput,
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
use monas_content::infrastructure::{key_wrapping::HpkeV1KeyWrapping, MultiStorageRepository};

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

/// ShareServiceの型エイリアス（可読性向上のため）。
///
/// share repository / CEK ストア / public key directory は `Arc<dyn …>` を受けるので、
/// in-memory / sled などの persistence backend を実行時に切り替えられる。
pub(super) type ShareServiceInstance = ShareService<
    DynShareRepository,
    MultiStorageRepository,
    super::content::DynCekStore,
    DynPublicKeyDirectory,
    HpkeV1KeyWrapping,
>;

/// SDK が使う share repository の動的型。
pub(super) type DynShareRepository = std::sync::Arc<
    dyn monas_content::application_service::share_service::ShareRepository + Send + Sync,
>;

/// SDK が使う PublicKeyDirectory の動的型。
pub(super) type DynPublicKeyDirectory = std::sync::Arc<
    dyn monas_content::application_service::share_service::PublicKeyDirectory + Send + Sync,
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
            key_epoch: domain_envelope.key_epoch(),
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
            ("sender_private_key", input.sender_private_key.as_str()),
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

        // 送信者の秘密鍵(HPKE Auth モード wrap の送信者認証に使用。保存はしない)
        let sender_private_key_bytes =
            match Self::decode_base64url_field("sender_private_key", &input.sender_private_key) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };

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
            sender_private_key: sender_private_key_bytes.clone(),
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
                    sender_private_key: sender_private_key_bytes.clone(),
                    recipient_key_id: result.recipient_key_id.clone(),
                };
                if let Err(rb) = self.share_service.revoke_share(rollback_cmd) {
                    return ApiResponse::error(
                        super::combine_rollback_failure(
                            e,
                            rb,
                            "Delegated token issuance",
                            "issuance",
                            "rollback",
                        ),
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
            sender_public_key: input.sender_public_key,
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
    /// 4. State Node の `min_valid_issued_at` を進めて既発行 Token を一括失効
    /// 5. CEK をローテーションして再暗号化
    /// 6. ShareService::revoke_shareを呼び出し（ACL 更新 + 残存受信者向け envelope 再発行）
    /// 7. State Node に再暗号化後の ciphertext を送信
    /// 8. 結果を返却
    ///
    /// 4 が無いと、取り消した相手の委譲 write Token が TTL 満了まで有効なまま残る
    /// （CEK ローテーションは復号を止めるだけで、書き込み権限は止めない）。
    ///
    /// 失効は残存受信者の Token も巻き添えにする。呼び出し側は
    /// `RevokeShareOutput::token_invalidated_at` より後に Token を再発行すること。
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
            ("sender_private_key", input.sender_private_key.as_str()),
            ("recipient_public_key", input.recipient_public_key.as_str()),
        ] {
            if let Err(e) = Self::validate_non_empty(field, value) {
                return ApiResponse::error(e, trace_id);
            }
        }

        // 2. ContentIdに変換
        let content_id = ContentId::new(input.content_id.clone());

        // この content への revoke を直列化する。revoke は ACL・CEK・ローカル
        // ciphertext・state node 状態にまたがる load-modify-save で、どこにも
        // version CAS が無い。`MonasController` は gateway から `Arc` 共有され
        // 同時に呼ばれるため、ロックが無いと 2 つの revoke が同じ Share を読んで
        // 後勝ちで save し、片方の受信者削除が消える(lost update)。
        // 異なる CEK が同じ key_epoch として配られる問題も同じ原因。
        //
        // snapshot 取得より前にロックを取る: 後にすると、読んだ snapshot が
        // ロック取得までの間に古くなり、失敗時の巻き戻しが他方の結果を
        // 上書きしてしまう。
        //
        // ロックはプロセス内のみ。複数 gateway プロセスからの並行 revoke は
        // これでは防げず、state node 側の CAS が必要になる(現状の制約)。
        // ガードを drop するとエントリは表から消えるので、revoke した content の
        // 数だけレジストリが伸び続けることはない。
        let _revoke_guard = self.content_revoke_locks.lock(content_id.as_str());

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

        // 送信者の秘密鍵(再発行 envelope の HPKE Auth モード wrap に使用。保存はしない)
        let sender_private_key_bytes =
            match Self::decode_base64url_field("sender_private_key", &input.sender_private_key) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };

        // 3. 共有先の公開鍵をデコードしてrecipient_key_idを計算
        let recipient_public_key_bytes =
            match Self::decode_base64url_field("recipient_public_key", &input.recipient_public_key)
            {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };

        let recipient_key_id = Self::compute_key_id_from_public_key(&recipient_public_key_bytes);

        // 3.5. 先に state node の `min_valid_issued_at` を進めて、既発行の委譲 Token を
        //      一括失効させる。CEK ローテーションだけでは「取り消した相手が持っている
        //      write Token」は TTL 満了まで生きたままで、新しい状態へ書き込み続けられる
        //      (docs/design.md「アクセス取り消し」の定義との食い違い)。
        //
        //      順序が invalidate → rotate である理由: 逆にすると、rotate から
        //      invalidate までの窓で取り消し済みの相手が書き込める。先に失効させて
        //      おけば、後段が失敗してローカルを巻き戻しても余分な失効が残るだけで、
        //      害は「残存受信者が Token を再発行してもらう必要がある」ことに留まる
        //      (これは CEK ローテーション時にどのみち必要になる)。
        //
        //      state node 連携なし(`auth` が None、ローカル専用テスト等)の場合は
        //      失効させる対象の Token も存在しないので何もしない。
        let state_node_content_id = input
            .remote_content_id
            .as_deref()
            .unwrap_or(&input.content_id)
            .to_string();
        let token_invalidated_at = if auth.is_some() {
            match self.send_invalidate_to_state_node::<RevokeShareOutput>(
                &state_node_content_id,
                auth,
                trace_id.clone(),
            ) {
                Ok(v) => v,
                // ここはまだローカル状態を一切変更していないので巻き戻し不要。
                Err(response) => return response,
            }
        } else {
            None
        };

        // 4. まず CEK をローテーションして再暗号化する。
        //    ShareService::revoke_share は「その時点の CEK・ciphertext」で残存受信者向け
        //    KeyEnvelope を再発行するため、**reencrypt が先**でないと旧 CEK の envelope を
        //    配ってしまい、ローテーションの意味がなくなる
        //    (service 側 step 2 の「再暗号化後はここが新しい CEK になっている想定」に一致させる)。
        let reencryption = match self.content_service.reencrypt(ReencryptContentCommand {
            content_id: ContentId::new(input.content_id.clone()),
        }) {
            Ok(result) => result,
            Err(e) => {
                // reencrypt は途中失敗時に旧 CEK を書き戻すが、content repo 側の状態も
                // 含めて確実に pre-revoke へ戻すため snapshot 復元も行う。
                //
                // TODO(pr29-followup): この経路は SDK 公開 API だけでは安定して再現できないため
                // integration test が存在しない。test-hook feature を導入してから
                // tests/share_controller_integration_test.rs にカバレッジを追加する。
                // 参考: PR #45 commit 392d6f1 の本文。
                let primary = Self::map_reencrypt_error(e);
                if let Err(restore_err) = self.restore_revoke_share_snapshot(&snapshot) {
                    return ApiResponse::error(
                        super::combine_rollback_failure(
                            primary,
                            restore_err,
                            "Reencrypt",
                            "reencrypt",
                            "restore",
                        ),
                        trace_id,
                    );
                }
                return ApiResponse::error(primary, trace_id);
            }
        };

        // 5. ShareService::revoke_shareを呼び出し(ACL 更新 + 残存受信者向けに
        //    新 CEK・新 ciphertext で KeyEnvelope を再発行)
        let cmd = RevokeShareCommand {
            content_id,
            sender_key_id,
            sender_private_key: sender_private_key_bytes,
            recipient_key_id,
        };

        let result = match self.share_service.revoke_share(cmd) {
            Ok(result) => result,
            Err(e) => {
                // ShareService::revoke_share は share_repository を先に save してから envelope を
                // 生成するため、途中で失敗した場合も ACL は既に変更されている可能性がある。
                // 直前の reencrypt の巻き戻しも含め、snapshot から share/content/cek を復元する。
                let primary = Self::map_share_error(e);
                if let Err(restore_err) = self.restore_revoke_share_snapshot(&snapshot) {
                    return ApiResponse::error(
                        super::combine_rollback_failure(
                            primary,
                            restore_err,
                            "Revoke",
                            "revoke",
                            "restore",
                        ),
                        trace_id,
                    );
                }
                return ApiResponse::error(primary, trace_id);
            }
        };

        // State Node は系列ID（remote_content_id）でコンテンツを管理する。
        // ローカル版IDしか送らないと State Node 側で未知のコンテンツ扱いになる。
        if let Some(response) = self.send_update_to_state_node(
            &state_node_content_id,
            &reencryption.encrypted_content,
            auth,
            trace_id.clone(),
        ) {
            if let Err(restore_err) = self.restore_revoke_share_snapshot(&snapshot) {
                let primary = response.error.clone().unwrap_or_else(|| {
                    ApiError::Internal("unknown state node update failure".into())
                });
                return ApiResponse::error(
                    super::combine_rollback_failure(
                        primary,
                        restore_err,
                        "State Node revoke sync",
                        "remote",
                        "restore",
                    ),
                    trace_id,
                );
            }
            return response;
        }

        // 残存受信者向けの再発行 envelope(新 CEK・新 ciphertext)を出力に載せる。
        // owner はこれを各受信者へ配布し、受信者が decrypt_shared_content で処理すると
        // ローカル保存済み CEK がローテーション後のものへ更新される。
        let reissued_envelopes = result
            .envelopes
            .iter()
            .map(|env| ReissuedKeyEnvelope {
                recipient_key_id: encode_base64url(env.recipient().key_id().as_bytes()),
                key_envelope: Self::to_key_envelope(env),
            })
            .collect();

        let output = RevokeShareOutput {
            content_id: result.content_id.as_str().to_string(),
            recipient_public_key: input.recipient_public_key,
            revoked: true,
            revoked_at: Some(Utc::now().to_rfc3339()),
            reissued_envelopes,
            token_invalidated_at,
        };

        ApiResponse::success(output, trace_id)
    }

    /// 共有されたコンテンツ payload を復号する
    ///
    /// 処理フロー:
    /// 1. 入力のバリデーション
    /// 2. ContentIdに変換
    /// 3. sender_public_keyとrecipient_key_idをデコード
    /// 4. 送信者鍵ピン(TOFU)と鍵世代(key_epoch)の検証:
    ///    - 初回はこの content の送信者公開鍵候補として受け入れ、復号成功時にピン留め
    ///    - 2回目以降はピン済み公開鍵と一致しない送信者を拒否し、
    ///      記録済みの鍵世代より古い envelope を拒否する(rotation 巻き戻し replay 防止)
    /// 5. KeyEnvelopeの各フィールドをデコード
    /// 6. KeyEnvelopeをmonas-content形式に変換
    /// 7. ShareService::unwrap_cek_from_envelopeを呼び出してCEKを取得
    ///    (HPKE Auth モード: unwrap 成功 = ピン留め鍵の持ち主が作った envelope の証明)
    /// 8. ContentService::decrypt_with_cekを呼び出してコンテンツを復号
    /// 9. CEK と送信者鍵ピン・鍵世代を保存し、結果を返却
    pub fn decrypt_shared_content(
        &self,
        input: DecryptSharedContentInput,
    ) -> ApiResponse<DecryptSharedContentOutput> {
        let trace_id = generate_trace_id();

        // 1. 入力のバリデーション
        for (field, value) in [
            ("content_id", input.content_id.as_str()),
            ("sender_public_key", input.sender_public_key.as_str()),
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

        // 3. sender_public_keyとrecipient_key_idをデコード
        let sender_public_key_bytes =
            match Self::decode_base64url_field("sender_public_key", &input.sender_public_key) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };
        let sender_key_id = Self::compute_key_id_from_public_key(&sender_public_key_bytes);

        let recipient_key_id_bytes =
            match Self::decode_base64url_field("recipient_key_id", &input.recipient_key_id) {
                Ok(v) => v,
                Err(e) => return ApiResponse::error(e, trace_id),
            };
        let recipient_key_id = KeyId::new(recipient_key_id_bytes);

        // 4. 送信者鍵ピン(TOFU)と鍵世代の検証。
        //    unwrap に使う鍵は「入力された鍵」ではなく「ピン済みの鍵」を優先する:
        //    ピンがある限り、呼び出し側が違う鍵を渡しても検証の根は動かない。
        //
        //    NOTE: 初回(ピン未設定)は呼び出し側の鍵をそのまま信頼する TOFU で
        //    あり、送信者認証ではない。HPKE Auth が示すのは「その鍵の持ち主が
        //    作った」ことだけで、「owner が作った」ことではないため、平文を知る
        //    第三者が正規 envelope より先にピンを取れる。初回鍵を owner identity
        //    へ束縛する修正は trust anchor の課題として別 issue で追跡する。
        let pinned = match self.sender_pin_store.load(content_id.as_str()) {
            Ok(p) => p,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Internal(format!("sender key pin store error: {e}")),
                    trace_id,
                );
            }
        };
        let effective_sender_public_key = match &pinned {
            None => sender_public_key_bytes.clone(),
            Some(pin) => {
                if pin.sender_public_key != sender_public_key_bytes {
                    return ApiResponse::error(
                        ApiError::Forbidden(format!(
                            "sender public key does not match the key pinned for content {} on                              first share. Rejecting the envelope: a different sender cannot                              replace the content encryption key.",
                            content_id.as_str()
                        )),
                        trace_id,
                    );
                }
                if input.key_envelope.key_epoch < pin.key_epoch {
                    return ApiResponse::error(
                        ApiError::Conflict(format!(
                            "stale key envelope: its key_epoch {} is older than the last accepted                              epoch {} for content {} (possible replay of a pre-rotation envelope).                              Ask the owner for the latest KeyEnvelope.",
                            input.key_envelope.key_epoch,
                            pin.key_epoch,
                            content_id.as_str()
                        )),
                        trace_id,
                    );
                }
                pin.sender_public_key.clone()
            }
        };

        // 秘密鍵をデコード
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
            input.key_envelope.key_epoch,
        );

        // 7. ShareService::unwrap_cek_from_envelopeを呼び出してCEKを取得。
        //    HPKE Auth モードのため、unwrap 成功 = effective_sender_public_key の
        //    持ち主がこの envelope を作った証明になる(偽送信者の envelope はここで失敗する)。
        let cek = match self.share_service.unwrap_cek_from_envelope(
            &domain_envelope,
            &private_key_bytes,
            &effective_sender_public_key,
        ) {
            Ok(cek) => cek,
            // HPKE Auth モードでは unwrap 失敗が「送信者検証の失敗」を意味し得る
            // (偽送信者の envelope / AAD 改ざん / 鍵不一致はすべてここで落ちる)。
            Err(ShareApplicationError::KeyWrapping(msg)) => {
                return ApiResponse::error(
                    ApiError::Forbidden(format!(
                        "failed to unwrap the CEK with the expected sender public key: the \
                         envelope was not created by the pinned sender, or its fields \
                         (content_id / recipient / key_epoch) were tampered with: {msg}"
                    )),
                    trace_id,
                );
            }
            Err(e) => {
                return ApiResponse::error(Self::map_share_error(e), trace_id);
            }
        };

        // 8. ContentService::decrypt_with_cekを呼び出してコンテンツを復号
        let raw_content: Vec<u8> =
            match self
                .content_service
                .decrypt_with_cek(content_id.clone(), cek.clone(), ciphertext)
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

        // 9. ローカル状態(送信者ピン・鍵世代・CEK)の更新。
        //
        //    unwrap + 復号の成功 = 送信者と鍵世代の正しさが暗号学的に確認できた
        //    時点なので、ここで初めてローカルへ反映する。
        //
        //    3つ組は 1 レコードにまとめて単一の compare-and-swap で入れ替える。
        //    以前は「pin を CAS してから CEK を別ストアへ save」していたが、
        //    2 つの commit に分かれている限り、間に別の世代の処理が割り込めば
        //    `pin = N+1, CEK = N` のような不整合が作れてしまう
        //    (`SenderKeyPin` のモジュール doc に interleaving を記載)。
        //
        //    CAS が失敗した = 別の処理が先に同じかより新しい世代へ進めた、なので
        //    こちらの(古い)3つ組は捨てる。
        let new_pin = monas_content::application_service::share_service::SenderKeyPin {
            sender_public_key: effective_sender_public_key,
            key_epoch: input.key_envelope.key_epoch,
            cek: Some(cek.0.clone()),
        };
        //    ここへ来る時点で、記録済み世代より古い envelope は step 4 で既に
        //    拒否されている(`stale key envelope`)。よって残るのは「同じ世代」か
        //    「より新しい世代」のどちらかで、どちらも CAS の期待値が
        //    「今読んだレコードそのもの」なので巻き戻しにはならない。
        //
        //    同一世代でも CAS を通すのは、旧レコードが CEK を持たない
        //    (この修正より前に作られた、あるいは CEK 保存に失敗した)場合に、
        //    同じ世代のまま CEK を埋め直して回復できるようにするため。
        //
        //    権威レコードが既にこの3つ組そのものなら CAS 自体は不要。ただし
        //    CEK キャッシュだけが欠けている可能性はあるので、その更新は通す。
        let already_current = pinned.as_ref() == Some(&new_pin);

        let should_refresh_cek_cache = if already_current {
            true
        } else {
            let advanced = match self.sender_pin_store.compare_and_save(
                content_id.as_str(),
                pinned.as_ref(),
                &new_pin,
            ) {
                Ok(advanced) => advanced,
                Err(e) => {
                    return ApiResponse::error(
                        ApiError::Internal(format!(
                            "decrypted the shared content but failed to persist the sender key pin \
                             for {}: {e}. Re-process the KeyEnvelope.",
                            content_id.as_str()
                        )),
                        trace_id,
                    );
                }
            };
            // CAS に負けた場合は、勝った側がより新しい(または同じ)世代を
            // 書いているので、こちらの CEK でキャッシュを上書きしてはいけない。
            advanced
        };

        // CEK ストアは上の権威レコードから導出されるキャッシュ。
        // CEK は受信者デバイスのローカルに留まり、ネットワークには出ない。
        if should_refresh_cek_cache {
            if let Err(e) = self.content_service.cek_store.save(&content_id, &cek) {
                // 権威レコードには CEK が入っているので、ここで失敗しても
                // 再処理すればキャッシュを埋め直せる。ただし黙って成功を
                // 返すと、呼び出し側は「以後この端末で検証付き read ができる」
                // と信じるのに実際は MissingKey で失敗するため、エラーにする。
                return ApiResponse::error(
                    ApiError::Internal(format!(
                        "decrypted the shared content but failed to persist its CEK for {}: {e}. \
                         Re-process the KeyEnvelope to enable state-node reads on this device.",
                        content_id.as_str()
                    )),
                    trace_id,
                );
            }
        }

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
