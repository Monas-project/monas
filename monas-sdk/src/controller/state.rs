use base64::{
    engine::general_purpose::STANDARD as BASE64_STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};
use sha2::{Digest, Sha256};

use crate::common::{
    encode_base64url, generate_trace_id, ApiError, ApiResponse, StateNodeAuthContext,
};
use crate::models::state::{
    GetHistoryInput, GetHistoryOutput, GetLatestVersionInput, GetLatestVersionOutput,
    ReadContentFromStateNodeInput, ReadContentFromStateNodeOutput, VerifyIntegrityInput,
    VerifyIntegrityOutput,
};
use crate::models::state_node::{StateNodeContentDataResponse, StateNodeContentHistoryResponse};

use super::MonasController;

impl MonasController {
    fn validate_state_content_id<T>(content_id: &str, trace_id: String) -> Option<ApiResponse<T>> {
        if content_id.is_empty() {
            return Some(ApiResponse::error(
                ApiError::Validation("content_id must not be empty".into()),
                trace_id,
            ));
        }
        None
    }

    /// State Node の読み取り API 用の認証コンテキストを解決する。
    ///
    /// 呼び出し元が Authorization を明示していればそのまま透過する。
    /// 無ければ書き込み系（create/update/delete）と同じく monas-account で
    /// `read:<content_id>:<timestamp>` に署名し、`user:<hex(pubkey)>` トークンを組み立てる。
    /// State Node 側は読み取り時にこの署名メッセージを検証する
    /// （`verify_read_access` → `verify_caller_signature("read", content_id, ..)`）。
    /// 署名を content_id にバインドすることで、relay 先ノード等に渡った署名を
    /// 他コンテンツの読み取りに再利用されることを防ぐ。
    fn resolve_state_read_auth<T>(
        &self,
        auth: Option<&StateNodeAuthContext>,
        content_id: &str,
        trace_id: &str,
    ) -> Result<Option<StateNodeAuthContext>, ApiResponse<T>> {
        match auth {
            Some(ctx) if ctx.authorization.is_none() => {
                self.prepare_state_node_metadata_auth(auth, "read", content_id, trace_id)
            }
            _ => Ok(auth.cloned()),
        }
    }

    fn state_node_get_string<T>(
        &self,
        url: &str,
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Result<(u16, String), ApiResponse<T>> {
        if let Some(ctx) = auth {
            self.resolve_request_timestamp::<T>(ctx, &trace_id)?;
        }

        let trace_id_for_call = trace_id.clone();
        let resp = Self::attach_state_node_auth(self.agent.get(url), auth)
            .config()
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(|e| {
                ApiResponse::error(
                    ApiError::from_ureq_error("Failed to call State Node", e),
                    trace_id_for_call,
                )
            })?;

        let status = resp.status().as_u16();
        let body = resp.into_body().read_to_string().map_err(|e| {
            ApiResponse::error(
                ApiError::Internal(format!("Failed to read State Node response body: {e}")),
                trace_id,
            )
        })?;

        Ok((status, body))
    }
    fn get_state_node_history<T>(
        &self,
        content_id: &str,
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Result<StateNodeContentHistoryResponse, ApiResponse<T>> {
        let url = format!("{}/content/{}/history", self.state_node_url, content_id);

        let (status, body) = self.state_node_get_string::<T>(&url, auth, trace_id.clone())?;
        if let Some(err) = Self::try_state_node_http_error(status, &body, trace_id.clone()) {
            return Err(err);
        }

        serde_json::from_str::<StateNodeContentHistoryResponse>(&body).map_err(|e| {
            ApiResponse::error(
                ApiError::Internal(format!("Failed to parse State Node response: {e}")),
                trace_id,
            )
        })
    }

    fn get_state_node_version_data<T>(
        &self,
        content_id: &str,
        version: &str,
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Result<StateNodeContentDataResponse, ApiResponse<T>> {
        let url = format!(
            "{}/content/{}/version/{}",
            self.state_node_url, content_id, version
        );

        let (status, body) = self.state_node_get_string::<T>(&url, auth, trace_id.clone())?;
        if let Some(err) = Self::try_state_node_http_error(status, &body, trace_id.clone()) {
            return Err(err);
        }

        serde_json::from_str::<StateNodeContentDataResponse>(&body).map_err(|e| {
            ApiResponse::error(
                ApiError::Internal(format!("Failed to parse State Node response: {e}")),
                trace_id,
            )
        })
    }

    /// コンテンツの最新バージョン（CID）を取得する。
    ///
    /// `auth` は State Node の `GET /content/:id/history` に転送する認証ヘッダ。本番では `Some` が必要。
    pub fn get_latest_version(
        &self,
        input: GetLatestVersionInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<GetLatestVersionOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }

        let auth = match self.resolve_state_read_auth::<GetLatestVersionOutput>(
            auth,
            &input.content_id,
            &trace_id,
        ) {
            Ok(resolved) => resolved,
            Err(e) => return e,
        };
        let history = match self.get_state_node_history::<GetLatestVersionOutput>(
            &input.content_id,
            auth.as_ref(),
            trace_id.clone(),
        ) {
            Ok(h) => h,
            Err(e) => return e,
        };

        let latest = history
            .versions
            .last()
            .cloned()
            .unwrap_or_else(|| input.content_id.clone());

        ApiResponse::success(
            GetLatestVersionOutput {
                content_id: input.content_id,
                latest_version: latest,
                updated_at: None,
            },
            trace_id,
        )
    }

    /// コンテンツの更新履歴を取得する。
    ///
    /// `auth` は State Node の `GET /content/:id/history` に転送する認証ヘッダ。本番では `Some` が必要。
    pub fn get_history(
        &self,
        input: GetHistoryInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<GetHistoryOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }

        let auth = match self.resolve_state_read_auth::<GetHistoryOutput>(
            auth,
            &input.content_id,
            &trace_id,
        ) {
            Ok(resolved) => resolved,
            Err(e) => return e,
        };
        let history = match self.get_state_node_history::<GetHistoryOutput>(
            &input.content_id,
            auth.as_ref(),
            trace_id.clone(),
        ) {
            Ok(h) => h,
            Err(e) => return e,
        };

        // limit はState Node側に無いので、SDK側で適用（末尾=最新側を優先）
        let mut versions = history.versions;
        let limit = input.limit as usize;
        if limit > 0 && versions.len() > limit {
            versions = versions[versions.len() - limit..].to_vec();
        }

        ApiResponse::success(
            GetHistoryOutput {
                content_id: input.content_id,
                versions,
            },
            trace_id,
        )
    }

    /// State Node から content を読み、検証・復号して平文を返す(検証付き read)。
    ///
    /// `docs/design.md` §10「read応答の完全性検証」の実 read 経路。処理フロー:
    /// 1. `read:{content_id}:{timestamp}` 署名の認証コンテキストを解決
    /// 2. 版を決定(`input.version` 指定があればその版、無ければ履歴の最新)
    /// 3. Node CBOR を取得し、CID 再計算で改ざん検証
    /// 4. ローカル cek_store から CEK を引き、AES-GCM 復号 + plain CID 照合
    ///
    /// CEK は「自分が作成した content」または「share の KeyEnvelope を処理済みの
    /// content」(`decrypt_shared_content` が保存する)についてローカルに存在する。
    ///
    /// **保証範囲**: 検証できるのは「返された Node の payload が、要求した版 CID に
    /// 対して真正であること」まで。「その版が本当に最新か」「正規の writer が書いた
    /// 版か」は保証しない — 版メタデータ(parents 等)に真正性が無く、観測済みの
    /// 正規暗号文を任意の parents で包み直した Node は CID 検証を通過するため。
    /// 版の真正性とロールバック耐性には owner 署名等の trust anchor が必要
    /// (issue #59)。分散システムである以上、sync 遅延による stale read は
    /// 正常な挙動であり、それと攻撃を応答単体で区別することはできない。
    pub fn read_content_from_state_node(
        &self,
        input: ReadContentFromStateNodeInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<ReadContentFromStateNodeOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }
        if input.local_content_id.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("local_content_id must not be empty".into()),
                trace_id,
            );
        }

        let auth = match self.resolve_state_read_auth::<ReadContentFromStateNodeOutput>(
            auth,
            &input.content_id,
            &trace_id,
        ) {
            Ok(resolved) => resolved,
            Err(e) => return e,
        };
        let auth = auth.as_ref();

        // 版の決定。明示指定が無ければ履歴の最新を読む。
        // 履歴は署名も系列検証も無いため「どの版を読むか」の選択にしか使えない。
        // 選ばれた版の payload は下の CID 検証が守るが、その版が最新である
        // ことは保証されない(上記「保証範囲」を参照)。
        let version = match input.version.clone() {
            Some(v) => v,
            None => {
                let history = match self.get_state_node_history::<ReadContentFromStateNodeOutput>(
                    &input.content_id,
                    auth,
                    trace_id.clone(),
                ) {
                    Ok(h) => h,
                    Err(e) => return e,
                };
                let latest = history
                    .versions
                    .last()
                    .cloned()
                    .unwrap_or_else(|| input.content_id.clone());
                latest
            }
        };

        // Node CBOR の取得 + CID 検証(A)
        let state_node_data = match self
            .get_state_node_version_data::<ReadContentFromStateNodeOutput>(
                &input.content_id,
                &version,
                auth,
                trace_id.clone(),
            ) {
            Ok(d) => d,
            Err(e) => return e,
        };

        let node_bytes = match BASE64_STANDARD.decode(&state_node_data.data) {
            Ok(b) => b,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Internal(format!("invalid base64 data from state node: {e}")),
                    trace_id,
                );
            }
        };

        // CID 再計算による改ざん検証。ここを通れば payload は要求した版 CID に
        // 対して真正(復号は下の verify_and_decrypt_relay_read が再度行う)。
        if let Err(e) = monas_content::infrastructure::node_verification::verify_and_extract(
            &node_bytes,
            &version,
        ) {
            {
                return ApiResponse::error(
                    ApiError::Internal(format!(
                        "state node response failed CID verification (tampered response?): {e}"
                    )),
                    trace_id,
                );
            }
        }

        // CEK ロード + AES-GCM 復号 + plain CID 照合
        //
        // CEK は「送信者ピンの権威レコード」を優先する。CEK ストアは、その
        // レコードから導出されるキャッシュに過ぎず、CAS 成功後の書き込み順が
        // 入れ替わると古い世代へ巻き戻り得る(世代 N の handler が CAS 後に
        // 停止し、その間に N+1 が権威レコードとキャッシュを進め、その後 N が
        // 再開してキャッシュだけを N に戻す)。権威レコードから直接引けば、
        // その巻き戻りは read に影響しない。
        //
        // 自分で作成した content には送信者ピンが存在しないので、その場合は
        // 従来どおりストアを引く。
        let local_content_id =
            monas_content::domain::content_id::ContentId::new(input.local_content_id.clone());
        let pinned_cek = match self.sender_pin_store.load(&input.local_content_id) {
            Ok(pin) => pin
                .and_then(|p| p.cek)
                .map(monas_content::domain::content::ContentEncryptionKey),
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Internal(format!("sender key pin store error: {e}")),
                    trace_id,
                );
            }
        };
        let plaintext = match self.content_service.verify_and_decrypt_relay_read(
            &node_bytes,
            &version,
            local_content_id,
            pinned_cek,
        ) {
            Ok(read) => read.plaintext,
            Err(e) => {
                return ApiResponse::error(
                    Self::map_verified_read_error(e, &input.local_content_id),
                    trace_id,
                );
            }
        };

        ApiResponse::success(
            ReadContentFromStateNodeOutput {
                content_id: input.content_id,
                local_content_id: input.local_content_id,
                version,
                content: encode_base64url(&plaintext),
            },
            trace_id,
        )
    }

    /// `verify_and_decrypt_relay_read` のエラーを、呼び出し側が対処を判断できる
    /// `ApiError` へ写像する。特に「CEK が無い」「CEK が合わない」は
    /// share / rotation / revoke のどの状況かをメッセージで区別する。
    fn map_verified_read_error(
        e: monas_content::application_service::content_service::VerifiedReadError,
        local_content_id: &str,
    ) -> ApiError {
        use monas_content::application_service::content_service::{
            DecryptWithCekError, VerifiedReadError,
        };
        match e {
            VerifiedReadError::NodeVerification(err) => ApiError::Internal(format!(
                "state node response failed CID verification (tampered response?): {err}"
            )),
            VerifiedReadError::KeyStore(err) => {
                ApiError::Internal(format!("CEK store error: {err:?}"))
            }
            VerifiedReadError::MissingKey => ApiError::NotFound(format!(
                "no content encryption key for local content {local_content_id} on this device: \
                 the content was neither created here nor received via share on this device. \
                 Process its share KeyEnvelope (POST /share/decrypt) first."
            )),
            VerifiedReadError::Decrypt(DecryptWithCekError::Domain(_)) => ApiError::Forbidden(
                "decryption failed with the locally stored CEK: the key may be stale after a CEK \
                 rotation, or your access may have been revoked. If you still have access, \
                 re-process the latest share KeyEnvelope to refresh the stored CEK."
                    .to_string(),
            ),
            VerifiedReadError::Decrypt(DecryptWithCekError::ContentIdMismatch {
                expected,
                actual,
            }) => ApiError::Conflict(format!(
                "decrypted content does not match local_content_id (expected {expected}, got \
                 {actual}): the content has likely been updated — pass the local content id that \
                 corresponds to the version being read"
            )),
        }
    }

    /// 取得したコンテンツの整合性を検証する。
    ///
    /// `auth` は State Node の履歴・バージ取得 API に転送する認証ヘッダ。本番では `Some` が必要。
    ///
    /// 処理フロー:
    /// 1. コンテンツのハッシュを計算
    /// 2. State Nodeから取得した情報と比較
    /// 3. 一致すれば valid: true
    pub fn verify_integrity(
        &self,
        input: VerifyIntegrityInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<VerifyIntegrityOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }

        if input.content.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("content must not be empty".into()),
                trace_id,
            );
        }

        let auth = match self.resolve_state_read_auth::<VerifyIntegrityOutput>(
            auth,
            &input.content_id,
            &trace_id,
        ) {
            Ok(resolved) => resolved,
            Err(e) => return e,
        };
        let auth = auth.as_ref();

        let content_bytes = match URL_SAFE_NO_PAD.decode(&input.content) {
            Ok(b) => b,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Validation(format!("Invalid content base64url: {e}")),
                    trace_id,
                );
            }
        };

        let computed_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&content_bytes);
            let digest = hasher.finalize();
            format!("{digest:x}")
        };

        let version_to_check = if let Some(v) = input.expected_version.clone() {
            v
        } else {
            match self.get_state_node_history::<VerifyIntegrityOutput>(
                &input.content_id,
                auth,
                trace_id.clone(),
            ) {
                Ok(h) => h
                    .versions
                    .last()
                    .cloned()
                    .unwrap_or_else(|| input.content_id.clone()),
                Err(e) => return e,
            }
        };

        let state_node_data = match self.get_state_node_version_data::<VerifyIntegrityOutput>(
            &input.content_id,
            &version_to_check,
            auth,
            trace_id.clone(),
        ) {
            Ok(d) => d,
            Err(e) => return e,
        };

        let node_bytes = match BASE64_STANDARD.decode(&state_node_data.data) {
            Ok(b) => b,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Internal(format!("invalid base64 data from state node: {e}")),
                    trace_id,
                );
            }
        };

        // State Node は read 応答として「Node 全体(CBOR)」を返す。まず CID を
        // 再計算して version と一致することを検証し(改ざん検知)、その上で
        // payload の暗号文を取り出す(§8.1)。照合先はクライアントが選択した
        // version に固定する。応答内の version は自己申告なので、それに対して
        // 照合すると任意の Node + その CID を返すだけで検証が通ってしまう。
        let state_bytes = match monas_content::infrastructure::node_verification::verify_and_extract(
            &node_bytes,
            &version_to_check,
        ) {
            Ok(verified) => verified.ciphertext,
            Err(e) => {
                return ApiResponse::success(
                    VerifyIntegrityOutput {
                        valid: false,
                        computed_hash,
                        reason: Some(format!("state node response failed CID verification: {e}")),
                    },
                    trace_id,
                );
            }
        };

        // State Node が保持するのは SDK が送信した「暗号文」なので、
        // local_content_id があればローカルに保存された暗号文とバイト比較する。
        // （平文 `content` と State Node のバイト列は一致し得ない。）
        let (valid, reason) = if let Some(local_id) = input.local_content_id.as_deref() {
            match self.content_service.fetch_encrypted(
                monas_content::domain::content_id::ContentId::new(local_id.to_string()),
            ) {
                Ok(local_cipher) => {
                    if local_cipher == state_bytes {
                        (true, None)
                    } else {
                        (
                            false,
                            Some(format!(
                                "state node ciphertext differs from local ciphertext (version={version_to_check})"
                            )),
                        )
                    }
                }
                Err(e) => (
                    false,
                    Some(format!(
                        "failed to load local ciphertext for {local_id}: {e}"
                    )),
                ),
            }
        } else {
            let valid = content_bytes == state_bytes;
            (
                valid,
                if valid {
                    None
                } else {
                    Some(format!(
                        "content mismatch with state node (version={version_to_check})"
                    ))
                },
            )
        };

        ApiResponse::success(
            VerifyIntegrityOutput {
                valid,
                computed_hash,
                reason,
            },
            trace_id,
        )
    }
}
