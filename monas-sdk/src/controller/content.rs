use base64::{
    engine::general_purpose::STANDARD as BASE64_STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};
use chrono::Utc;

use crate::common::{generate_trace_id, ApiError, ApiResponse, StateNodeAuthContext};
use crate::models::content::{
    CreateContentInput, CreateContentOutput, DeleteContentInput, DeleteContentOutput,
    GetContentInput, GetContentOutput, UpdateContentInput, UpdateContentOutput,
};
use crate::models::state_node::{
    StateNodeCreateContentRequest, StateNodeCreateContentResponse, StateNodeDeleteContentResponse,
    StateNodeErrorResponse, StateNodeUpdateContentRequest, StateNodeUpdateContentResponse,
};

use monas_content::application_service::content_service::{
    ContentEncryptionKeyStore, ContentRepository, ContentService, CreateContentCommand,
    DeleteContentCommand, DeleteError, FetchError, RestoreDeletedContentCommand,
    RestoreDeletedError, UpdateContentCommand, UpdateError,
};
use monas_content::domain::content::{Content, ContentEncryptionKey, StorageProvider};
use monas_content::domain::content_id::ContentId;
use monas_content::infrastructure::{
    content_id::Sha256ContentIdGenerator,
    encryption::{Aes256CtrContentEncryption, OsRngContentEncryptionKeyGenerator},
    key_store::InMemoryContentEncryptionKeyStore,
    MultiStorageRepository,
};

use super::MonasController;

/// ContentServiceの型エイリアス（可読性向上のため）
pub(super) type ContentServiceInstance = ContentService<
    Sha256ContentIdGenerator,
    MultiStorageRepository,
    OsRngContentEncryptionKeyGenerator,
    Aes256CtrContentEncryption,
    InMemoryContentEncryptionKeyStore,
>;

#[derive(Clone)]
struct LocalContentSnapshot {
    content_id: ContentId,
    raw_content: Vec<u8>,
    name: String,
    path: String,
    provider: Option<StorageProvider>,
}

#[derive(Clone)]
struct StoredContentSnapshot {
    content_id: ContentId,
    content: Content,
    cek: ContentEncryptionKey,
}

impl MonasController {
    pub(super) fn attach_state_node_auth<Any>(
        mut req: ureq::RequestBuilder<Any>,
        auth: Option<&StateNodeAuthContext>,
    ) -> ureq::RequestBuilder<Any> {
        if let Some(ctx) = auth {
            if let Some(value) = &ctx.authorization {
                req = req.header("Authorization", value);
            }
            if let Some(value) = &ctx.request_signature {
                req = req.header("X-Request-Signature", value);
            }
            if let Some(value) = ctx.request_timestamp {
                req = req.header("X-Request-Timestamp", &value.to_string());
            }
        }
        req
    }

    pub(super) fn state_node_error_message_from_body(body: &str) -> Option<String> {
        serde_json::from_str::<StateNodeErrorResponse>(body.trim())
            .ok()
            .map(|e| e.error)
            .filter(|s| !s.is_empty())
    }

    pub(super) fn map_state_node_http_status_to_api_response<T>(
        status: u16,
        message: String,
        trace_id: String,
    ) -> ApiResponse<T> {
        match status {
            400 => ApiResponse::error(ApiError::Validation(message), trace_id),
            401 => ApiResponse::error(ApiError::Unauthorized(message), trace_id),
            403 => ApiResponse::error(ApiError::Forbidden(message), trace_id),
            404 => ApiResponse::error(ApiError::NotFound(message), trace_id),
            408 => ApiResponse::error(ApiError::Timeout(message), trace_id),
            409 => ApiResponse::error(ApiError::Conflict(message), trace_id),
            _ => ApiResponse::error(ApiError::Internal(message), trace_id),
        }
    }

    /// HTTP ステータスが 2xx でなければ `Some(エラー)`。2xx のときは `None`。
    pub(super) fn try_state_node_http_error<T>(
        status: u16,
        body: &str,
        trace_id: String,
    ) -> Option<ApiResponse<T>> {
        if (200..300).contains(&status) {
            return None;
        }
        let msg = Self::state_node_error_message_from_body(body).unwrap_or_else(|| {
            let t = body.trim();
            if t.is_empty() {
                format!("State Node returned HTTP {status}")
            } else {
                t.to_string()
            }
        });
        Some(Self::map_state_node_http_status_to_api_response(status, msg, trace_id))
    }

    /// FetchErrorをApiErrorにマッピング
    fn map_fetch_error(e: FetchError) -> ApiError {
        match e {
            FetchError::NotFound => ApiError::NotFound("Content not found".into()),
            FetchError::Deleted => ApiError::NotFound("Content is deleted".into()),
            FetchError::MissingKey => {
                ApiError::Internal("Missing encryption key for content".into())
            }
            FetchError::Domain(err) => ApiError::Internal(format!("Domain error: {err:?}")),
            FetchError::Repository(err) => ApiError::Internal(format!("Repository error: {err}")),
            FetchError::KeyStore(err) => ApiError::Internal(format!("Key store error: {err}")),
        }
    }

    /// UpdateErrorをApiErrorにマッピング
    fn map_update_error(e: UpdateError) -> ApiError {
        match e {
            UpdateError::NotFound => ApiError::NotFound("Content not found".into()),
            UpdateError::Validation(msg) => ApiError::Validation(msg),
            UpdateError::Domain(err) => ApiError::Internal(format!("Domain error: {err:?}")),
            UpdateError::Repository(err) => ApiError::Internal(format!("Repository error: {err}")),
            UpdateError::KeyStore(err) => ApiError::Internal(format!("Key store error: {err}")),
            UpdateError::MissingEncryptedContent => {
                ApiError::Internal("Missing encrypted content".into())
            }
        }
    }

    /// DeleteErrorをApiErrorにマッピング
    fn map_delete_error(e: DeleteError) -> ApiError {
        match e {
            DeleteError::NotFound => ApiError::NotFound("Content not found".into()),
            DeleteError::Domain(err) => ApiError::Internal(format!("Domain error: {err:?}")),
            DeleteError::Repository(err) => ApiError::Internal(format!("Repository error: {err}")),
            DeleteError::KeyStore(err) => ApiError::Internal(format!("Key store error: {err}")),
        }
    }

    fn map_restore_deleted_error(e: RestoreDeletedError) -> ApiError {
        match e {
            RestoreDeletedError::Validation(msg) => ApiError::Validation(msg),
            RestoreDeletedError::NotFound => ApiError::NotFound("Content not found".into()),
            RestoreDeletedError::NotDeleted => {
                ApiError::Conflict("Content is not deleted".into())
            }
            RestoreDeletedError::Domain(err) => ApiError::Internal(format!("Domain error: {err:?}")),
            RestoreDeletedError::Repository(err) => {
                ApiError::Internal(format!("Repository error: {err}"))
            }
            RestoreDeletedError::KeyStore(err) => {
                ApiError::Internal(format!("Key store error: {err}"))
            }
            RestoreDeletedError::MissingEncryptedContent => {
                ApiError::Internal("Missing encrypted content".into())
            }
        }
    }

    /// content_idのバリデーション
    /// エラーがある場合はSome(ApiResponse)を返し、成功時はNoneを返す
    fn validate_content_id<T>(content_id: &str, trace_id: String) -> Option<ApiResponse<T>> {
        if content_id.is_empty() {
            return Some(ApiResponse::error(
                ApiError::Validation("content_id must not be empty".into()),
                trace_id,
            ));
        }
        None
    }

    /// base64urlデコードされたコンテンツのバリデーション
    /// エラーがある場合はApiResponse<T>を返し、成功時はVec<u8>を返す
    fn decode_and_validate_content<T>(
        content_base64url: &str,
        trace_id: String,
    ) -> Result<Vec<u8>, ApiResponse<T>> {
        if content_base64url.is_empty() {
            return Err(ApiResponse::error(
                ApiError::Validation("content must not be empty".into()),
                trace_id,
            ));
        }

        let content_bytes = match URL_SAFE_NO_PAD.decode(content_base64url) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(ApiResponse::error(
                    ApiError::Validation(format!("Invalid content base64url: {e}")),
                    trace_id,
                ));
            }
        };

        if content_bytes.is_empty() {
            return Err(ApiResponse::error(
                ApiError::Validation("content must not be empty after decoding".into()),
                trace_id,
            ));
        }

        Ok(content_bytes)
    }

    fn capture_local_content_snapshot(
        &self,
        content_id: ContentId,
    ) -> Result<LocalContentSnapshot, FetchError> {
        let fetched = self.content_service.fetch(content_id, None)?;
        Ok(LocalContentSnapshot {
            content_id: fetched.content_id,
            raw_content: fetched.raw_content,
            name: fetched.metadata.name().to_string(),
            path: fetched.metadata.path().to_string(),
            provider: fetched.metadata.provider().cloned(),
        })
    }

    fn restore_deleted_from_snapshot(
        &self,
        snapshot: &LocalContentSnapshot,
    ) -> Result<(), RestoreDeletedError> {
        self.content_service
            .restore_deleted(RestoreDeletedContentCommand {
                content_id: snapshot.content_id.clone(),
                name: snapshot.name.clone(),
                path: snapshot.path.clone(),
                raw_content: snapshot.raw_content.clone(),
                provider: snapshot.provider.clone(),
            })
            .map(|_| ())
    }

    fn capture_stored_content_snapshot(
        &self,
        content_id: &ContentId,
    ) -> Result<StoredContentSnapshot, ApiError> {
        let content = self
            .content_service
            .content_repository
            .find_by_id(content_id)
            .map_err(|e| ApiError::Internal(format!("Repository error: {e}")))?
            .ok_or_else(|| ApiError::NotFound("Content not found".into()))?;

        let cek = self
            .content_service
            .cek_store
            .load(content_id)
            .map_err(|e| ApiError::Internal(format!("Key store error: {e}")))?
            .ok_or_else(|| ApiError::Internal("Missing encryption key for content".into()))?;

        Ok(StoredContentSnapshot {
            content_id: content_id.clone(),
            content,
            cek,
        })
    }

    fn restore_stored_content_snapshot(
        &self,
        snapshot: &StoredContentSnapshot,
    ) -> Result<(), ApiError> {
        self.content_service
            .content_repository
            .save(&snapshot.content_id, &snapshot.content)
            .map_err(|e| ApiError::Internal(format!("Repository restore error: {e}")))?;

        self.content_service
            .cek_store
            .save(&snapshot.content_id, &snapshot.cek)
            .map_err(|e| ApiError::Internal(format!("Key store restore error: {e}")))?;

        Ok(())
    }

    fn rollback_created_content(&self, content_id: ContentId) -> Result<(), ApiError> {
        self.content_service
            .delete(DeleteContentCommand {
                content_id,
                provider: None,
            })
            .map(|_| ())
            .map_err(Self::map_delete_error)
    }

    fn rollback_updated_content(
        &self,
        before_update: &StoredContentSnapshot,
        updated_content_id: &ContentId,
    ) -> Result<(), ApiError> {
        if updated_content_id == &before_update.content_id {
            return self.restore_stored_content_snapshot(before_update);
        }

        self.content_service
            .delete(DeleteContentCommand {
                content_id: updated_content_id.clone(),
                provider: None,
            })
            .map(|_| ())
            .map_err(Self::map_delete_error)
    }

    /// State Node に `POST /content` を送る（`http_api::create_content` と同じ契約）。
    /// エラー時は `Some`、成功時は `None`。2xx かつ本文がある場合は JSON を検証する。
    fn send_create_to_state_node<T>(
        &self,
        encrypted_content: &[u8],
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Option<ApiResponse<T>> {
        let encrypted_data_base64 = BASE64_STANDARD.encode(encrypted_content);
        let state_node_request = StateNodeCreateContentRequest {
            data: encrypted_data_base64,
        };

        let state_node_url = format!("{}/content", self.state_node_url);
        let req = Self::attach_state_node_auth(ureq::post(&state_node_url), auth);

        let resp = match req.send_json(state_node_request) {
            Ok(r) => r,
            Err(e) => {
                return Some(ApiResponse::error(
                    ApiError::Internal(format!("Failed to send request to State Node: {e}")),
                    trace_id,
                ));
            }
        };

        let status = resp.status().as_u16();
        let body = match resp.into_body().read_to_string() {
            Ok(s) => s,
            Err(e) => {
                return Some(ApiResponse::error(
                    ApiError::Internal(format!("Failed to read State Node response body: {e}")),
                    trace_id,
                ));
            }
        };

        if let Some(err) = Self::try_state_node_http_error(status, &body, trace_id.clone()) {
            return Some(err);
        }

        if body.trim().is_empty() {
            return None;
        }

        match serde_json::from_str::<StateNodeCreateContentResponse>(&body) {
            Ok(_) => None,
            Err(e) => Some(ApiResponse::error(
                ApiError::Internal(format!("Invalid State Node create response JSON: {e}")),
                trace_id,
            )),
        }
    }

    /// State Node に `PUT /content/:id` を送る（`http_api::update_content` と同じ契約）。
    pub(super) fn send_update_to_state_node<T>(
        &self,
        content_id: &str,
        encrypted_content: &[u8],
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Option<ApiResponse<T>> {
        let encrypted_data_base64 = BASE64_STANDARD.encode(encrypted_content);
        let state_node_request = StateNodeUpdateContentRequest {
            data: encrypted_data_base64,
        };

        let state_node_url = format!("{}/content/{}", self.state_node_url, content_id);
        let req = Self::attach_state_node_auth(ureq::put(&state_node_url), auth);

        let resp = match req.send_json(state_node_request) {
            Ok(r) => r,
            Err(e) => {
                return Some(ApiResponse::error(
                    ApiError::Internal(format!("Failed to send request to State Node: {e}")),
                    trace_id,
                ));
            }
        };

        let status = resp.status().as_u16();
        let body = match resp.into_body().read_to_string() {
            Ok(s) => s,
            Err(e) => {
                return Some(ApiResponse::error(
                    ApiError::Internal(format!("Failed to read State Node response body: {e}")),
                    trace_id,
                ));
            }
        };

        if let Some(err) = Self::try_state_node_http_error(status, &body, trace_id.clone()) {
            return Some(err);
        }

        if body.trim().is_empty() {
            return None;
        }

        match serde_json::from_str::<StateNodeUpdateContentResponse>(&body) {
            Ok(parsed) => {
                if !parsed.updated {
                    return Some(ApiResponse::error(
                        ApiError::Internal(
                            "State Node did not confirm content update (updated=false)".into(),
                        ),
                        trace_id,
                    ));
                }
                None
            }
            Err(e) => Some(ApiResponse::error(
                ApiError::Internal(format!("Invalid State Node update response JSON: {e}")),
                trace_id,
            )),
        }
    }

    /// State Node に `DELETE /content/:id` を送る（`http_api::delete_content` と同じ契約）。
    fn send_delete_to_state_node<T>(
        &self,
        content_id: &str,
        auth: Option<&StateNodeAuthContext>,
        trace_id: String,
    ) -> Option<ApiResponse<T>> {
        let state_node_url = format!("{}/content/{}", self.state_node_url, content_id);
        let req = Self::attach_state_node_auth(ureq::delete(&state_node_url), auth);

        let resp = match req.call() {
            Ok(r) => r,
            Err(e) => {
                return Some(ApiResponse::error(
                    ApiError::Internal(format!("Failed to send delete request to State Node: {e}")),
                    trace_id,
                ));
            }
        };

        let status = resp.status().as_u16();
        let body = match resp.into_body().read_to_string() {
            Ok(s) => s,
            Err(e) => {
                return Some(ApiResponse::error(
                    ApiError::Internal(format!("Failed to read State Node response body: {e}")),
                    trace_id,
                ));
            }
        };

        if let Some(err) = Self::try_state_node_http_error(status, &body, trace_id.clone()) {
            return Some(err);
        }

        if body.trim().is_empty() {
            return None;
        }

        match serde_json::from_str::<StateNodeDeleteContentResponse>(&body) {
            Ok(parsed) => {
                if !parsed.deleted {
                    return Some(ApiResponse::error(
                        ApiError::Internal(
                            "State Node did not confirm content deletion (deleted=false)".into(),
                        ),
                        trace_id,
                    ));
                }
                None
            }
            Err(e) => Some(ApiResponse::error(
                ApiError::Internal(format!("Invalid State Node delete response JSON: {e}")),
                trace_id,
            )),
        }
    }
    /// 新しいコンテンツを作成し、State Node に登録する。
    ///
    /// `auth` は State Node に転送する認証ヘッダ（ゲートウェイ等から透過）。本番では `Some` が必要。
    ///
    /// 処理フロー:
    /// 1. 入力のバリデーション（content, metadata.name）
    /// 2. コンテンツをbase64urlデコード
    /// 3. ContentService::createを呼び出して以下を実行:
    ///    - content_id生成（コンテンツのハッシュベース）
    ///    - コンテンツの暗号化
    ///    - 暗号化コンテンツをリポジトリに保存
    ///    - CEKをキーストアに保存
    /// 4. State Nodeに暗号化されたコンテンツを送信
    /// 5. 結果を返却
    pub fn create_content(
        &self,
        input: CreateContentInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<CreateContentOutput> {
        let trace_id = generate_trace_id();

        if input.content.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("content must not be empty".into()),
                trace_id,
            );
        }

        let content_bytes = match URL_SAFE_NO_PAD.decode(&input.content) {
            Ok(bytes) => bytes,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Validation(format!("Invalid content base64url: {e}")),
                    trace_id,
                );
            }
        };

        if content_bytes.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("content must not be empty after decoding".into()),
                trace_id,
            );
        }

        let name = match input.metadata.as_ref().and_then(|m| m.name.clone()) {
            Some(name) => name,
            None => {
                return ApiResponse::error(
                    ApiError::Validation("metadata.name is required".into()),
                    trace_id,
                );
            }
        };

        let path = format!("/{name}");

        let content_service = &self.content_service;

        let cmd = CreateContentCommand {
            raw_content: content_bytes,
            name,
            path,
            provider: None,
        };

        let result = match content_service.create(cmd) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Internal(format!("Failed to create content: {e}")),
                    trace_id,
                );
            }
        };

        if let Some(response) =
            self.send_create_to_state_node(&result.encrypted_content, auth, trace_id.clone())
        {
            if let Err(rollback_err) = self.rollback_created_content(result.content_id.clone()) {
                let remote_message = response
                    .error
                    .as_ref()
                    .map(|e| format!("{e:?}"))
                    .unwrap_or_else(|| "unknown state node create failure".into());
                return ApiResponse::error(
                    ApiError::Internal(format!(
                        "State Node create failed and local rollback also failed: remote={remote_message}, rollback={rollback_err}"
                    )),
                    trace_id,
                );
            }
            return response;
        }

        let output = CreateContentOutput {
            content_id: result.content_id.as_str().to_string(),
            created_at: Some(Utc::now().to_rfc3339()),
        };

        ApiResponse::success(output, trace_id)
    }

    /// 通常コンテンツをローカル状態から取得し、復号する
    ///
    /// 処理フロー:
    /// 1. 入力のバリデーション（content_id）
    /// 2. ContentIdに変換
    /// 3. ContentService::fetchを呼び出して以下を実行:
    ///    - リポジトリから暗号化されたコンテンツを取得
    ///    - キーストアからCEKを取得
    ///    - CEKでコンテンツを復号
    /// 4. 復号されたコンテンツをbase64urlエンコード
    /// 5. メタデータを変換
    /// 6. 結果を返却
    pub fn get_content(&self, input: GetContentInput) -> ApiResponse<GetContentOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_content_id(&input.content_id, trace_id.clone()) {
            return response;
        }

        let content_id = ContentId::new(input.content_id.clone());

        let content_service = &self.content_service;

        let result = match content_service.fetch(content_id, None) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(Self::map_fetch_error(e), trace_id);
            }
        };

        let content_base64url = URL_SAFE_NO_PAD.encode(&result.raw_content);

        let metadata = crate::models::content::ContentMetadata {
            name: Some(result.metadata.name().to_string()),
            content_type: None,
            created_at: Some(result.metadata.created_at().to_rfc3339()),
            updated_at: Some(result.metadata.updated_at().to_rfc3339()),
        };

        let output = GetContentOutput {
            content_id: result.content_id.as_str().to_string(),
            content: content_base64url,
            metadata: Some(metadata),
        };

        ApiResponse::success(output, trace_id)
    }

    /// 既存のコンテンツを更新する。
    ///
    /// `auth` は State Node に転送する認証ヘッダ（ゲートウェイ等から透過）。本番では `Some` が必要。
    ///
    /// 処理フロー:
    /// 1. 入力のバリデーション（base_version_id, contentまたはmetadata.name）
    /// 2. ContentIdに変換（更新元の版IDを保存）
    /// 3. 更新内容を準備（new_name, new_raw_content）
    /// 4. ContentService::updateを呼び出して以下を実行:
    ///    - 既存コンテンツを取得
    ///    - 新しいコンテンツがある場合は暗号化
    ///    - リポジトリに保存
    ///    - CEKを更新（必要に応じて）
    /// 5. State Nodeに暗号化されたコンテンツを送信
    /// 6. 結果を返却
    pub fn update_content(
        &self,
        input: UpdateContentInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<UpdateContentOutput> {
        let trace_id = generate_trace_id();

        // 1. 入力のバリデーション
        if input.base_version_id.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("base_version_id must not be empty".into()),
                trace_id,
            );
        }

        // 2. ContentIdに変換
        let base_version_id = input.base_version_id.clone();
        let content_id = ContentId::new(base_version_id.clone());
        let before_update = match self.capture_stored_content_snapshot(&content_id) {
            Ok(snapshot) => snapshot,
            Err(error) => return ApiResponse::error(error, trace_id),
        };

        // 3. new_nameとnew_raw_contentを準備
        let new_name = input.metadata.as_ref().and_then(|m| m.name.clone());

        let new_raw_content = if input.content.is_empty() {
            None
        } else {
            // コンテンツをbase64urlデコード
            match Self::decode_and_validate_content(&input.content, trace_id.clone()) {
                Ok(bytes) => Some(bytes),
                Err(response) => return response,
            }
        };

        // 4. new_nameとnew_raw_contentのどちらか一方以上が指定されていることを確認
        if new_name.is_none() && new_raw_content.is_none() {
            return ApiResponse::error(
                ApiError::Validation(
                    "at least one of content or metadata.name must be provided".into(),
                ),
                trace_id,
            );
        }

        let content_service = &self.content_service;

        let cmd = UpdateContentCommand {
            content_id,
            new_name,
            new_raw_content,
            provider: None,
        };

        let result = match content_service.update(cmd) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(Self::map_update_error(e), trace_id);
            }
        };

        if let Some(response) = self.send_update_to_state_node(
            result.series_id.as_str(),
            &result.encrypted_content,
            auth,
            trace_id.clone(),
        ) {
            if let Err(rollback_err) =
                self.rollback_updated_content(&before_update, &result.content_id)
            {
                let remote_message = response
                    .error
                    .as_ref()
                    .map(|e| format!("{e:?}"))
                    .unwrap_or_else(|| "unknown state node update failure".into());
                return ApiResponse::error(
                    ApiError::Internal(format!(
                        "State Node update failed and local rollback also failed: remote={remote_message}, rollback={rollback_err}"
                    )),
                    trace_id,
                );
            }
            return response;
        }

        let output = UpdateContentOutput {
            series_id: result.series_id.as_str().to_string(),
            previous_version_id: base_version_id,
            version_id: result.content_id.as_str().to_string(),
            updated_at: Some(Utc::now().to_rfc3339()),
        };

        ApiResponse::success(output, trace_id)
    }

    /// コンテンツを削除する。
    ///
    /// `auth` は State Node に転送する認証ヘッダ（ゲートウェイ等から透過）。本番では `Some` が必要。
    ///
    /// 処理フロー:
    /// 1. 入力のバリデーション（content_id）
    /// 2. ContentIdに変換
    /// 3. ContentService::deleteを呼び出して以下を実行:
    ///    - リポジトリからコンテンツを削除（論理削除）
    ///    - キーストアからCEKを削除
    /// 4. State Node へ削除を通知
    /// 5. 結果を返却
    pub fn delete_content(
        &self,
        input: DeleteContentInput,
        auth: Option<&StateNodeAuthContext>,
    ) -> ApiResponse<DeleteContentOutput> {
        let trace_id = generate_trace_id();

        // 1. 入力のバリデーション
        if let Some(response) = Self::validate_content_id(&input.content_id, trace_id.clone()) {
            return response;
        }

        // 2. ContentIdに変換
        let content_id = ContentId::new(input.content_id.clone());

        let snapshot = match self.capture_local_content_snapshot(content_id.clone()) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                return ApiResponse::error(Self::map_fetch_error(e), trace_id);
            }
        };

        // 3. ContentServiceを使用
        let content_service = &self.content_service;

        // 4. DeleteContentCommandを作成
        let cmd = DeleteContentCommand {
            content_id,
            provider: None,
        };

        // 5. ContentService::deleteを呼び出してコンテンツを削除
        let result = match content_service.delete(cmd) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(Self::map_delete_error(e), trace_id);
            }
        };

        if let Some(response) =
            self.send_delete_to_state_node(&input.content_id, auth, trace_id.clone())
        {
            if let Err(restore_err) = self.restore_deleted_from_snapshot(&snapshot) {
                let remote_message = response
                    .error
                    .as_ref()
                    .map(|e| format!("{e:?}"))
                    .unwrap_or_else(|| "unknown state node delete failure".into());
                let rollback_message = format!("{:?}", Self::map_restore_deleted_error(restore_err));
                return ApiResponse::error(
                    ApiError::Internal(format!(
                        "State Node delete failed and local restore also failed: remote={remote_message}, restore={rollback_message}"
                    )),
                    trace_id,
                );
            }
            return response;
        }

        let output = DeleteContentOutput {
            content_id: result.content_id.as_str().to_string(),
            deleted: true,
            deleted_at: Some(Utc::now().to_rfc3339()),
        };

        ApiResponse::success(output, trace_id)
    }
}
