use base64::{
    engine::general_purpose::STANDARD as BASE64_STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};
use chrono::Utc;

use crate::common::{generate_trace_id, ApiError, ApiResponse};
use crate::models::content::{
    CreateContentInput, CreateContentOutput, DeleteContentInput, DeleteContentOutput,
    GetContentInput, GetContentOutput, UpdateContentInput, UpdateContentOutput,
};
use crate::models::state_node::{StateNodeCreateContentRequest, StateNodeUpdateContentRequest};

use monas_content::application_service::content_service::{
    ContentService, CreateContentCommand, DeleteContentCommand, DeleteError, FetchError,
    UpdateContentCommand, UpdateError,
};
use monas_content::domain::content_id::ContentId;
use monas_content::infrastructure::{
    content_id::Sha256ContentIdGenerator,
    encryption::{Aes256CtrContentEncryption, OsRngContentEncryptionKeyGenerator},
    key_store::InMemoryContentEncryptionKeyStore,
    repository::InMemoryContentRepository,
};

use super::MonasController;

/// ContentServiceの型エイリアス（可読性向上のため）
pub(super) type ContentServiceInstance = ContentService<
    Sha256ContentIdGenerator,
    InMemoryContentRepository,
    OsRngContentEncryptionKeyGenerator,
    Aes256CtrContentEncryption,
    InMemoryContentEncryptionKeyStore,
>;

impl MonasController {
    /// FetchErrorをApiErrorにマッピング
    fn map_fetch_error(e: FetchError) -> ApiError {
        match e {
            FetchError::NotFound => ApiError::NotFound("Content not found".into()),
            FetchError::Deleted => ApiError::NotFound("Content is deleted".into()),
            FetchError::MissingKey => {
                ApiError::Internal("Missing encryption key for content".into())
            }
            FetchError::Domain(err) => ApiError::Internal(format!("Domain error: {:?}", err)),
            FetchError::Repository(err) => ApiError::Internal(format!("Repository error: {}", err)),
            FetchError::KeyStore(err) => ApiError::Internal(format!("Key store error: {}", err)),
        }
    }

    /// UpdateErrorをApiErrorにマッピング
    fn map_update_error(e: UpdateError) -> ApiError {
        match e {
            UpdateError::NotFound => ApiError::NotFound("Content not found".into()),
            UpdateError::Validation(msg) => ApiError::Validation(msg),
            UpdateError::Domain(err) => ApiError::Internal(format!("Domain error: {:?}", err)),
            UpdateError::Repository(err) => {
                ApiError::Internal(format!("Repository error: {}", err))
            }
            UpdateError::KeyStore(err) => ApiError::Internal(format!("Key store error: {}", err)),
        }
    }

    /// DeleteErrorをApiErrorにマッピング
    fn map_delete_error(e: DeleteError) -> ApiError {
        match e {
            DeleteError::NotFound => ApiError::NotFound("Content not found".into()),
            DeleteError::Domain(err) => ApiError::Internal(format!("Domain error: {:?}", err)),
            DeleteError::Repository(err) => {
                ApiError::Internal(format!("Repository error: {}", err))
            }
            DeleteError::KeyStore(err) => ApiError::Internal(format!("Key store error: {}", err)),
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
                    ApiError::Validation(format!("Invalid content base64url: {}", e)),
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

    /// State Nodeにコンテンツを作成するリクエストを送信
    /// エラーがある場合はSome(ApiResponse)を返し、成功時はNoneを返す
    fn send_create_to_state_node<T>(
        &self,
        encrypted_content: &[u8],
        trace_id: String,
    ) -> Option<ApiResponse<T>> {
        let encrypted_data_base64 = BASE64_STANDARD.encode(encrypted_content);
        let state_node_request = StateNodeCreateContentRequest {
            data: encrypted_data_base64,
        };

        let state_node_url = format!("{}/content", self.state_node_url);
        if let Err(e) = ureq::post(&state_node_url).send_json(state_node_request) {
            let error_msg = format!("Failed to send request to State Node: {}", e);
            return Some(ApiResponse::error(ApiError::Internal(error_msg), trace_id));
        }

        None
    }

    /// State Nodeにコンテンツを更新するリクエストを送信
    /// エラーがある場合はSome(ApiResponse)を返し、成功時はNoneを返す
    fn send_update_to_state_node<T>(
        &self,
        content_id: &str,
        encrypted_content: &[u8],
        trace_id: String,
    ) -> Option<ApiResponse<T>> {
        let encrypted_data_base64 = BASE64_STANDARD.encode(encrypted_content);
        let state_node_request = StateNodeUpdateContentRequest {
            data: encrypted_data_base64,
        };

        let state_node_url = format!("{}/content/{}", self.state_node_url, content_id);
        if let Err(e) = ureq::put(&state_node_url).send_json(state_node_request) {
            let error_msg = format!("Failed to send request to State Node: {}", e);
            return Some(ApiResponse::error(ApiError::Internal(error_msg), trace_id));
        }

        None
    }
    /// 新しいコンテンツを作成し、State Nodeに登録する
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
    pub fn create_content(&self, input: CreateContentInput) -> ApiResponse<CreateContentOutput> {
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
                    ApiError::Validation(format!("Invalid content base64url: {}", e)),
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

        let path = format!("/{}", name);

        let content_service = &self.content_service;

        let cmd = CreateContentCommand {
            raw_content: content_bytes,
            name,
            path,
        };

        let result = match content_service.create(cmd) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Internal(format!("Failed to create content: {}", e)),
                    trace_id,
                );
            }
        };

        if let Some(response) =
            self.send_create_to_state_node(&result.encrypted_content, trace_id.clone())
        {
            return response;
        }

        let output = CreateContentOutput {
            content_id: result.content_id.as_str().to_string(),
            created_at: Some(Utc::now().to_rfc3339()),
        };

        ApiResponse::success(output, trace_id)
    }

    /// コンテンツを取得し、復号する
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

        let result = match content_service.fetch(content_id) {
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
            version: input.version.unwrap_or_else(|| String::new()),
            metadata: Some(metadata),
        };

        ApiResponse::success(output, trace_id)
    }

    /// 既存のコンテンツを更新する
    ///
    /// 処理フロー:
    /// 1. 入力のバリデーション（content_id, contentまたはmetadata.name）
    /// 2. ContentIdに変換（元のcontent_idを保存）
    /// 3. 更新内容を準備（new_name, new_raw_content）
    /// 4. ContentService::updateを呼び出して以下を実行:
    ///    - 既存コンテンツを取得
    ///    - 新しいコンテンツがある場合は暗号化
    ///    - リポジトリに保存
    ///    - CEKを更新（必要に応じて）
    /// 5. State Nodeに暗号化されたコンテンツを送信
    /// 6. 結果を返却
    pub fn update_content(&self, input: UpdateContentInput) -> ApiResponse<UpdateContentOutput> {
        let trace_id = generate_trace_id();

        // 1. 入力のバリデーション
        if let Some(response) = Self::validate_content_id(&input.content_id, trace_id.clone()) {
            return response;
        }

        // 2. ContentIdに変換
        let original_content_id = input.content_id.clone();
        let content_id = ContentId::new(original_content_id.clone());

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
        };

        let result = match content_service.update(cmd) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(Self::map_update_error(e), trace_id);
            }
        };

        if let Some(response) = self.send_update_to_state_node(
            &original_content_id,
            &result.encrypted_content,
            trace_id.clone(),
        ) {
            return response;
        }

        let output = UpdateContentOutput {
            content_id: result.content_id.as_str().to_string(),
            new_version: result.content_id.as_str().to_string(), // 新しいcontent_idをnew_versionとして使用
            updated_at: Some(Utc::now().to_rfc3339()),
        };

        ApiResponse::success(output, trace_id)
    }

    /// コンテンツを削除する
    ///
    /// 処理フロー:
    /// 1. 入力のバリデーション（content_id）
    /// 2. ContentIdに変換
    /// 3. ContentService::deleteを呼び出して以下を実行:
    ///    - リポジトリからコンテンツを削除（論理削除）
    ///    - キーストアからCEKを削除
    /// 4. 結果を返却
    ///
    /// 注意: State Nodeへの削除リクエスト送信は未実装（State Node側のdeleteエンドポイント実装後に追加予定）
    pub fn delete_content(&self, input: DeleteContentInput) -> ApiResponse<DeleteContentOutput> {
        let trace_id = generate_trace_id();

        // 1. 入力のバリデーション
        if let Some(response) = Self::validate_content_id(&input.content_id, trace_id.clone()) {
            return response;
        }

        // 2. ContentIdに変換
        let content_id = ContentId::new(input.content_id.clone());

        // 3. ContentServiceを使用
        let content_service = &self.content_service;

        // 4. DeleteContentCommandを作成
        let cmd = DeleteContentCommand { content_id };

        // 5. ContentService::deleteを呼び出してコンテンツを削除
        let result = match content_service.delete(cmd) {
            Ok(result) => result,
            Err(e) => {
                return ApiResponse::error(Self::map_delete_error(e), trace_id);
            }
        };

        // TODO: State Nodeに削除リクエストを送信

        let output = DeleteContentOutput {
            content_id: result.content_id.as_str().to_string(),
            deleted: true,
            deleted_at: Some(Utc::now().to_rfc3339()),
        };

        ApiResponse::success(output, trace_id)
    }
}
