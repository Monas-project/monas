use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;

use crate::common::{generate_trace_id, ApiError, ApiResponse};
use crate::models::content::{
    CreateContentInput, CreateContentOutput, DeleteContentInput, DeleteContentOutput,
    GetContentInput, GetContentOutput, UpdateContentInput, UpdateContentOutput,
};

use monas_content::application_service::content_service::{
    ContentService, CreateContentCommand,
};
use monas_content::infrastructure::{
    content_id::Sha256ContentIdGenerator,
    encryption::{Aes256CtrContentEncryption, OsRngContentEncryptionKeyGenerator},
    key_store::InMemoryContentEncryptionKeyStore,
    repository::InMemoryContentRepository,
};

use super::MonasController;


impl MonasController {
    /// 新しいコンテンツを作成し、State Nodeに登録する
    ///
    /// 処理フロー:
    /// 1. content_idを生成（コンテンツのハッシュベース）
    /// 2. コンテンツを暗号化
    /// 3. Content Service: 暗号化コンテンツをDBに保存、CEKをDBに保存
    /// 4. CreateOperation を作成
    /// 5. 秘密鍵で Operation に署名
    /// 6. State Node: Operationを受け取り、状態を登録
    /// 7. 結果を返却
    pub fn create_content(&self, input: CreateContentInput) -> ApiResponse<CreateContentOutput> {
        let trace_id = generate_trace_id();

        // 1. 入力のバリデーション
        if input.private_key.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("private_key must not be empty".into()),
                trace_id,
            );
        }

        if input.content.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("content must not be empty".into()),
                trace_id,
            );
        }

        // 2. コンテンツをbase64urlデコード
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

        // 3. メタデータからnameを取得（必須）
        let name = input
            .metadata
            .as_ref()
            .and_then(|m| m.name.clone())
            .ok_or_else(|| {
                return ApiResponse::error(
                    ApiError::Validation("metadata.name is required".into()),
                    trace_id,
                );
            })?;

        // pathはnameから生成（/nameの形式）
        let path = format!("/{}", name);

        // 4. ContentServiceの依存関係を準備
        let content_repository = InMemoryContentRepository::default();
        let cek_store = InMemoryContentEncryptionKeyStore::default();

        // 5. ContentServiceのインスタンスを作成
        let content_service = ContentService {
            content_id_generator: Sha256ContentIdGenerator,
            content_repository,
            key_generator: OsRngContentEncryptionKeyGenerator,
            encryptor: Aes256CtrContentEncryption,
            cek_store,
        };

        // 6. ContentService::createを呼び出してコンテンツを作成
        // これにより以下が実行される:
        //   - content_id生成（コンテンツのハッシュベース）
        //   - コンテンツの暗号化
        //   - 暗号化コンテンツをDBに保存
        //   - CEKをDBに保存
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

        // 7. State Nodeに暗号化されたコンテンツを送信
        // TODO: HTTP API経由でState Nodeに暗号化されたコンテンツを送信
        // State Nodeは内部でEventを生成するため、Operationを作成する必要はない
        // 暗号化されたコンテンツのデータを送信する

        // 8. レスポンスを構築
        let output = CreateContentOutput {
            content_id: result.content_id.as_str().to_string(),
            operation_id: format!("op_{}", generate_trace_id()), // TODO: 実際のoperation_idを取得
            created_at: Some(Utc::now().to_rfc3339()),
        };

        ApiResponse::success(output, trace_id)
    }

    /// コンテンツを取得し、復号する
    ///
    /// 処理フロー:
    /// 1. Content Service: DBから暗号化されたコンテンツを取得
    /// 2. Content Service: DBからCEKを取得
    /// 3. CEKでコンテンツを復号
    /// 4. 結果を返却
    pub fn get_content(&self, _input: GetContentInput) -> ApiResponse<GetContentOutput> {
        let trace_id = generate_trace_id();

        // TODO: monas-content の ContentService.fetch を呼び出す

        ApiResponse::error(
            ApiError::Internal("get_content is not implemented yet".into()),
            trace_id,
        )
    }

    /// 既存のコンテンツを更新する
    ///
    /// 処理フロー:
    /// 1. 新しいコンテンツを暗号化
    /// 2. Content Service: 暗号化コンテンツをDBに保存
    /// 3. UpdateOperation を作成
    /// 4. 秘密鍵で Operation に署名
    /// 5. State Node: Operationを受け取り、権限チェック（ACL確認）
    /// 6. State Node: 権限があれば状態を更新
    /// 7. 新しいバージョンのCIDを返却
    pub fn update_content(&self, _input: UpdateContentInput) -> ApiResponse<UpdateContentOutput> {
        let trace_id = generate_trace_id();

        // TODO: monas-content の ContentService.update を呼び出す

        ApiResponse::error(
            ApiError::Internal("update_content is not implemented yet".into()),
            trace_id,
        )
    }

    /// コンテンツを削除する
    ///
    /// 処理フロー:
    /// 1. DeleteOperation を作成
    /// 2. 秘密鍵で Operation に署名
    /// 3. State Node: Operationを受け取り、権限チェック（ACL確認）
    /// 4. State Node: 権限があれば状態を更新（削除フラグ）
    /// 5. Content Service: DBからコンテンツを削除（または削除フラグを設定）
    pub fn delete_content(&self, _input: DeleteContentInput) -> ApiResponse<DeleteContentOutput> {
        let trace_id = generate_trace_id();

        // TODO: monas-content の ContentService.delete を呼び出す

        ApiResponse::error(
            ApiError::Internal("delete_content is not implemented yet".into()),
            trace_id,
        )
    }
}
