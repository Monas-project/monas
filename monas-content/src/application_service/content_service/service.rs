use crate::domain::{
    content::{Content, ContentError},
    content_id::ContentIdGenerator,
    encryption::{ContentEncryption, ContentEncryptionKeyGenerator},
};

use super::{
    ContentCreatedOperation, ContentDeletedOperation, ContentRepository, ContentRepositoryError,
    ContentUpdatedOperation, CreateContentCommand, CreateContentResult, DeleteContentCommand,
    DeleteContentResult, StateNodeClient, StateNodeClientError, UpdateContentCommand,
    UpdateContentResult,
};

/// コンテンツ作成ユースケースのアプリケーションサービス。
pub struct ContentService<G, R, C, K, E> {
    pub content_id_generator: G,
    pub content_repository: R,
    pub state_node_client: C,
    pub key_generator: K,
    pub encryptor: E,
}

impl<G, R, C, K, E> ContentService<G, R, C, K, E>
where
    G: ContentIdGenerator,
    R: ContentRepository,
    C: StateNodeClient,
    K: ContentEncryptionKeyGenerator,
    E: ContentEncryption,
{
    pub fn create(&self, cmd: CreateContentCommand) -> Result<CreateContentResult, CreateError> {
        // 簡易バリデーション
        if cmd.name.trim().is_empty() {
            return Err(CreateError::Validation("name must not be empty".into()));
        }
        if cmd.path.trim().is_empty() {
            return Err(CreateError::Validation("path must not be empty".into()));
        }
        if cmd.raw_content.is_empty() {
            return Err(CreateError::Validation(
                "raw_content must not be empty".into(),
            ));
        }

        // CEK の生成
        let key = self.key_generator.generate();

        // ドメインの Content::create を呼び出し、ContentId生成＋暗号化＋メタデータ生成
        let (content, _event) = Content::create(
            cmd.name,
            cmd.raw_content,
            cmd.path,
            &self.content_id_generator,
            &key,
            &self.encryptor,
        )
        .map_err(CreateError::Domain)?;

        // コンテンツを永続化
        self.content_repository
            .save(content.id(), &content)
            .map_err(CreateError::Repository)?;

        // state-node に送る Operation を組み立て
        let metadata = content.metadata().clone();
        let content_id = content.id().clone();
        let operation = ContentCreatedOperation {
            content_id: content_id.clone(),
            hash: content_id.as_str().to_string(),
            path: metadata.path().to_string(),
            // 現時点では公開鍵を扱っていないため空文字。
            // 将来的にShare/鍵管理と連携したら埋める想定。
            public_key: String::new(),
        };

        // state-node へ通知
        self.state_node_client
            .send_content_created(&operation)
            .map_err(CreateError::StateNode)?;

        Ok(CreateContentResult {
            content_id,
            metadata,
            public_key: operation.public_key,
        })
    }

    /// コンテンツ更新ユースケース。
    ///
    /// - `new_name` と `new_raw_content` はどちらか片方だけ、あるいは両方指定可能
    /// - どちらも `None` の場合は Validation エラーとする
    pub fn update(&self, cmd: UpdateContentCommand) -> Result<UpdateContentResult, UpdateError> {
        // 簡易バリデーション
        if cmd.new_name.as_ref().is_none() && cmd.new_raw_content.as_ref().is_none() {
            return Err(UpdateError::Validation(
                "at least one of new_name or new_raw_content must be provided".into(),
            ));
        }
        if let Some(name) = &cmd.new_name {
            if name.trim().is_empty() {
                return Err(UpdateError::Validation("name must not be empty".into()));
            }
        }
        if let Some(raw) = &cmd.new_raw_content {
            if raw.is_empty() {
                return Err(UpdateError::Validation(
                    "new_raw_content must not be empty when provided".into(),
                ));
            }
        }

        // 既存コンテンツの取得
        let mut content = self
            .content_repository
            .find_by_id(&cmd.content_id)
            .map_err(UpdateError::Repository)?
            .ok_or(UpdateError::NotFound)?;

        // バイナリ更新が指定されている場合
        if let Some(raw) = cmd.new_raw_content {
            let key = self.key_generator.generate();
            let (updated, _event) = content
                .update_content(raw, &key, &self.encryptor)
                .map_err(UpdateError::Domain)?;
            content = updated;
        }

        // 名前変更が指定されている場合
        if let Some(name) = cmd.new_name {
            let (updated, _event) = content.rename(name).map_err(UpdateError::Domain)?;
            content = updated;
        }

        // state nodeの実装によるため仮置き
        self.content_repository
            .save(content.id(), &content)
            .map_err(UpdateError::Repository)?;

        // state-node に送る更新 Operation を組み立て
        let metadata = content.metadata().clone();
        let content_id = content.id().clone();
        let operation = ContentUpdatedOperation {
            content_id: content_id.clone(),
            hash: content_id.as_str().to_string(),
            path: metadata.path().to_string(),
        };

        // state-node へ通知
        self.state_node_client
            .send_content_updated(&operation)
            .map_err(UpdateError::StateNode)?;

        Ok(UpdateContentResult {
            content_id,
            metadata,
        })
    }

    /// コンテンツ削除ユースケース。
    ///
    /// - 物理削除ではなく、ドメインオブジェクト上で `is_deleted` フラグとバッファをクリアして保存する「論理削除」
    pub fn delete(&self, cmd: DeleteContentCommand) -> Result<DeleteContentResult, DeleteError> {
        // 既存コンテンツの取得
        let content = self
            .content_repository
            .find_by_id(&cmd.content_id)
            .map_err(DeleteError::Repository)?
            .ok_or(DeleteError::NotFound)?;

        // ドメインの削除処理（状態遷移とバリデーション）
        let (deleted_content, _event) = content.delete().map_err(DeleteError::Domain)?;

        // 論理削除済みの状態を保存
        self.content_repository
            .save(deleted_content.id(), &deleted_content)
            .map_err(DeleteError::Repository)?;

        // state-node に送る削除 Operation を組み立て
        let metadata = deleted_content.metadata().clone();
        let content_id = deleted_content.id().clone();
        let operation = ContentDeletedOperation {
            content_id: content_id.clone(),
            path: metadata.path().to_string(),
        };

        // state-node へ通知
        self.state_node_client
            .send_content_deleted(&operation)
            .map_err(DeleteError::StateNode)?;

        Ok(DeleteContentResult {
            content_id,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeleteError {
    #[error("content not found")]
    NotFound,
    #[error("domain error: {0:?}")]
    Domain(ContentError),
    #[error("repository error: {0}")]
    Repository(ContentRepositoryError),
    #[error("state-node error: {0}")]
    StateNode(StateNodeClientError),
}

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("domain error: {0:?}")]
    Domain(ContentError),
    #[error("repository error: {0}")]
    Repository(ContentRepositoryError),
    #[error("state-node error: {0}")]
    StateNode(StateNodeClientError),
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("content not found")]
    NotFound,
    #[error("domain error: {0:?}")]
    Domain(ContentError),
    #[error("repository error: {0}")]
    Repository(ContentRepositoryError),
    #[error("state-node error: {0}")]
    StateNode(StateNodeClientError),
}


