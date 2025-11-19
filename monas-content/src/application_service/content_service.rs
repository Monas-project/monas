use crate::domain::{
    content::{Content, ContentError},
    content_id::{ContentId, ContentIdGenerator},
    encryption::{ContentEncryption, ContentEncryptionKeyGenerator},
    metadata::Metadata,
};

/// コンテンツ作成ユースケースの入力。
pub struct CreateContentCommand {
    pub name: String,
    pub path: String,
    pub raw_content: Vec<u8>,
}

/// コンテンツ作成ユースケースの出力。
pub struct CreateContentResult {
    pub content_id: ContentId,
    pub metadata: Metadata,
    /// コンテンツ暗号化に用いた鍵から導出される公開情報など。
    /// 具体的な意味づけは後続の設計で決める。
    pub public_key: String,
}

/// コンテンツ更新ユースケースの入力。
pub struct UpdateContentCommand {
    pub content_id: ContentId,
    pub new_name: Option<String>,
    pub new_raw_content: Option<Vec<u8>>,
}

/// コンテンツ更新ユースケースの出力。
pub struct UpdateContentResult {
    pub content_id: ContentId,
    pub metadata: Metadata,
}

/// コンテンツを永続化するポート。
pub trait ContentRepository {
    fn save(&self, content_id: &ContentId, content: &Content)
        -> Result<(), ContentRepositoryError>;
    fn find_by_id(&self, content_id: &ContentId)
        -> Result<Option<Content>, ContentRepositoryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ContentRepositoryError {
    #[error("storage error: {0}")]
    Storage(String),
}

/// state-node へ Operation を送信するポート。
pub trait StateNodeClient {
    fn send_content_created(
        &self,
        operation: &ContentCreatedOperation,
    ) -> Result<(), StateNodeClientError>;
}

#[derive(Debug, thiserror::Error)]
pub enum StateNodeClientError {
    #[error("network error: {0}")]
    Network(String),
}

/// state-node に送る「コンテンツ作成」Operation のDTO（アプリケーション層側の表現）。
pub struct ContentCreatedOperation {
    pub content_id: ContentId,
    pub hash: String,
    pub path: String,
    pub public_key: String,
    // TODO: 必要に応じて nodes や license などを追加。
}

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

        Ok(UpdateContentResult {
            content_id: content.id().clone(),
            metadata: content.metadata().clone(),
        })
    }
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
}
