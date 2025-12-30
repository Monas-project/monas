mod keypair;
mod content;
mod share;
mod state;
use content::ContentServiceInstance;

/// MonasController - SDK のオーケストレーター
/// 
/// 各ドメイン（monas-account, monas-content, monas-state-node）の
/// Presentation層を呼び出してオーケストレーションを行う
pub struct MonasController {
    /// State NodeのベースURL
    state_node_url: String,
    /// ContentService（リクエスト間で状態を共有）
    content_service: ContentServiceInstance,
}

impl MonasController {
    /// 環境変数からState Node URLを取得してMonasControllerを生成
    /// 
    /// 環境変数 `MONAS_STATE_NODE_URL` が設定されている場合はそれを使用し、
    /// 設定されていない場合はデフォルト値 `http://127.0.0.1:8080` を使用します。
    pub fn new() -> Self {
        let state_node_url = std::env::var("MONAS_STATE_NODE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        
        Self {
            state_node_url,
            content_service: Self::create_content_service(),
        }
    }

    /// 明示的にState Node URLを指定してMonasControllerを生成
    pub fn with_state_node_url(state_node_url: impl Into<String>) -> Self {
        Self {
            state_node_url: state_node_url.into(),
            content_service: Self::create_content_service(),
        }
    }

    /// ContentServiceのインスタンスを作成するヘルパーメソッド
    fn create_content_service() -> ContentServiceInstance {
        use monas_content::infrastructure::{
            content_id::Sha256ContentIdGenerator,
            encryption::{Aes256CtrContentEncryption, OsRngContentEncryptionKeyGenerator},
            key_store::InMemoryContentEncryptionKeyStore,
            repository::InMemoryContentRepository,
        };
        use monas_content::application_service::content_service::ContentService;

        let content_repository = InMemoryContentRepository::default();
        let cek_store = InMemoryContentEncryptionKeyStore::default();

        ContentService {
            content_id_generator: Sha256ContentIdGenerator,
            content_repository: content_repository.clone(),
            key_generator: OsRngContentEncryptionKeyGenerator,
            encryptor: Aes256CtrContentEncryption,
            cek_store,
        }
    }
}

impl Default for MonasController {
    fn default() -> Self {
        Self::new()
    }
}
