mod content;
mod keypair;
mod share;
mod state;
use content::ContentServiceInstance;
use share::ShareServiceInstance;

/// MonasController - SDK のオーケストレーター
///
/// 各ドメイン（monas-account, monas-content, monas-state-node）の
/// Presentation層を呼び出してオーケストレーションを行う
pub struct MonasController {
    /// State NodeのベースURL
    state_node_url: String,
    /// ContentService
    content_service: ContentServiceInstance,
    /// ShareService
    share_service: ShareServiceInstance,
}

impl MonasController {
    /// 環境変数からState Node URLを取得してMonasControllerを生成
    ///
    /// 環境変数 `MONAS_STATE_NODE_URL` が設定されている場合はそれを使用し、
    /// 設定されていない場合はデフォルト値 `http://127.0.0.1:8080` を使用します。
    pub fn new() -> Self {
        let state_node_url = std::env::var("MONAS_STATE_NODE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

        let content_repository = Self::create_content_repository();
        let cek_store = Self::create_cek_store();

        Self {
            state_node_url,
            content_service: Self::create_content_service(
                content_repository.clone(),
                cek_store.clone(),
            ),
            share_service: Self::create_share_service(content_repository, cek_store),
        }
    }

    /// 明示的にState Node URLを指定してMonasControllerを生成
    pub fn with_state_node_url(state_node_url: impl Into<String>) -> Self {
        let content_repository = Self::create_content_repository();
        let cek_store = Self::create_cek_store();

        Self {
            state_node_url: state_node_url.into(),
            content_service: Self::create_content_service(
                content_repository.clone(),
                cek_store.clone(),
            ),
            share_service: Self::create_share_service(content_repository, cek_store),
        }
    }

    /// ContentRepositoryのインスタンスを作成するヘルパーメソッド
    fn create_content_repository(
    ) -> monas_content::infrastructure::repository::InMemoryContentRepository {
        use monas_content::infrastructure::repository::InMemoryContentRepository;
        InMemoryContentRepository::default()
    }

    /// ContentEncryptionKeyStoreのインスタンスを作成するヘルパーメソッド
    fn create_cek_store(
    ) -> monas_content::infrastructure::key_store::InMemoryContentEncryptionKeyStore {
        use monas_content::infrastructure::key_store::InMemoryContentEncryptionKeyStore;
        InMemoryContentEncryptionKeyStore::default()
    }

    /// ContentServiceのインスタンスを作成するヘルパーメソッド
    fn create_content_service(
        content_repository: monas_content::infrastructure::repository::InMemoryContentRepository,
        cek_store: monas_content::infrastructure::key_store::InMemoryContentEncryptionKeyStore,
    ) -> ContentServiceInstance {
        use monas_content::application_service::content_service::ContentService;
        use monas_content::infrastructure::{
            content_id::Sha256ContentIdGenerator,
            encryption::{Aes256CtrContentEncryption, OsRngContentEncryptionKeyGenerator},
        };

        ContentService {
            content_id_generator: Sha256ContentIdGenerator,
            content_repository: content_repository.clone(),
            key_generator: OsRngContentEncryptionKeyGenerator,
            encryptor: Aes256CtrContentEncryption,
            cek_store: cek_store.clone(),
        }
    }

    /// ShareServiceのインスタンスを作成するヘルパーメソッド
    fn create_share_service(
        content_repository: monas_content::infrastructure::repository::InMemoryContentRepository,
        cek_store: monas_content::infrastructure::key_store::InMemoryContentEncryptionKeyStore,
    ) -> ShareServiceInstance {
        use monas_content::application_service::share_service::ShareService;
        use monas_content::infrastructure::{
            key_wrapping::HpkeV1KeyWrapping, public_key_directory::InMemoryPublicKeyDirectory,
            share_repository::InMemoryShareRepository,
        };

        ShareService {
            share_repository: InMemoryShareRepository::default(),
            content_repository,
            cek_store,
            public_key_directory: InMemoryPublicKeyDirectory::default(),
            key_wrapper: HpkeV1KeyWrapping,
        }
    }
}

impl Default for MonasController {
    fn default() -> Self {
        Self::new()
    }
}
