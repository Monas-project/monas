mod content;
mod keypair;
mod share;
mod state;
use content::ContentServiceInstance;
use share::ShareServiceInstance;

use crate::common::MonasConfig;

/// MonasController - SDK のオーケストレーター
pub struct MonasController {
    /// State NodeのベースURL
    pub(super) state_node_url: String,
    /// Account(issuer)のベースURL
    pub(super) account_url: String,
    /// 全 HTTP 呼び出しで共有する ureq Agent (タイムアウト等を保持)
    pub(super) agent: ureq::Agent,
    /// ContentService
    content_service: ContentServiceInstance,
    /// ShareService
    share_service: ShareServiceInstance,
}

impl MonasController {
    /// 環境変数からState Node URLを取得してMonasControllerを生成
    ///
    /// 環境変数 `MONAS_STATE_NODE_URL` が設定されている場合はそれを使用し、
    /// 設定されていない場合はデフォルト値 `http://127.0.0.1:8080` を使用
    pub fn new() -> Self {
        let state_node_url = std::env::var("MONAS_STATE_NODE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let account_url =
            std::env::var("MONAS_ACCOUNT_URL").unwrap_or_else(|_| "http://127.0.0.1:4002".into());
        Self::with_config(MonasConfig::new(state_node_url, account_url))
    }

    /// 明示的にState Node URLを指定してMonasControllerを生成
    pub fn with_state_node_url(state_node_url: impl Into<String>) -> Self {
        let url = state_node_url.into();
        // 開発/テスト互換のため、account_url は明示未指定時に state_node_url と同じ値を使う。
        Self::with_config(MonasConfig::new(url.clone(), url))
    }

    /// State Node URL と Account URL を明示してMonasControllerを生成
    pub fn with_urls(state_node_url: impl Into<String>, account_url: impl Into<String>) -> Self {
        Self::with_config(MonasConfig::new(state_node_url, account_url))
    }

    /// `MonasConfig` を使って MonasController を生成する。
    ///
    /// タイムアウトなど今後追加される設定はこの経路で注入する。
    pub fn with_config(config: MonasConfig) -> Self {
        let content_repository = Self::create_content_repository();
        let cek_store = Self::create_cek_store();
        let agent = Self::build_agent(&config);

        Self {
            state_node_url: config.state_node_url,
            account_url: config.account_url,
            agent,
            content_service: Self::create_content_service(
                content_repository.clone(),
                cek_store.clone(),
            ),
            share_service: Self::create_share_service(content_repository, cek_store),
        }
    }

    /// 設定から ureq::Agent を構築するヘルパーメソッド
    fn build_agent(config: &MonasConfig) -> ureq::Agent {
        let ureq_config = ureq::Agent::config_builder()
            .timeout_global(Some(config.request_timeout))
            .build();
        ureq::Agent::new_with_config(ureq_config)
    }

    /// ContentRepositoryのインスタンスを作成するヘルパーメソッド
    fn create_content_repository() -> monas_content::infrastructure::MultiStorageRepository {
        use monas_content::infrastructure::MultiStorageRepository;
        let registry = std::sync::Arc::new(monas_filesync::init_registry_default());
        MultiStorageRepository::in_memory(registry, "local")
    }

    /// ContentEncryptionKeyStoreのインスタンスを作成するヘルパーメソッド
    fn create_cek_store(
    ) -> monas_content::infrastructure::key_store::InMemoryContentEncryptionKeyStore {
        use monas_content::infrastructure::key_store::InMemoryContentEncryptionKeyStore;
        InMemoryContentEncryptionKeyStore::default()
    }

    /// ContentServiceのインスタンスを作成するヘルパーメソッド
    fn create_content_service(
        content_repository: monas_content::infrastructure::MultiStorageRepository,
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
        content_repository: monas_content::infrastructure::MultiStorageRepository,
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
