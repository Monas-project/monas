mod content;
mod keypair;
mod share;
mod state;
use std::sync::Arc;

use content::{ContentServiceInstance, DynCekStore};
use share::{DynShareRepository, ShareServiceInstance};

use crate::common::{ApiError, MonasConfig, PersistenceConfig};

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
    /// 明示的にState Node URLを指定してMonasControllerを生成 (in-memory persistence)。
    ///
    /// 本番 gateway はこのコンストラクタを使ってはならない。
    /// 必ず `with_config` + `MonasConfig::with_persistence_dir(...)` を使うこと。
    pub fn with_state_node_url(state_node_url: impl Into<String>) -> Self {
        let url = state_node_url.into();
        // 開発/テスト互換のため、account_url は明示未指定時に state_node_url と同じ値を使う。
        Self::with_config(MonasConfig::new(url.clone(), url))
            .expect("InMemory persistence must not fail to open")
    }

    /// State Node URL と Account URL を明示してMonasControllerを生成 (in-memory persistence)。
    ///
    /// 本番 gateway はこのコンストラクタを使ってはならない。
    /// 必ず `with_config` + `MonasConfig::with_persistence_dir(...)` を使うこと。
    pub fn with_urls(state_node_url: impl Into<String>, account_url: impl Into<String>) -> Self {
        Self::with_config(MonasConfig::new(state_node_url, account_url))
            .expect("InMemory persistence must not fail to open")
    }

    /// `MonasConfig` を使って `MonasController` を生成する。
    ///
    /// `config.persistence` に応じて CEK ストアと Share repository を構築する。
    /// `Sled { dir }` の場合、ディレクトリが存在しなければ作成する。
    /// オープンに失敗した場合は `ApiError::Internal` を返す。
    ///
    /// `InMemory` persistence は揮発するため、本番 gateway は必ず
    /// `MonasConfig::with_persistence_dir(...)` で sled backend を指定すること。
    pub fn with_config(config: MonasConfig) -> Result<Self, ApiError> {
        let content_repository = Self::create_content_repository();
        let (cek_store, share_repository) = Self::create_persistence(&config.persistence)?;
        let agent = Self::build_agent(&config);

        Ok(Self {
            state_node_url: config.state_node_url,
            account_url: config.account_url,
            agent,
            content_service: Self::create_content_service(
                content_repository.clone(),
                cek_store.clone(),
            ),
            share_service: Self::create_share_service(
                content_repository,
                cek_store,
                share_repository,
            ),
        })
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

    /// `PersistenceConfig` から CEK ストアと Share repository の動的インスタンスを構築する。
    ///
    /// `InMemory` 選択時は揮発する旨の警告を stderr に 1 度だけ出す。
    /// `Sled { dir }` 選択時は同一の sled DB を CEK と Share で共有する
    /// (キー空間はそれぞれ `cek:` / `share:` プレフィックスで分離されている)。
    fn create_persistence(
        persistence: &PersistenceConfig,
    ) -> Result<(DynCekStore, DynShareRepository), ApiError> {
        use monas_content::infrastructure::{
            key_store::{InMemoryContentEncryptionKeyStore, SledContentEncryptionKeyStore},
            share_repository::{InMemoryShareRepository, SledShareRepository},
        };

        match persistence {
            PersistenceConfig::InMemory => {
                eprintln!(
                    "monas-sdk: PersistenceConfig::InMemory is in use. \
                     CEK and share data are kept in memory only and will be lost on restart. \
                     Use MonasConfig::with_persistence_dir(<path>) for production gateways."
                );
                let cek: DynCekStore = Arc::new(InMemoryContentEncryptionKeyStore::default());
                let share: DynShareRepository = Arc::new(InMemoryShareRepository::default());
                Ok((cek, share))
            }
            PersistenceConfig::Sled { dir } => {
                if let Err(e) = std::fs::create_dir_all(dir) {
                    return Err(ApiError::Internal(format!(
                        "failed to create persistence dir {dir:?}: {e}"
                    )));
                }
                let cek = SledContentEncryptionKeyStore::open(dir).map_err(|e| {
                    ApiError::Internal(format!("failed to open sled CEK store at {dir:?}: {e}"))
                })?;
                let share = SledShareRepository::open(dir).map_err(|e| {
                    ApiError::Internal(format!(
                        "failed to open sled share repository at {dir:?}: {e}"
                    ))
                })?;
                let cek: DynCekStore = Arc::new(cek);
                let share: DynShareRepository = Arc::new(share);
                Ok((cek, share))
            }
        }
    }

    /// ContentServiceのインスタンスを作成するヘルパーメソッド
    fn create_content_service(
        content_repository: monas_content::infrastructure::MultiStorageRepository,
        cek_store: DynCekStore,
    ) -> ContentServiceInstance {
        use monas_content::application_service::content_service::ContentService;
        use monas_content::infrastructure::{
            content_id::Sha256ContentIdGenerator,
            encryption::{Aes256CtrContentEncryption, OsRngContentEncryptionKeyGenerator},
        };

        ContentService {
            content_id_generator: Sha256ContentIdGenerator,
            content_repository,
            key_generator: OsRngContentEncryptionKeyGenerator,
            encryptor: Aes256CtrContentEncryption,
            cek_store,
        }
    }

    /// ShareServiceのインスタンスを作成するヘルパーメソッド
    fn create_share_service(
        content_repository: monas_content::infrastructure::MultiStorageRepository,
        cek_store: DynCekStore,
        share_repository: DynShareRepository,
    ) -> ShareServiceInstance {
        use monas_content::application_service::share_service::ShareService;
        use monas_content::infrastructure::{
            key_wrapping::HpkeV1KeyWrapping, public_key_directory::InMemoryPublicKeyDirectory,
        };

        ShareService {
            share_repository,
            content_repository,
            cek_store,
            public_key_directory: InMemoryPublicKeyDirectory::default(),
            key_wrapper: HpkeV1KeyWrapping,
        }
    }
}
