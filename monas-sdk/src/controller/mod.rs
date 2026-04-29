mod async_api;
mod content;
mod keypair;
mod share;
mod state;
use std::sync::Arc;

use content::{ContentServiceInstance, DynCekStore};
use share::{DynShareRepository, ShareServiceInstance};

use crate::common::{ApiError, MonasConfig, PersistenceConfig};

/// プライマリ操作が失敗し、補償 (rollback / restore) も失敗した場合に返すべき
/// 単一 `ApiError` を組み立てる helper。
///
/// PR #29 review (design 軸 / `ApiError::Internal` collapse) で指摘されたとおり、
/// 何も考えず `ApiError::Internal(format!(...))` に潰すと
/// 元の 401 / 404 / 408 / 409 が一律 500 に化けて呼び出し側が誤った対応を取る。
///
/// この helper は:
/// - `primary` が `Internal` でない場合 → primary の variant を保ったまま、
///   message に rollback 失敗情報を suffix として追記する。
/// - `primary` が `Internal` の場合 → 従来通り `Internal` のまま結合する。
///
/// `context` は呼び出し側固有のラベル (例: "State Node create").
/// `primary_label` / `rollback_label` は message を読みやすくするための識別子
/// (例: "remote" / "rollback").
pub(super) fn combine_rollback_failure(
    primary: ApiError,
    rollback_err: impl std::fmt::Display,
    context: &str,
    primary_label: &str,
    rollback_label: &str,
) -> ApiError {
    let suffix = format!(
        "{context} failed and local {rollback_label} also failed: \
         {primary_label}={primary}, {rollback_label}={rollback_err}"
    );
    // `ApiError` は `#[non_exhaustive]`。crate 内では現在の variant 列挙でカバーできるが、
    // 将来 crate 外で variant が増えた場合に備えて safety net を残す意図で
    // `unreachable_patterns` 警告を抑止する。
    #[allow(unreachable_patterns)]
    match primary {
        ApiError::Validation(_) => ApiError::Validation(suffix),
        ApiError::Unauthorized(_) => ApiError::Unauthorized(suffix),
        ApiError::Forbidden(_) => ApiError::Forbidden(suffix),
        ApiError::NotFound(_) => ApiError::NotFound(suffix),
        ApiError::Conflict(_) => ApiError::Conflict(suffix),
        ApiError::Timeout(_) => ApiError::Timeout(suffix),
        ApiError::Internal(_) => ApiError::Internal(suffix),
        _ => ApiError::Internal(suffix),
    }
}

/// MonasController - SDK のオーケストレーター
pub struct MonasController {
    /// State NodeのベースURL
    pub(super) state_node_url: String,
    /// Account(issuer)のベースURL
    pub(super) account_url: String,
    /// 全 HTTP 呼び出しで共有する ureq Agent (タイムアウト等を保持)
    pub(super) agent: ureq::Agent,
    /// `X-Request-Timestamp` の許容 skew (Gateway 経由で渡された timestamp が古すぎる/未来すぎる場合 reject)
    pub(super) request_timestamp_skew: std::time::Duration,
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
            request_timestamp_skew: config.request_timestamp_skew,
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
