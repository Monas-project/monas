mod async_api;
mod content;
mod keypair;
mod share;
mod state;
use std::sync::Arc;

use content::{ContentServiceInstance, DynCekStore};
use share::{DynPublicKeyDirectory, DynShareRepository, ShareServiceInstance};

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
    // `ApiError` は `#[non_exhaustive]` だが crate 内では全 variant が見えるので、
    // catch-all を置かずに全 variant を明示列挙する。
    // 将来 `ApiError` に新 variant が追加された場合、ここが compile error になり
    // 「variant をどう保持/分類するか」を決め忘れる事故を防ぐ
    // (catch-all で `Internal` に collapse すると 401/404/408/409 が 500 化する旧バグの再発になる)。
    match primary {
        ApiError::Validation(_) => ApiError::Validation(suffix),
        ApiError::Unauthorized(_) => ApiError::Unauthorized(suffix),
        ApiError::Forbidden(_) => ApiError::Forbidden(suffix),
        ApiError::NotFound(_) => ApiError::NotFound(suffix),
        ApiError::Conflict(_) => ApiError::Conflict(suffix),
        ApiError::Timeout(_) => ApiError::Timeout(suffix),
        ApiError::Internal(_) => ApiError::Internal(suffix),
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
    /// **このコンストラクタは test/開発専用。** 本番 gateway は必ず
    /// `with_config` + `MonasConfig::with_persistence_dir(...)` を使うこと。
    /// in-memory persistence のため、再起動で CEK / share / public-key directory が
    /// 全て揮発する。
    ///
    /// TODO(pr46-followup): `#[cfg(any(test, feature = "test-util"))]` で
    /// 本番 binary から完全に消す型レベル強制は別 PR で扱う。現時点では
    /// `#[deprecated]` で build 時 warning を出すに留める。
    #[deprecated(
        note = "test/dev-only constructor: use MonasController::with_config(MonasConfig::new(...).with_persistence_dir(...)) for production gateways"
    )]
    pub fn with_state_node_url(state_node_url: impl Into<String>) -> Self {
        let url = state_node_url.into();
        // 開発/テスト互換のため、account_url は明示未指定時に state_node_url と同じ値を使う。
        Self::with_config(MonasConfig::new(url.clone(), url))
            .expect("InMemory persistence must not fail to open")
    }

    /// State Node URL と Account URL を明示してMonasControllerを生成 (in-memory persistence)。
    ///
    /// **このコンストラクタは test/開発専用。** 本番 gateway は必ず
    /// `with_config` + `MonasConfig::with_persistence_dir(...)` を使うこと。
    /// in-memory persistence のため、再起動で CEK / share / public-key directory が
    /// 全て揮発する。
    #[deprecated(
        note = "test/dev-only constructor: use MonasController::with_config(MonasConfig::new(...).with_persistence_dir(...)) for production gateways"
    )]
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
        // TODO(pr46-followup architecture):
        // The SDK still constructs in-process `ContentService` + `ShareService`,
        // making it a parallel authoritative tier alongside State Node. This is
        // a *deferred* item from the PR #29 review; see PR #46 description's
        // "Out of scope" section. The proper fix is either (a) make the SDK a
        // stateless thin client and push CEK / share ownership to State Node,
        // or (b) define an explicit pluggable port for CEK ownership semantics.
        let content_repository = Self::create_content_repository();
        let (cek_store, share_repository, public_key_directory) =
            Self::create_persistence(&config.persistence)?;
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
                public_key_directory,
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
    ///
    /// TODO(pr46-followup): content body は依然 `MultiStorageRepository::in_memory` 固定で、
    /// `Sled` モードを選んでも暗号文ローカルキャッシュは再起動で揮発する。
    /// State Node が canonical なので decrypt 自体は復元可能 (CEK は sled で永続化済) だが、
    /// SDK ローカルキャッシュ層も pluggable 化するのは別 PR で扱う (PR #46 description 参照)。
    fn create_content_repository() -> monas_content::infrastructure::MultiStorageRepository {
        use monas_content::infrastructure::MultiStorageRepository;
        let registry = std::sync::Arc::new(monas_filesync::init_registry_default());
        MultiStorageRepository::in_memory(registry, "local")
    }

    /// `PersistenceConfig` から CEK ストア / Share repository / Public key directory の
    /// 動的インスタンスを構築する。
    ///
    /// `InMemory` 選択時は揮発する旨の警告を stderr に 1 度だけ出す。
    ///
    /// `Sled { dir }` 選択時は **単一の `sled::Db`** を 1 度だけ open し、
    /// CEK / Share / Public key directory の 3 ストアに共有させる。sled は path 単位で
    /// 排他 flock を取るため、同じディレクトリを 2 度 open すると 2 個目が
    /// 失敗する (`MONAS_PERSISTENCE_DIR` 設定時の本番経路で必ず再現)。
    /// キー空間は `cek:` / `share:` / `pubkey:` プレフィックスで分離されている。
    fn create_persistence(
        persistence: &PersistenceConfig,
    ) -> Result<(DynCekStore, DynShareRepository, DynPublicKeyDirectory), ApiError> {
        use monas_content::infrastructure::{
            key_store::{InMemoryContentEncryptionKeyStore, SledContentEncryptionKeyStore},
            public_key_directory::{InMemoryPublicKeyDirectory, SledPublicKeyDirectory},
            share_repository::{InMemoryShareRepository, SledShareRepository},
        };

        match persistence {
            PersistenceConfig::InMemory => {
                eprintln!(
                    "monas-sdk: PersistenceConfig::InMemory is in use. \
                     CEK / share / public-key data are kept in memory only and will be lost on restart. \
                     Use MonasConfig::with_persistence_dir(<path>) for production gateways."
                );
                let cek: DynCekStore = Arc::new(InMemoryContentEncryptionKeyStore::default());
                let share: DynShareRepository = Arc::new(InMemoryShareRepository::default());
                let pkd: DynPublicKeyDirectory = Arc::new(InMemoryPublicKeyDirectory::default());
                Ok((cek, share, pkd))
            }
            PersistenceConfig::Sled { dir } => {
                if let Err(e) = std::fs::create_dir_all(dir) {
                    return Err(ApiError::Internal(format!(
                        "failed to create persistence dir {dir:?}: {e}"
                    )));
                }
                // sled は path 単位で flock を取るので 1 度だけ開く。
                // `sled::Db` は Arc ベースで Clone 可能なので、3 つのストアに同じ Db を渡す。
                let db = sled::open(dir).map_err(|e| {
                    ApiError::Internal(format!("failed to open sled DB at {dir:?}: {e}"))
                })?;
                let cek = SledContentEncryptionKeyStore::with_db(db.clone());
                let share = SledShareRepository::with_db(db.clone());
                let pkd = SledPublicKeyDirectory::with_db(db);
                let cek: DynCekStore = Arc::new(cek);
                let share: DynShareRepository = Arc::new(share);
                let pkd: DynPublicKeyDirectory = Arc::new(pkd);
                Ok((cek, share, pkd))
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
        public_key_directory: DynPublicKeyDirectory,
    ) -> ShareServiceInstance {
        use monas_content::application_service::share_service::ShareService;
        use monas_content::infrastructure::key_wrapping::HpkeV1KeyWrapping;

        ShareService {
            share_repository,
            content_repository,
            cek_store,
            public_key_directory,
            key_wrapper: HpkeV1KeyWrapping,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `combine_rollback_failure` は `primary` の variant を保ち、message に
    /// rollback 情報を suffix として追加する。
    /// PR #29 review (design 軸) で指摘された「ApiError::Internal collapse」を
    /// regression として固定するためのテスト。
    #[test]
    fn combine_rollback_failure_preserves_validation_variant() {
        let combined = combine_rollback_failure(
            ApiError::Validation("bad".into()),
            "boom",
            "Op",
            "primary",
            "rollback",
        );
        assert!(matches!(combined, ApiError::Validation(_)));
        let msg = combined.to_string();
        assert!(msg.contains("Op failed"), "msg={msg}");
        assert!(msg.contains("primary=Validation error: bad"), "msg={msg}");
        assert!(msg.contains("rollback=boom"), "msg={msg}");
    }

    #[test]
    fn combine_rollback_failure_preserves_unauthorized_variant() {
        let combined = combine_rollback_failure(
            ApiError::Unauthorized("nope".into()),
            "rb-fail",
            "Sign",
            "primary",
            "rollback",
        );
        assert!(matches!(combined, ApiError::Unauthorized(_)));
        assert_eq!(combined.status_code(), 401);
    }

    #[test]
    fn combine_rollback_failure_preserves_forbidden_variant() {
        let combined = combine_rollback_failure(
            ApiError::Forbidden("no".into()),
            "rb",
            "Op",
            "primary",
            "rollback",
        );
        assert!(matches!(combined, ApiError::Forbidden(_)));
        assert_eq!(combined.status_code(), 403);
    }

    #[test]
    fn combine_rollback_failure_preserves_not_found_variant() {
        let combined = combine_rollback_failure(
            ApiError::NotFound("missing".into()),
            "rb",
            "Op",
            "primary",
            "rollback",
        );
        assert!(matches!(combined, ApiError::NotFound(_)));
        assert_eq!(combined.status_code(), 404);
    }

    #[test]
    fn combine_rollback_failure_preserves_conflict_variant() {
        let combined = combine_rollback_failure(
            ApiError::Conflict("dup".into()),
            "rb",
            "Op",
            "primary",
            "rollback",
        );
        assert!(matches!(combined, ApiError::Conflict(_)));
        assert_eq!(combined.status_code(), 409);
    }

    #[test]
    fn combine_rollback_failure_preserves_timeout_variant() {
        let combined = combine_rollback_failure(
            ApiError::Timeout("hang".into()),
            "rb",
            "Op",
            "primary",
            "rollback",
        );
        assert!(matches!(combined, ApiError::Timeout(_)));
        assert_eq!(combined.status_code(), 408);
    }

    #[test]
    fn combine_rollback_failure_preserves_internal_variant() {
        let combined = combine_rollback_failure(
            ApiError::Internal("oops".into()),
            "rb",
            "Op",
            "primary",
            "rollback",
        );
        assert!(matches!(combined, ApiError::Internal(_)));
        assert_eq!(combined.status_code(), 500);
    }

    #[test]
    fn combine_rollback_failure_message_contains_labels() {
        let combined = combine_rollback_failure(
            ApiError::NotFound("x".into()),
            "y",
            "ContextOp",
            "remote",
            "restore",
        );
        let msg = combined.to_string();
        assert!(msg.contains("ContextOp failed"));
        assert!(msg.contains("local restore also failed"));
        assert!(msg.contains("remote=Not found: x"));
        assert!(msg.contains("restore=y"));
    }
}
