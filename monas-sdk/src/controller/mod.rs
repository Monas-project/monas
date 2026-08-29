mod async_api;
mod content;
mod keypair;
mod share;
mod state;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use content::{ContentServiceInstance, DynCekStore};
use share::{DynPublicKeyDirectory, DynShareRepository, ShareServiceInstance};

use crate::common::{ApiError, ApiResponse, MonasConfig, PersistenceConfig, StateNodeAuthContext};

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
    /// share 受信者側の送信者公開鍵ピン(TOFU)と受理済み CEK 鍵世代の記録
    /// (KeyEnvelope の送信者認証と rotation 巻き戻し replay 防止)
    sender_pin_store: DynSenderPinStore,
    /// content 単位の revoke 直列化ロック。
    content_revoke_locks: ContentLocks,
}

/// SDK が使う送信者鍵ピンストアの動的型。
///
/// 参照するのは application 層のポートで、実装(In-memory / Sled)がある
/// infrastructure 層ではない。SDK が特定の保存先実装に依存しないようにする。
pub(super) type DynSenderPinStore =
    std::sync::Arc<dyn monas_content::application_service::share_service::SenderKeyPinStore>;

/// content id ごとの相互排他ロック。
///
/// revoke は「ACL・CEK・ローカル ciphertext・state node の状態」を
/// load-modify-save で更新する複合操作で、そのどれにも version CAS が無い。
/// `MonasController` は gateway 等で `Arc` 共有され複数リクエストから同時に
/// 呼ばれるため、同じ content への revoke が並行すると次が起こる:
///
/// - 双方が同じ Share を読み、後勝ちで save → 片方の受信者削除が消える
///   (lost update)
/// - 異なる CEK が同じ key_epoch として配られる
/// - ローカル ACL/CEK と state node の ciphertext が別リクエスト由来になる
///
/// 根本解決は Share・CEK・ciphertext を1つの transactional CAS にまとめる
/// ことだが、3ストア + リモート更新にまたがるため、まず content 単位の
/// 直列化で「並行 revoke が状態を分岐させない」ことを保証する。
/// ロックはプロセス内のみで、複数 gateway プロセスからの並行 revoke は
/// カバーしない(その場合は state node 側の CAS が必要)。
#[derive(Default)]
struct ContentLocksState {
    /// 現在 revoke 中の content id。エントリが無い = 誰も触っていない。
    held: std::collections::HashSet<String>,
}

#[derive(Clone, Default)]
pub(super) struct ContentLocks {
    inner: Arc<(std::sync::Mutex<ContentLocksState>, std::sync::Condvar)>,
}

impl ContentLocks {
    /// `content_id` の revoke 権を取り、保持している間だけ他を待たせるガードを
    /// 返す。同じ id への revoke は直列化され、異なる id は互いに待たない。
    ///
    /// ガードを drop するとエントリが表から消える(待っている者がいれば、その
    /// 相手が起きて自分のエントリを立て直す)。**表は revoke 中の content 数
    /// までしか伸びない** — 詳細は [`ContentLockGuard`]。
    pub(super) fn lock(&self, content_id: &str) -> ContentLockGuard {
        let (mutex, condvar) = &*self.inner;
        let mut state = mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // 既に誰かが持っているなら空くまで待つ。`wait` は mutex を手放すので、
        // 待っている間に解放側が入れる。
        while state.held.contains(content_id) {
            state = condvar
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }

        // 空いていた: 自分が保持者になる。
        state.held.insert(content_id.to_string());
        drop(state);

        ContentLockGuard {
            locks: self.inner.clone(),
            content_id: content_id.to_string(),
        }
    }

    /// 現在このレジストリが保持しているエントリ数(テスト用)。
    #[cfg(test)]
    pub(super) fn tracked_len(&self) -> usize {
        let (mutex, _) = &*self.inner;
        mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .held
            .len()
    }
}

/// 保持している間だけ、その content の revoke が直列化される。
///
/// drop 時にエントリを表から取り除き、待っている者を起こす。取り除かないと、
/// revoke した content の数だけ表が伸び続けて二度と縮まない — gateway は
/// 動かしっぱなしなので、稼働時間と扱った content 数に比例してメモリを食う。
/// 1 件あたりは数十バイトだが上限が無いのが問題で、PR #56 のレビューで
/// 指摘された。
///
/// エントリの有無そのものが「保持者がいるか」を表すので、drop では常に消す。
/// 待っている者はこの削除を見て初めて自分が保持者になれる(`lock` の while は
/// `contains_key` が false になるまで回る)。判定も削除も同じ mutex の下で
/// 行うため、起きた側が保持者になるまでに別のリクエストが割り込む隙は無い。
/// 結果として、**表のサイズは同時に revoke 中の content 数**で頭打ちになる。
pub(super) struct ContentLockGuard {
    locks: Arc<(std::sync::Mutex<ContentLocksState>, std::sync::Condvar)>,
    content_id: String,
}

impl Drop for ContentLockGuard {
    fn drop(&mut self) {
        let (mutex, condvar) = &*self.locks;
        let mut state = mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // エントリを落とすことが「解放」そのもの。これが無いと表が伸び続ける。
        state.held.remove(&self.content_id);
        drop(state);
        condvar.notify_all();
    }
}

impl MonasController {
    pub(super) fn current_unix_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Validate a caller-supplied State Node request timestamp.
    ///
    /// `auth: None` callers are handled by the caller and remain the dev/test
    /// unsigned path. Once an auth context exists, timestamp must be present and
    /// inside the configured skew window; otherwise a gateway can turn missing
    /// or malformed replay metadata into a freshly signed request.
    pub(super) fn resolve_request_timestamp<T>(
        &self,
        ctx: &StateNodeAuthContext,
        trace_id: &str,
    ) -> Result<u64, ApiResponse<T>> {
        let now = Self::current_unix_timestamp();
        let Some(ts) = ctx.request_timestamp else {
            return Err(ApiResponse::error(
                ApiError::Unauthorized("X-Request-Timestamp is required".into()),
                trace_id.to_string(),
            ));
        };
        let skew = self.request_timestamp_skew.as_secs();
        let diff = ts.abs_diff(now);
        if diff > skew {
            return Err(ApiResponse::error(
                ApiError::Unauthorized(format!(
                    "X-Request-Timestamp out of acceptable window (|now - ts| = {diff}s, max = {skew}s)"
                )),
                trace_id.to_string(),
            ));
        }
        Ok(ts)
    }

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
        let (cek_store, share_repository, public_key_directory, sender_pin_store) =
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
            sender_pin_store,
            content_revoke_locks: ContentLocks::default(),
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
    /// キー空間は `cek:` / `share:` / `pubkey:` / `sender_pin:` プレフィックスで分離されている。
    fn create_persistence(
        persistence: &PersistenceConfig,
    ) -> Result<
        (
            DynCekStore,
            DynShareRepository,
            DynPublicKeyDirectory,
            DynSenderPinStore,
        ),
        ApiError,
    > {
        use monas_content::infrastructure::{
            key_store::{InMemoryContentEncryptionKeyStore, SledContentEncryptionKeyStore},
            public_key_directory::{InMemoryPublicKeyDirectory, SledPublicKeyDirectory},
            sender_key_pin_store::{InMemorySenderKeyPinStore, SledSenderKeyPinStore},
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
                let sender_pin: DynSenderPinStore = Arc::new(InMemorySenderKeyPinStore::default());
                Ok((cek, share, pkd, sender_pin))
            }
            PersistenceConfig::Sled { dir } => {
                if let Err(e) = std::fs::create_dir_all(dir) {
                    return Err(ApiError::Internal(format!(
                        "failed to create persistence dir {dir:?}: {e}"
                    )));
                }
                // sled は path 単位で flock を取るので 1 度だけ開く。
                // `sled::Db` は Arc ベースで Clone 可能なので、4 つのストアに同じ Db を渡す。
                let db = sled::open(dir).map_err(|e| {
                    ApiError::Internal(format!("failed to open sled DB at {dir:?}: {e}"))
                })?;
                let cek = SledContentEncryptionKeyStore::with_db(db.clone());
                let share = SledShareRepository::with_db(db.clone());
                let pkd = SledPublicKeyDirectory::with_db(db.clone());
                let sender_pin = SledSenderKeyPinStore::with_db(db);
                let cek: DynCekStore = Arc::new(cek);
                let share: DynShareRepository = Arc::new(share);
                let pkd: DynPublicKeyDirectory = Arc::new(pkd);
                let sender_pin: DynSenderPinStore = Arc::new(sender_pin);
                Ok((cek, share, pkd, sender_pin))
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
            encryption::{Aes256GcmContentEncryption, OsRngContentEncryptionKeyGenerator},
        };

        ContentService {
            content_id_generator: Sha256ContentIdGenerator,
            content_repository,
            key_generator: OsRngContentEncryptionKeyGenerator,
            encryptor: Aes256GcmContentEncryption,
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

    /// ロックを手放したら、その content のエントリはレジストリから消える。
    ///
    /// 消さないと revoke した content の数だけ表が伸び続け、gateway は
    /// 動かしっぱなしなので稼働時間に比例してメモリを食う(PR #56 レビュー指摘)。
    #[test]
    fn releasing_a_content_lock_drops_its_registry_entry() {
        let locks = ContentLocks::default();
        assert_eq!(locks.tracked_len(), 0);

        {
            let _guard = locks.lock("content-1");
            assert_eq!(locks.tracked_len(), 1, "保持中はエントリがある");
        }
        assert_eq!(locks.tracked_len(), 0, "解放したら消える");

        // 別々の content を順に触っても溜まらない。
        for i in 0..100 {
            let _guard = locks.lock(&format!("content-{i}"));
        }
        assert_eq!(
            locks.tracked_len(),
            0,
            "順に revoke しただけでエントリが溜まってはならない"
        );
    }

    /// 表が縮んでも、同じ content への同時 revoke は直列化されたままである。
    /// (エントリ削除で相互排他まで壊していないことの確認)
    #[test]
    fn same_content_locks_are_still_mutually_exclusive() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let locks = ContentLocks::default();
        let inside = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        std::thread::scope(|scope| {
            for _ in 0..8 {
                let locks = locks.clone();
                let inside = inside.clone();
                let max_seen = max_seen.clone();
                scope.spawn(move || {
                    for _ in 0..50 {
                        let _guard = locks.lock("same-content");
                        let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                        max_seen.fetch_max(now, Ordering::SeqCst);
                        std::thread::yield_now();
                        inside.fetch_sub(1, Ordering::SeqCst);
                    }
                });
            }
        });

        assert_eq!(
            max_seen.load(Ordering::SeqCst),
            1,
            "同じ content のクリティカルセクションに同時に 2 つ入ってはならない"
        );
        assert_eq!(locks.tracked_len(), 0, "全部終われば空になる");
    }

    /// 異なる content は互いに待たない(id ごとに分けている意味の確認)。
    #[test]
    fn different_contents_do_not_block_each_other() {
        let locks = ContentLocks::default();
        let _held = locks.lock("content-a");
        // content-a を保持したまま content-b を取れる。ここで固まるなら
        // レジストリ全体を 1 本のロックで守ってしまっている。
        let _other = locks.lock("content-b");
        assert_eq!(locks.tracked_len(), 2);
    }

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
