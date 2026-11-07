mod async_api;
mod content;
mod keypair;
mod share;
mod state;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use content::{ContentServiceInstance, DynCekStore};
use share::{DynPublicKeyDirectory, DynShareRepository, ShareServiceInstance};

use monas_account::application_service::{AccountKeyStore, AccountService};
use monas_account::infrastructure::key_store::{InMemoryAccountKeyStore, SledAccountKeyStore};

use crate::common::{ApiError, ApiResponse, MonasConfig, PersistenceConfig, StateNodeAuthContext};

/// Helper that builds the single `ApiError` to return when the primary operation failed and the
/// compensation (rollback / restore) also failed.
///
/// As pointed out in the PR #29 review (design axis / `ApiError::Internal` collapse),
/// naively collapsing into `ApiError::Internal(format!(...))` turns
/// the original 401 / 404 / 408 / 409 uniformly into 500, and the caller responds incorrectly.
///
/// This helper:
/// - If `primary` is not `Internal` → keeps primary's variant and
///   appends the rollback failure info to the message as a suffix.
/// - If `primary` is `Internal` → combines them as `Internal`, as before.
///
/// `context` is a caller-specific label (e.g. "State Node create").
/// `primary_label` / `rollback_label` are identifiers that make the message easier to read
/// (e.g. "remote" / "rollback").
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
    // `ApiError` is `#[non_exhaustive]`, but all variants are visible inside the crate, so
    // enumerate every variant explicitly without a catch-all.
    // If a new variant is added to `ApiError` in the future, this becomes a compile error,
    // preventing us from forgetting to decide "how to preserve/classify the variant"
    // (collapsing to `Internal` via a catch-all would reintroduce the old bug where 401/404/408/409 became 500).
    match primary {
        ApiError::Validation(_) => ApiError::Validation(suffix),
        ApiError::Unauthorized(_) => ApiError::Unauthorized(suffix),
        ApiError::Forbidden(_) => ApiError::Forbidden(suffix),
        ApiError::NotFound(_) => ApiError::NotFound(suffix),
        ApiError::Gone(_) => ApiError::Gone(suffix),
        ApiError::Conflict(_) => ApiError::Conflict(suffix),
        ApiError::Timeout(_) => ApiError::Timeout(suffix),
        ApiError::Internal(_) => ApiError::Internal(suffix),
    }
}

/// Signing key store held by the SDK process.
pub(super) enum AccountKeyStoreKind {
    InMemory(InMemoryAccountKeyStore),
    Sled(SledAccountKeyStore),
}

impl AccountKeyStore for AccountKeyStoreKind {
    fn save(
        &self,
        key: &monas_account::application_service::StoredAccountKey,
    ) -> Result<(), monas_account::application_service::AccountKeyStoreError> {
        match self {
            Self::InMemory(store) => store.save(key),
            Self::Sled(store) => store.save(key),
        }
    }

    fn load(
        &self,
    ) -> Result<
        Option<monas_account::application_service::StoredAccountKey>,
        monas_account::application_service::AccountKeyStoreError,
    > {
        match self {
            Self::InMemory(store) => store.load(),
            Self::Sled(store) => store.load(),
        }
    }

    fn delete(&self) -> Result<(), monas_account::application_service::AccountKeyStoreError> {
        match self {
            Self::InMemory(store) => store.delete(),
            Self::Sled(store) => store.delete(),
        }
    }
}

/// MonasController - the SDK orchestrator
pub struct MonasController {
    /// Base URL of the State Node
    pub(super) state_node_url: String,
    /// Signing and delegation. The service holds the signing key store. One per process.
    ///
    /// No key is created at startup. It is created only when the user calls
    /// `create_signing_account`; until then, signing and delegation fail with a "no signing
    /// account" error.
    ///
    /// Kept in a separate directory from the sled for content CEKs. The signing key and the
    /// content key are distinct secrets, and sled flocks per path, so they cannot share a
    /// directory.
    pub(super) account_service: AccountService<AccountKeyStoreKind>,
    /// ureq Agent shared by all HTTP calls (holds timeouts, etc.)
    pub(super) agent: ureq::Agent,
    /// Allowed skew for `X-Request-Timestamp` (reject if the timestamp passed via the Gateway is too old / too far in the future)
    pub(super) request_timestamp_skew: std::time::Duration,
    /// ContentService
    content_service: ContentServiceInstance,
    /// ShareService
    share_service: ShareServiceInstance,
    /// Recipient-side record of sender public key pins (TOFU) and accepted CEK key epochs
    /// (KeyEnvelope sender authentication and prevention of rotation-rollback replay)
    sender_pin_store: DynSenderPinStore,
    /// Per-file (file_id) write serialization lock. Taken by update, delete, pull, and
    /// share, revoke, permission changes. The record, CEK, and share settings are one entry
    /// per file, so this keeps a rollback on failure from erasing a concurrent success.
    content_revoke_locks: ContentLocks,
}

/// Dynamic type of the sender key pin store used by the SDK.
///
/// It refers to the application-layer port, not the infrastructure layer that holds the
/// implementations (In-memory / Sled), so the SDK does not depend on a specific storage
/// implementation.
pub(super) type DynSenderPinStore =
    std::sync::Arc<dyn monas_content::application_service::share_service::SenderKeyPinStore>;

/// Mutual-exclusion lock per content id.
///
/// revoke is a compound operation that updates "ACL, CEK, local ciphertext, and state node
/// state" via load-modify-save, and none of them has a version CAS.
/// `MonasController` is shared via `Arc` in the gateway etc. and called concurrently from
/// multiple requests, so concurrent revokes on the same content cause the following:
///
/// - Both read the same Share and save last-writer-wins → one recipient removal is lost
///   (lost update)
/// - Different CEKs are distributed under the same key_epoch
/// - Local ACL/CEK and the state node ciphertext come from different requests
///
/// The fundamental fix is to combine Share, CEK, and ciphertext into one transactional CAS,
/// but since that spans 3 stores + a remote update, we first guarantee via per-content
/// serialization that "concurrent revokes do not fork the state".
/// The lock is in-process only and does not cover concurrent revokes from multiple gateway
/// processes (that requires a CAS on the state node side).
#[derive(Default)]
struct ContentLocksState {
    /// Content ids currently being revoked. No entry = nobody is touching it.
    held: std::collections::HashSet<String>,
}

#[derive(Clone, Default)]
pub(super) struct ContentLocks {
    inner: Arc<(std::sync::Mutex<ContentLocksState>, std::sync::Condvar)>,
}

impl ContentLocks {
    /// Takes the revoke right for `content_id` and returns a guard that makes others wait
    /// only while it is held. Revokes on the same id are serialized; different ids never wait
    /// on each other.
    ///
    /// Dropping the guard removes the entry from the table (if someone is waiting, that
    /// waiter wakes up and re-inserts its own entry). **The table grows only up to the number
    /// of content being revoked** — see [`ContentLockGuard`] for details.
    pub(super) fn lock(&self, content_id: &str) -> ContentLockGuard {
        let (mutex, condvar) = &*self.inner;
        let mut state = mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // If someone already holds it, wait until it is free. `wait` releases the mutex, so
        // the releasing side can get in while we wait.
        while state.held.contains(content_id) {
            state = condvar
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }

        // It was free: become the holder.
        state.held.insert(content_id.to_string());
        drop(state);

        ContentLockGuard {
            locks: self.inner.clone(),
            content_id: content_id.to_string(),
        }
    }

    /// Number of entries currently held by this registry (for tests).
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

/// While held, revokes on that content are serialized.
///
/// On drop, removes the entry from the table and wakes the waiters. Without removal, the
/// table keeps growing by the number of revoked content and never shrinks — the gateway runs
/// continuously, so memory grows in proportion to uptime and the number of content handled.
/// Each entry is only tens of bytes, but the lack of an upper bound is the problem; this was
/// pointed out in the PR #56 review.
///
/// The presence of the entry itself means "there is a holder", so drop always removes it.
/// A waiter can become the holder only after seeing this removal (the while in `lock` loops
/// until `contains_key` is false). Both the check and the removal happen under the same
/// mutex, so no other request can cut in before the woken side becomes the holder.
/// As a result, **the table size is capped at the number of content concurrently being
/// revoked**.
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

        // Dropping the entry is the "release" itself. Without it the table keeps growing.
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

    /// Creates a MonasController with an explicitly specified State Node URL (in-memory persistence).
    ///
    /// **This constructor is for test/development only.** Production gateways must use
    /// `with_config` + `MonasConfig::with_persistence_dir(...)`.
    /// Because persistence is in-memory, CEK / share / public-key directory are all lost on
    /// restart.
    ///
    /// TODO(pr46-followup): type-level enforcement that removes this entirely from production
    /// binaries via `#[cfg(any(test, feature = "test-util"))]` is handled in a separate PR. For
    /// now we only emit a build-time warning via `#[deprecated]`.
    #[deprecated(
        note = "test/dev-only constructor: use MonasController::with_config(MonasConfig::new(...).with_persistence_dir(...)) for production gateways"
    )]
    pub fn with_state_node_url(state_node_url: impl Into<String>) -> Self {
        Self::with_config(MonasConfig::new(state_node_url))
            .expect("InMemory persistence must not fail to open")
    }

    /// Creates a `MonasController` from a `MonasConfig`.
    ///
    /// Builds the CEK store and Share repository according to `config.persistence`.
    /// For `Sled { dir }`, creates the directory if it does not exist.
    /// Returns `ApiError::Internal` if opening fails.
    ///
    /// `InMemory` persistence is volatile, so production gateways must specify the sled
    /// backend via `MonasConfig::with_persistence_dir(...)`.
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
        let account_key_store = Self::create_account_key_store(&config.persistence)?;
        let account_service = AccountService {
            key_store: account_key_store,
        };
        let agent = Self::build_agent(&config);

        Ok(Self {
            state_node_url: config.state_node_url,
            account_service,
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

    /// Helper method that builds a ureq::Agent from the config
    ///
    /// Does not treat non-2xx as errors: each caller maps the status and response body to
    /// an `ApiError` (401/403/404/409 …) (`try_state_node_http_error` /
    /// `try_account_http_error`). With ureq's default, a 4xx becomes an Err from `send()`,
    /// the body is discarded, and it collapses into `Internal` (500) — the State Node's
    /// "403 due to Token revocation" was showing up as 500 from the gateway.
    fn build_agent(config: &MonasConfig) -> ureq::Agent {
        let ureq_config = ureq::Agent::config_builder()
            .timeout_global(Some(config.request_timeout))
            .http_status_as_error(false)
            .build();
        ureq::Agent::new_with_config(ureq_config)
    }

    /// Helper method that creates a ContentRepository instance
    ///
    /// TODO(pr46-followup): the content body is still fixed to `MultiStorageRepository::in_memory`,
    /// so even in `Sled` mode the local ciphertext cache is lost on restart.
    /// Since the State Node is canonical, decryption itself is recoverable (CEK is persisted in sled),
    /// but making the SDK local cache layer pluggable is handled in a separate PR (see PR #46 description).
    fn create_content_repository() -> monas_content::infrastructure::MultiStorageRepository {
        use monas_content::infrastructure::MultiStorageRepository;
        let registry = std::sync::Arc::new(monas_filesync::init_registry_default());
        MultiStorageRepository::in_memory(registry, "local")
    }

    /// Builds dynamic instances of the CEK store / Share repository / Public key directory
    /// from a `PersistenceConfig`.
    ///
    /// When `InMemory` is selected, prints a warning to stderr once that the data is volatile.
    ///
    /// When `Sled { dir }` is selected, opens a **single `sled::Db`** exactly once and
    /// shares it among the CEK / Share / Public key directory stores. sled takes an exclusive
    /// flock per path, so opening the same directory twice makes the second open
    /// fail (always reproduced on the production path when `MONAS_PERSISTENCE_DIR` is set).
    /// Key spaces are separated by the `cek:` / `share:` / `pubkey:` / `sender_pin:` prefixes.
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
                     Signing key / CEK / share / public-key data are kept in memory only and will be lost on restart. \
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
                // sled takes a flock per path, so open it only once.
                // `sled::Db` is Arc-based and Clone-able, so pass the same Db to all 4 stores.
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

    /// Creates the key store for the signing principal.
    ///
    /// Opens `dir/account`, separate from the content sled (directly under `dir`). Calling
    /// `sled::open` twice on the same path makes the second one fail on the flock.
    fn create_account_key_store(
        persistence: &PersistenceConfig,
    ) -> Result<AccountKeyStoreKind, ApiError> {
        match persistence {
            PersistenceConfig::InMemory => Ok(AccountKeyStoreKind::InMemory(
                InMemoryAccountKeyStore::default(),
            )),
            PersistenceConfig::Sled { dir } => {
                let account_dir = dir.join("account");
                if let Err(e) = std::fs::create_dir_all(&account_dir) {
                    return Err(ApiError::Internal(format!(
                        "failed to create account key dir {account_dir:?}: {e}"
                    )));
                }
                let store = SledAccountKeyStore::open(&account_dir).map_err(|e| {
                    ApiError::Internal(format!(
                        "failed to open account key store at {account_dir:?}: {e}"
                    ))
                })?;
                Ok(AccountKeyStoreKind::Sled(store))
            }
        }
    }

    /// Helper method that creates a ContentService instance
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

    /// Helper method that creates a ShareService instance
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

    /// Once a lock is released, that content's entry disappears from the registry.
    ///
    /// Without removal, the table keeps growing by the number of revoked content, and since
    /// the gateway runs continuously, memory grows with uptime (pointed out in the PR #56 review).
    #[test]
    fn releasing_a_content_lock_drops_its_registry_entry() {
        let locks = ContentLocks::default();
        assert_eq!(locks.tracked_len(), 0);

        {
            let _guard = locks.lock("content-1");
            assert_eq!(locks.tracked_len(), 1, "entry exists while held");
        }
        assert_eq!(locks.tracked_len(), 0, "removed once released");

        // Touching distinct content one after another does not accumulate entries.
        for i in 0..100 {
            let _guard = locks.lock(&format!("content-{i}"));
        }
        assert_eq!(
            locks.tracked_len(),
            0,
            "sequential revokes alone must not accumulate entries"
        );
    }

    /// Even though the table shrinks, concurrent revokes on the same content stay serialized.
    /// (Confirms that removing entries did not break mutual exclusion.)
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
            "two must never be inside the same content's critical section at once"
        );
        assert_eq!(locks.tracked_len(), 0, "empty once everything finishes");
    }

    /// Different content never wait on each other (confirms the point of splitting per id).
    #[test]
    fn different_contents_do_not_block_each_other() {
        let locks = ContentLocks::default();
        let _held = locks.lock("content-a");
        // content-b can be taken while holding content-a. If this hangs, the whole
        // registry is guarded by a single lock.
        let _other = locks.lock("content-b");
        assert_eq!(locks.tracked_len(), 2);
    }

    /// `combine_rollback_failure` keeps `primary`'s variant and appends the rollback info to
    /// the message as a suffix.
    /// Test that pins the "ApiError::Internal collapse" pointed out in the PR #29 review
    /// (design axis) as a regression.
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

    /// Merely starting up does not create a signing key. Only the user's create_signing_account does.
    #[test]
    #[allow(deprecated)]
    fn fresh_controller_has_no_signing_key() {
        use monas_account::application_service::AccountKeyStore;

        let controller = MonasController::with_state_node_url("http://127.0.0.1:9");
        let stored = controller.account_service.key_store.load().expect("load");
        assert!(
            stored.is_none(),
            "SDK must not create a signing key on its own"
        );
    }

    #[test]
    fn sled_signing_key_survives_reopen() {
        use monas_account::application_service::AccountKeyStore;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("monas-sdk-account-key-{nanos}"));
        let config = MonasConfig::new("http://127.0.0.1:1").with_persistence_dir(&dir);
        let first = MonasController::with_config(config).expect("first open");
        first
            .create_signing_account()
            .data
            .expect("create signing account");
        let first_key = first
            .account_service
            .key_store
            .load()
            .expect("load")
            .expect("signing key")
            .public_key;
        drop(first);

        let config = MonasConfig::new("http://127.0.0.1:1").with_persistence_dir(&dir);
        let second = MonasController::with_config(config).expect("reopen");
        let second_key = second
            .account_service
            .key_store
            .load()
            .expect("load")
            .expect("signing key")
            .public_key;
        assert_eq!(first_key, second_key);
        drop(second);
        let _ = std::fs::remove_dir_all(dir);
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
