//! Record of already-accepted signed requests (mutation replay prevention).
//!
//! The in-signature timestamp freshness check (5-minute window) only guarantees that "old
//! signatures cannot be reused forever". Within the window, the same signature passes any
//! number of times.
//!
//! update / delete are not idempotent, so this is not mere duplication but a **state
//! rollback**. If an attacker captures a signed old ciphertext update A and resends it after a
//! legitimate update B has landed, the server commits A as "a new operation whose parent is the
//! latest version at that point". As a result, the old ciphertext becomes the latest version.
//!
//! So we record a value that uniquely identifies each accepted mutation request and reject a
//! second presentation. The identifier is derived from **the signed message and the signer**
//! (`StateNodeService::mutation_request_id`). The message is bound to all of operation /
//! resource / timestamp / body digest, so a match means a resend of exactly the same request,
//! and no new field needs to be added to the wire format.
//!
//! **Do not use a digest of the signature bytes as the identifier.** ECDSA is malleable: for
//! a valid `(r, s)`, `(r, n - s)` also verifies with the same message and key. Hashing the
//! signature gives one approved request two identifiers, letting an attacker slip past this
//! record by transforming a captured signature once.
//!
//! ## Retention
//!
//! Records may be discarded once they exceed the signature freshness window
//! (`MAX_REQUEST_AGE_SECS`), because a signature outside the window is rejected by the
//! freshness check even without this record. So the store does not grow without bound, and GC
//! only needs to "delete expired entries".

use std::collections::HashMap;
use std::sync::Mutex;

/// Signature freshness window. Keep in sync with `MAX_AGE_SECS` in `MonasAccountAdapter`.
/// Keeping records beyond this is pointless (the signature expires first).
pub const CONSUMED_REQUEST_RETENTION_SECS: u64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum ConsumedRequestStoreError {
    #[error("consumed request store error: {0}")]
    Storage(String),
}

/// Record of accepted mutation requests.
pub trait ConsumedRequestStore: Send + Sync {
    /// Record `request_id` as "accepted for the first time now".
    ///
    /// A return value of `false` = already recorded (= replay). The caller must reject without
    /// committing. Recording and checking must be atomic: if both copies of an identical request
    /// arriving concurrently receive `true`, double application cannot be prevented.
    ///
    /// `now` is **this node's current time** (Unix seconds). Used to purge expired records.
    ///
    /// Do not pass the caller-declared in-signature timestamp. By first submitting a valid
    /// request with a future-leaning timestamp within the allowed skew, one could force early
    /// purging of records still inside the freshness window, and then re-present an old signature.
    fn record_if_absent(
        &self,
        request_id: &[u8],
        now: u64,
    ) -> Result<bool, ConsumedRequestStoreError>;
}

/// In-process `HashMap` implementation.
///
/// Records may be volatile because the retention period equals the signature freshness
/// window. Records inside the window are lost when the node restarts, but the replays that
/// could pass then are limited to "the same signature arriving within 5 minutes across a
/// restart". That is the only difference from persisting them, and we judged it a better
/// trade-off than adding fsync cost to every mutation.
///
/// Note that these records are independent per node. Sending the same signature to multiple
/// replicas gets it accepted once on each. CRDTs tolerate duplicate application of the same
/// operation, but this does not guarantee "exactly once as seen from any node".
#[derive(Default)]
pub struct InMemoryConsumedRequestStore {
    /// request id -> acceptance time (Unix seconds)
    inner: Mutex<HashMap<Vec<u8>, u64>>,
}

impl ConsumedRequestStore for InMemoryConsumedRequestStore {
    fn record_if_absent(
        &self,
        request_id: &[u8],
        now: u64,
    ) -> Result<bool, ConsumedRequestStoreError> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Purge expired entries. Since this runs on every insert, the store size is capped at
        // "the number of mutations that arrived within the freshness window".
        guard.retain(|_, accepted_at| {
            now.saturating_sub(*accepted_at) < CONSUMED_REQUEST_RETENTION_SECS
        });

        if guard.contains_key(request_id) {
            return Ok(false);
        }
        guard.insert(request_id.to_vec(), now);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_presentation_is_accepted_and_the_replay_is_not() {
        let store = InMemoryConsumedRequestStore::default();
        let now = 1_000_000;

        assert!(store.record_if_absent(b"sig-a", now).unwrap());
        assert!(!store.record_if_absent(b"sig-a", now).unwrap());
        // Different signatures are independent
        assert!(store.record_if_absent(b"sig-b", now).unwrap());
    }

    /// GC runs on server time, so a caller shifting timestamps back and forth cannot drop
    /// records early. Here we verify that "records do not disappear unless time advances",
    /// including presentations that move time backwards.
    #[test]
    fn out_of_order_presentations_cannot_evict_a_live_record() {
        let store = InMemoryConsumedRequestStore::default();
        let now = 1_000_000;

        assert!(store.record_if_absent(b"victim", now).unwrap());

        // Even if another request arrives at a time that looks "future-leaning", the caller
        // passes server time so the window does not move = victim survives.
        assert!(store.record_if_absent(b"other", now).unwrap());
        assert!(
            !store.record_if_absent(b"victim", now).unwrap(),
            "a live record must not be evictable by other traffic"
        );

        // A presentation that moves time backwards does not revive it either
        assert!(
            !store.record_if_absent(b"victim", now - 100).unwrap(),
            "an earlier presentation must not resurrect the record"
        );
    }

    /// Records past the freshness window are discarded. This is safe because such a signature
    /// is rejected by the freshness check regardless of whether a record exists.
    #[test]
    fn records_are_dropped_once_the_signature_itself_would_expire() {
        let store = InMemoryConsumedRequestStore::default();
        let now = 1_000_000;

        assert!(store.record_if_absent(b"sig", now).unwrap());
        assert!(!store.record_if_absent(b"sig", now + 1).unwrap());
        assert!(!store
            .record_if_absent(b"sig", now + CONSUMED_REQUEST_RETENTION_SECS - 1)
            .unwrap());

        // Outside the window. The record is purged and the store does not grow
        assert!(store
            .record_if_absent(b"sig", now + CONSUMED_REQUEST_RETENTION_SECS)
            .unwrap());
        assert_eq!(
            store.inner.lock().unwrap().len(),
            1,
            "expired records must be pruned rather than accumulate"
        );
    }
}
