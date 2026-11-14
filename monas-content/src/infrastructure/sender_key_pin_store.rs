//! Implementations of [`SenderKeyPinStore`].
//!
//! The port definition (the trait and [`SenderKeyPin`]) lives in
//! `application_service::share_service::sender_key_pin_port`.
//! This module contains only the per-backend implementations; upper layers such as the SDK
//! refer to the trait.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::application_service::share_service::sender_key_pin_port::{
    SenderKeyPin, SenderKeyPinStore, SenderKeyPinStoreError,
};

/// In-process `HashMap` implementation. For tests/development (volatile across restarts = back to
/// TOFU every time).
#[derive(Clone, Default)]
pub struct InMemorySenderKeyPinStore {
    inner: Arc<Mutex<HashMap<String, SenderKeyPin>>>,
}

impl SenderKeyPinStore for InMemorySenderKeyPinStore {
    fn load(&self, content_id: &str) -> Result<Option<SenderKeyPin>, SenderKeyPinStoreError> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| SenderKeyPinStoreError::Storage(e.to_string()))?;
        Ok(guard.get(content_id).cloned())
    }

    fn save(&self, content_id: &str, pin: &SenderKeyPin) -> Result<(), SenderKeyPinStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| SenderKeyPinStoreError::Storage(e.to_string()))?;
        guard.insert(content_id.to_string(), pin.clone());
        Ok(())
    }

    fn compare_and_save(
        &self,
        content_id: &str,
        expected: Option<&SenderKeyPin>,
        pin: &SenderKeyPin,
    ) -> Result<bool, SenderKeyPinStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| SenderKeyPinStoreError::Storage(e.to_string()))?;
        if guard.get(content_id) != expected {
            return Ok(false);
        }
        guard.insert(content_id.to_string(), pin.clone());
        Ok(true)
    }
}

/// sled implementation. The key is `"sender_pin:{content_id}"`, the value is the JSON of the
/// `SenderKeyPin`. Can share the same `sled::Db` as the CEK / share / pubkey stores.
pub struct SledSenderKeyPinStore {
    db: sled::Db,
}

impl SledSenderKeyPinStore {
    pub fn with_db(db: sled::Db) -> Self {
        Self { db }
    }

    fn sled_key(content_id: &str) -> String {
        format!("sender_pin:{content_id}")
    }
}

impl SenderKeyPinStore for SledSenderKeyPinStore {
    fn load(&self, content_id: &str) -> Result<Option<SenderKeyPin>, SenderKeyPinStoreError> {
        let opt = self
            .db
            .get(Self::sled_key(content_id))
            .map_err(|e| SenderKeyPinStoreError::Storage(e.to_string()))?;
        opt.map(|ivec| {
            serde_json::from_slice(&ivec)
                .map_err(|e| SenderKeyPinStoreError::Storage(e.to_string()))
        })
        .transpose()
    }

    fn save(&self, content_id: &str, pin: &SenderKeyPin) -> Result<(), SenderKeyPinStoreError> {
        let bytes =
            serde_json::to_vec(pin).map_err(|e| SenderKeyPinStoreError::Storage(e.to_string()))?;
        self.db
            .insert(Self::sled_key(content_id), bytes)
            .map_err(|e| SenderKeyPinStoreError::Storage(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| SenderKeyPinStoreError::Storage(e.to_string()))?;
        Ok(())
    }

    fn compare_and_save(
        &self,
        content_id: &str,
        expected: Option<&SenderKeyPin>,
        pin: &SenderKeyPin,
    ) -> Result<bool, SenderKeyPinStoreError> {
        // Compare in the stored form (JSON bytes). `SenderKeyPin`'s field order is fixed and
        // serde_json emits fields in declaration order, so equal values yield equal bytes.
        // `cek: None` omits the field entirely via `skip_serializing_if`, but that is also
        // unique per value, so the comparison still holds (it also matches legacy records).
        let expected_bytes = expected
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|e| SenderKeyPinStoreError::Storage(e.to_string()))?;
        let new_bytes =
            serde_json::to_vec(pin).map_err(|e| SenderKeyPinStoreError::Storage(e.to_string()))?;

        let swapped = self
            .db
            .compare_and_swap(
                Self::sled_key(content_id),
                expected_bytes.as_deref(),
                Some(new_bytes),
            )
            .map_err(|e| SenderKeyPinStoreError::Storage(e.to_string()))?
            .is_ok();
        if swapped {
            self.db
                .flush()
                .map_err(|e| SenderKeyPinStoreError::Storage(e.to_string()))?;
        }
        Ok(swapped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(store: &dyn SenderKeyPinStore) {
        assert!(store.load("content-a").unwrap().is_none());

        let pin_v0 = SenderKeyPin {
            sender_public_key: vec![0x04, 1, 2, 3],
            key_epoch: 0,
            cek: None,
        };
        store.save("content-a", &pin_v0).unwrap();
        assert_eq!(store.load("content-a").unwrap(), Some(pin_v0.clone()));

        // Epoch update after rotation
        let pin_v1 = SenderKeyPin {
            key_epoch: 1,
            ..pin_v0
        };
        store.save("content-a", &pin_v1).unwrap();
        assert_eq!(store.load("content-a").unwrap(), Some(pin_v1));

        assert!(store.load("content-b").unwrap().is_none());

        // compare-and-advance: advances if the expected value matches the current value
        let pin_v2 = SenderKeyPin {
            sender_public_key: vec![0x04, 1, 2, 3],
            key_epoch: 2,
            cek: None,
        };
        let current = store.load("content-a").unwrap();
        assert!(store
            .compare_and_save("content-a", current.as_ref(), &pin_v2)
            .unwrap());
        assert_eq!(store.load("content-a").unwrap(), Some(pin_v2.clone()));

        // If the expected value is stale (a concurrent operation advanced first), do not roll back
        let stale = SenderKeyPin {
            sender_public_key: vec![0x04, 1, 2, 3],
            key_epoch: 1,
            cek: None,
        };
        assert!(!store
            .compare_and_save("content-a", Some(&stale), &stale)
            .unwrap());
        assert_eq!(store.load("content-a").unwrap(), Some(pin_v2));

        // First write expecting no record (None) / fails if a record already exists
        let first = SenderKeyPin {
            sender_public_key: vec![0x04, 9, 9, 9],
            key_epoch: 0,
            cek: None,
        };
        assert!(store.compare_and_save("content-c", None, &first).unwrap());
        assert!(!store.compare_and_save("content-c", None, &first).unwrap());
    }

    #[test]
    fn in_memory_roundtrip() {
        roundtrip(&InMemorySenderKeyPinStore::default());
    }

    /// Rollback prevention under concurrency: if epochs N and N+1 start having observed the same
    /// pin, and N completes after N+1 has advanced first, the pin does not move backwards.
    /// Since the SDK "publishes the CEK only when the CAS succeeds", this CAS returning false is
    /// the last line of defense against a CEK rollback.
    fn concurrent_epochs_do_not_roll_back(store: &dyn SenderKeyPinStore) {
        let key = vec![0x04, 1, 2, 3];
        let epoch0 = SenderKeyPin {
            sender_public_key: key.clone(),
            key_epoch: 0,
            cek: None,
        };
        store.save("c", &epoch0).unwrap();

        // Two operations start having observed the same pin (epoch 0)
        let observed = store.load("c").unwrap();

        let epoch2 = SenderKeyPin {
            sender_public_key: key.clone(),
            key_epoch: 2,
            cek: None,
        };
        let epoch1 = SenderKeyPin {
            sender_public_key: key,
            key_epoch: 1,
            cek: None,
        };

        // The newer epoch advances first
        assert!(store
            .compare_and_save("c", observed.as_ref(), &epoch2)
            .unwrap());

        // The older epoch that completes later fails the CAS and cannot roll back the pin
        assert!(!store
            .compare_and_save("c", observed.as_ref(), &epoch1)
            .unwrap());
        assert_eq!(store.load("c").unwrap(), Some(epoch2));
    }

    /// Since the triple is a single record, a state where the epoch and CEK disagree cannot be
    /// produced via CAS. In the old design (pin and CEK in separate stores / separate commits),
    /// an epoch-N operation could write back only the CEK and produce `pin = N+1, CEK = N`.
    fn epoch_and_cek_advance_together(store: &dyn SenderKeyPinStore) {
        let key = vec![0x04, 1, 2, 3];
        let cek_of = |epoch: u64| Some(vec![epoch as u8; 32]);

        let epoch0 = SenderKeyPin {
            sender_public_key: key.clone(),
            key_epoch: 0,
            cek: cek_of(0),
        };
        store.save("c", &epoch0).unwrap();

        // The epoch 1 and epoch 2 operations start having observed the same pin (epoch 0)
        let observed = store.load("c").unwrap();

        let epoch2 = SenderKeyPin {
            sender_public_key: key.clone(),
            key_epoch: 2,
            cek: cek_of(2),
        };
        let epoch1 = SenderKeyPin {
            sender_public_key: key,
            key_epoch: 1,
            cek: cek_of(1),
        };

        assert!(store
            .compare_and_save("c", observed.as_ref(), &epoch2)
            .unwrap());
        // The older epoch that completes later loses the CAS. Since the CEK is carried along,
        // a state of "new epoch but old CEK" cannot arise.
        assert!(!store
            .compare_and_save("c", observed.as_ref(), &epoch1)
            .unwrap());

        let current = store.load("c").unwrap().expect("record should exist");
        assert_eq!(current.key_epoch, 2);
        assert_eq!(
            current.cek,
            cek_of(2),
            "CEK advances together with the epoch"
        );
    }

    #[test]
    fn in_memory_epoch_and_cek_advance_together() {
        epoch_and_cek_advance_together(&InMemorySenderKeyPinStore::default());
    }

    #[test]
    fn sled_epoch_and_cek_advance_together() {
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        epoch_and_cek_advance_together(&SledSenderKeyPinStore::with_db(db));
    }

    /// Records written before this fix (without the CEK field) must be readable.
    /// Otherwise, every existing recipient would have to start over from TOFU.
    #[test]
    fn legacy_record_without_cek_deserializes() {
        let legacy = br#"{"sender_public_key":[4,1,2,3],"key_epoch":7}"#;
        let pin: SenderKeyPin = serde_json::from_slice(legacy).unwrap();
        assert_eq!(pin.key_epoch, 7);
        assert_eq!(pin.cek, None);
    }

    /// The CEK must not appear in `Debug` output. Prevents key material from leaking via logs or
    /// panic messages.
    #[test]
    fn debug_output_redacts_the_cek() {
        let pin = SenderKeyPin {
            sender_public_key: vec![0x04, 1, 2, 3],
            key_epoch: 1,
            cek: Some(vec![0xAB; 32]),
        };
        let rendered = format!("{pin:?}");
        assert!(rendered.contains("<redacted>"), "rendered={rendered}");
        assert!(!rendered.contains("171"), "CEK bytes leaked: {rendered}");
    }

    #[test]
    fn in_memory_concurrent_epochs_do_not_roll_back() {
        concurrent_epochs_do_not_roll_back(&InMemorySenderKeyPinStore::default());
    }

    #[test]
    fn sled_concurrent_epochs_do_not_roll_back() {
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        concurrent_epochs_do_not_roll_back(&SledSenderKeyPinStore::with_db(db));
    }

    #[test]
    fn sled_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        roundtrip(&SledSenderKeyPinStore::with_db(db));
    }
}
