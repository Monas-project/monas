//! 受信者側の送信者公開鍵ピン(TOFU)ストア。
//!
//! share の KeyEnvelope は HPKE Auth モードでラップされており、受信者は
//! 「期待する送信者の公開鍵」で unwrap する(成功 = その鍵の持ち主が作った証明)。
//! このストアは content ごとに、最初に unwrap に成功した送信者公開鍵を
//! ピン留めし(TOFU)、以後の envelope はピン済みの鍵でのみ検証する。
//!
//! 併せて CEK の鍵世代(key_epoch)も記録し、記録済み世代より古い envelope を
//! 拒否する基準にする(rotation 後に旧 envelope を再送して CEK を巻き戻す
//! replay 攻撃の防止)。
//!
//! キーは受信者から見た(ローカルの) content id。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum SenderKeyPinStoreError {
    #[error("sender key pin store error: {0}")]
    Storage(String),
}

/// ピン留めされた送信者公開鍵と、最後に受理した鍵世代。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SenderKeyPin {
    /// 送信者の公開鍵バイト列(P-256 uncompressed form)。
    pub sender_public_key: Vec<u8>,
    /// 最後に unwrap に成功した envelope の key_epoch。
    pub key_epoch: u64,
}

/// `content_id -> (送信者公開鍵, 最終受理 key_epoch)` の永続化ポート。
pub trait SenderKeyPinStore: Send + Sync {
    fn load(&self, content_id: &str) -> Result<Option<SenderKeyPin>, SenderKeyPinStoreError>;
    fn save(&self, content_id: &str, pin: &SenderKeyPin) -> Result<(), SenderKeyPinStoreError>;

    /// compare-and-advance: 現在値が `expected` と一致する場合のみ `pin` へ進める。
    /// 戻り値は「進めたかどうか」。
    ///
    /// envelope の並行処理(rotation 前後の epoch N / N+1 が同時に走る等)で、
    /// 「load した時点の pin」を前提に無条件 save すると、後から完了した古い
    /// epoch が新しい pin と CEK を巻き戻せる。ピンの前進をこの CAS に限定し、
    /// **成功したときだけ CEK を公開する**ことで、その巻き戻しを防ぐ。
    fn compare_and_save(
        &self,
        content_id: &str,
        expected: Option<&SenderKeyPin>,
        pin: &SenderKeyPin,
    ) -> Result<bool, SenderKeyPinStoreError>;
}

/// プロセス内 `HashMap` 実装。テスト・開発用（再起動で揮発 = 毎回 TOFU に戻る）。
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

/// sled 実装。キーは `"sender_pin:{content_id}"`、値は `SenderKeyPin` の JSON。
/// CEK / share / pubkey ストアと同じ `sled::Db` を共有できる。
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
        // 比較は保存形式(JSON バイト列)で行う。`SenderKeyPin` のフィールド順は
        // 固定で serde_json も宣言順に出すため、同じ値は同じバイト列になる。
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
        };
        store.save("content-a", &pin_v0).unwrap();
        assert_eq!(store.load("content-a").unwrap(), Some(pin_v0.clone()));

        // rotation 後の epoch 更新
        let pin_v1 = SenderKeyPin {
            key_epoch: 1,
            ..pin_v0
        };
        store.save("content-a", &pin_v1).unwrap();
        assert_eq!(store.load("content-a").unwrap(), Some(pin_v1));

        assert!(store.load("content-b").unwrap().is_none());

        // compare-and-advance: 期待値が現在値と一致すれば進む
        let pin_v2 = SenderKeyPin {
            sender_public_key: vec![0x04, 1, 2, 3],
            key_epoch: 2,
        };
        let current = store.load("content-a").unwrap();
        assert!(store
            .compare_and_save("content-a", current.as_ref(), &pin_v2)
            .unwrap());
        assert_eq!(store.load("content-a").unwrap(), Some(pin_v2.clone()));

        // 期待値が古ければ(並行処理が先に進めていれば)巻き戻さない
        let stale = SenderKeyPin {
            sender_public_key: vec![0x04, 1, 2, 3],
            key_epoch: 1,
        };
        assert!(!store
            .compare_and_save("content-a", Some(&stale), &stale)
            .unwrap());
        assert_eq!(store.load("content-a").unwrap(), Some(pin_v2));

        // 未記録(None)期待の初回書き込み / 既に記録がある場合は失敗
        let first = SenderKeyPin {
            sender_public_key: vec![0x04, 9, 9, 9],
            key_epoch: 0,
        };
        assert!(store.compare_and_save("content-c", None, &first).unwrap());
        assert!(!store.compare_and_save("content-c", None, &first).unwrap());
    }

    #[test]
    fn in_memory_roundtrip() {
        roundtrip(&InMemorySenderKeyPinStore::default());
    }

    /// 並行処理の巻き戻し防止: epoch N と N+1 が同じ pin を観測して開始し、
    /// N+1 が先に前進した後に N が完了しても、pin は後退しない。
    /// SDK 側は「CAS が成功したときだけ CEK を公開する」ため、この CAS が
    /// false を返すことが CEK 巻き戻しを止める最後の砦になる。
    fn concurrent_epochs_do_not_roll_back(store: &dyn SenderKeyPinStore) {
        let key = vec![0x04, 1, 2, 3];
        let epoch0 = SenderKeyPin {
            sender_public_key: key.clone(),
            key_epoch: 0,
        };
        store.save("c", &epoch0).unwrap();

        // 2 つの処理が同じ pin(epoch 0)を観測して開始する
        let observed = store.load("c").unwrap();

        let epoch2 = SenderKeyPin {
            sender_public_key: key.clone(),
            key_epoch: 2,
        };
        let epoch1 = SenderKeyPin {
            sender_public_key: key,
            key_epoch: 1,
        };

        // 新しい世代が先に前進する
        assert!(store
            .compare_and_save("c", observed.as_ref(), &epoch2)
            .unwrap());

        // 後から完了した古い世代は CAS に失敗し、pin を巻き戻せない
        assert!(!store
            .compare_and_save("c", observed.as_ref(), &epoch1)
            .unwrap());
        assert_eq!(store.load("c").unwrap(), Some(epoch2));
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
