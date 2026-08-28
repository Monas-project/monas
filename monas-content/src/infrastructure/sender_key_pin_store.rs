//! [`SenderKeyPinStore`] の実装。
//!
//! ポート定義(トレイトと [`SenderKeyPin`])は
//! `application_service::share_service::sender_key_pin_port` にある。
//! ここにあるのは保存先ごとの実装だけで、SDK など上位のレイヤーは
//! トレイトの方を参照する。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::application_service::share_service::sender_key_pin_port::{
    SenderKeyPin, SenderKeyPinStore, SenderKeyPinStoreError,
};

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
        // `cek: None` は `skip_serializing_if` で欄ごと省かれるが、これも
        // 値ごとに一意なので比較は成立する(旧形式レコードとも一致する)。
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
            cek: None,
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
            cek: None,
        };
        assert!(!store
            .compare_and_save("content-a", Some(&stale), &stale)
            .unwrap());
        assert_eq!(store.load("content-a").unwrap(), Some(pin_v2));

        // 未記録(None)期待の初回書き込み / 既に記録がある場合は失敗
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

    /// 並行処理の巻き戻し防止: epoch N と N+1 が同じ pin を観測して開始し、
    /// N+1 が先に前進した後に N が完了しても、pin は後退しない。
    /// SDK 側は「CAS が成功したときだけ CEK を公開する」ため、この CAS が
    /// false を返すことが CEK 巻き戻しを止める最後の砦になる。
    fn concurrent_epochs_do_not_roll_back(store: &dyn SenderKeyPinStore) {
        let key = vec![0x04, 1, 2, 3];
        let epoch0 = SenderKeyPin {
            sender_public_key: key.clone(),
            key_epoch: 0,
            cek: None,
        };
        store.save("c", &epoch0).unwrap();

        // 2 つの処理が同じ pin(epoch 0)を観測して開始する
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

    /// 3つ組が1レコードなので、世代と CEK が食い違った状態を CAS 経由では
    /// 作れない。旧設計(pin と CEK が別ストア・別 commit)では、epoch N の
    /// 処理が CEK だけを書き戻して `pin = N+1, CEK = N` を作れた。
    fn epoch_and_cek_advance_together(store: &dyn SenderKeyPinStore) {
        let key = vec![0x04, 1, 2, 3];
        let cek_of = |epoch: u64| Some(vec![epoch as u8; 32]);

        let epoch0 = SenderKeyPin {
            sender_public_key: key.clone(),
            key_epoch: 0,
            cek: cek_of(0),
        };
        store.save("c", &epoch0).unwrap();

        // epoch 1 と epoch 2 の処理が、同じ pin(epoch 0)を観測して開始する
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
        // 後から完了した古い世代は CAS に負ける。CEK も一緒に載っているので、
        // 「世代だけ新しく CEK は古い」状態は生じ得ない。
        assert!(!store
            .compare_and_save("c", observed.as_ref(), &epoch1)
            .unwrap());

        let current = store.load("c").unwrap().expect("record should exist");
        assert_eq!(current.key_epoch, 2);
        assert_eq!(current.cek, cek_of(2), "CEK は世代と一緒に進む");
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

    /// この修正より前に書かれたレコード(CEK 欄なし)を読めること。
    /// 読めないと、既存の受信者が全員 TOFU からやり直しになる。
    #[test]
    fn legacy_record_without_cek_deserializes() {
        let legacy = br#"{"sender_public_key":[4,1,2,3],"key_epoch":7}"#;
        let pin: SenderKeyPin = serde_json::from_slice(legacy).unwrap();
        assert_eq!(pin.key_epoch, 7);
        assert_eq!(pin.cek, None);
    }

    /// CEK が `Debug` 出力に出ないこと。ログや panic メッセージ経由で
    /// 鍵素材が漏れるのを防ぐ。
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
