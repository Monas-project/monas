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
}

/// sled 実装。キーは `"sender_pin:{content_id}"`、値は `SenderKeyPin` の JSON。
/// CEK / share / pubkey / last_seen ストアと同じ `sled::Db` を共有できる。
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
    }

    #[test]
    fn in_memory_roundtrip() {
        roundtrip(&InMemorySenderKeyPinStore::default());
    }

    #[test]
    fn sled_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        roundtrip(&SledSenderKeyPinStore::with_db(db));
    }
}
