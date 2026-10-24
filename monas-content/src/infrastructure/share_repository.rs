use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::application_service::share_service::{ShareRepository, ShareRepositoryError};
use crate::domain::content_id::ContentId;
use crate::domain::share::Share;

/// シンプルなインメモリ実装の ShareRepository。
///
/// - key: `content_id.as_str()`
/// - value: `Share`
#[derive(Clone, Default)]
pub struct InMemoryShareRepository {
    inner: Arc<Mutex<HashMap<String, Share>>>,
}

impl ShareRepository for InMemoryShareRepository {
    fn load(&self, content_id: &ContentId) -> Result<Option<Share>, ShareRepositoryError> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;

        Ok(guard.get(content_id.as_str()).cloned())
    }

    fn save(&self, share: &Share) -> Result<(), ShareRepositoryError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;

        guard.insert(share.content_id().as_str().to_string(), share.clone());
        Ok(())
    }
}

/// sled を用いた ShareRepository 実装。
///
/// - キー: `"share-series:{series_id}"`（UTF-8 文字列）
/// - 値: `Share` を JSON でシリアライズしたバイト列
/// - 以前の形式のキー `"share:{plainCid}"` は `load_legacy` で読むだけで、書かない。
///
/// 以前の形式と別のプレフィックスにしているのは、系列ID が作成時の plainCid と
/// 同じ値だから。同じ `"share:"` だと、作成時の plainCid のキーに残っている古い
/// 共有設定(編集前のもの)を、系列ID の最新の設定と区別できない。
///
/// NOTE:
/// - CEK ストアなど、他の sled ベースストアと**同じ DB ファイルを共有してもよい**ことを想定し、
///   プレフィックスによりキー空間を分離している。
#[derive(Clone)]
pub struct SledShareRepository {
    db: sled::Db,
}

impl SledShareRepository {
    /// 指定されたパスに sled DB を開く。
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ShareRepositoryError> {
        let db = sled::open(path).map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;
        Ok(Self { db })
    }

    /// 既存の `sled::Db` ハンドルを共有してインスタンスを構築する。
    ///
    /// CEK ストアと同じ DB ファイルを共有したい場合に使う
    /// (`SledContentEncryptionKeyStore::with_db` と同じ `sled::Db` を渡す)。
    pub fn with_db(db: sled::Db) -> Self {
        Self { db }
    }
}

impl SledShareRepository {
    fn load_key(&self, sled_key: String) -> Result<Option<Share>, ShareRepositoryError> {
        let opt = self
            .db
            .get(sled_key)
            .map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;

        if let Some(ivec) = opt {
            let share: Share = serde_json::from_slice(&ivec)
                .map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;
            Ok(Some(share))
        } else {
            Ok(None)
        }
    }
}

impl ShareRepository for SledShareRepository {
    fn load(&self, series_id: &ContentId) -> Result<Option<Share>, ShareRepositoryError> {
        self.load_key(format!("share-series:{}", series_id.as_str()))
    }

    fn save(&self, share: &Share) -> Result<(), ShareRepositoryError> {
        let key = format!("share-series:{}", share.content_id().as_str());
        let value =
            serde_json::to_vec(share).map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;

        self.db
            .insert(key, value)
            .map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| ShareRepositoryError::Storage(e.to_string()))?;

        Ok(())
    }

    fn load_legacy(
        &self,
        plain_content_id: &ContentId,
    ) -> Result<Option<Share>, ShareRepositoryError> {
        self.load_key(format!("share:{}", plain_content_id.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share_with(content_id: &str, key: u8) -> Share {
        let mut share = Share::new(ContentId::new(content_id.into()));
        share
            .grant_read(crate::domain::share::KeyId::new(vec![key]))
            .unwrap();
        share
    }

    /// 以前の形式(`share:{plainCid}`)は `load` では読まず、`load_legacy` でだけ読む。
    /// 系列ID は作成時の plainCid と同じ値なので、`load` が `share:` を読むと、
    /// 作成時の plainCid に残った編集前の設定を最新として返してしまう。
    #[test]
    fn legacy_plain_cid_keys_are_read_only_through_load_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let repo = SledShareRepository::open(dir.path()).unwrap();
        let legacy = share_with("v1", 1);
        repo.db
            .insert("share:v1", serde_json::to_vec(&legacy).unwrap())
            .unwrap();

        let id = ContentId::new("v1".into());
        assert!(repo.load(&id).unwrap().is_none());
        let read = repo.load_legacy(&id).unwrap().expect("legacy share");
        assert_eq!(read.recipients().len(), 1);

        let current = share_with("v1", 2);
        repo.save(&current).unwrap();
        let loaded = repo.load(&id).unwrap().expect("series share");
        assert!(loaded
            .recipients()
            .contains_key(&crate::domain::share::KeyId::new(vec![2])));
        // 書き込みは新しいキーにだけ行き、以前の形式のキーは変わらない。
        let still_legacy = repo.load_legacy(&id).unwrap().unwrap();
        assert!(still_legacy
            .recipients()
            .contains_key(&crate::domain::share::KeyId::new(vec![1])));
    }
}
