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
/// - キー: `"share:{content_id.as_str()}"`（UTF-8 文字列）
/// - 値: `Share` を JSON でシリアライズしたバイト列
///
/// NOTE:
/// - CEK ストアなど、他の sled ベースストアと**同じ DB ファイルを共有してもよい**ことを想定し、
///   `"share:"` プレフィックスによりキー空間を分離している。
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
}

impl ShareRepository for SledShareRepository {
    fn load(&self, content_id: &ContentId) -> Result<Option<Share>, ShareRepositoryError> {
        let sled_key = format!("share:{}", content_id.as_str());
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

    fn save(&self, share: &Share) -> Result<(), ShareRepositoryError> {
        let key = format!("share:{}", share.content_id().as_str());
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
}
