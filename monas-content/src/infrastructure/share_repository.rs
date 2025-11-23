use std::collections::HashMap;
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
