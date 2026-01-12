use crate::application_service::content_service::{ContentRepository, ContentRepositoryError};
use crate::domain::content::Content;
use crate::domain::content_id::ContentId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// v1 用のインメモリ ContentRepository 実装。
/// プロセス内の HashMap に保存するだけで、永続化は行わない。
#[derive(Clone, Default)]
pub struct InMemoryContentRepository {
    inner: Arc<Mutex<HashMap<String, Content>>>,
}

impl ContentRepository for InMemoryContentRepository {
    fn save(
        &self,
        content_id: &ContentId,
        content: &Content,
    ) -> Result<(), ContentRepositoryError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| ContentRepositoryError::Storage(e.to_string()))?;

        guard.insert(content_id.as_str().to_string(), content.clone());
        Ok(())
    }

    fn find_by_id(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<Content>, ContentRepositoryError> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| ContentRepositoryError::Storage(e.to_string()))?;

        Ok(guard.get(content_id.as_str()).cloned())
    }

    // 将来の実装: 暗号文からContentIdを生成する場合の削除処理
    // 将来的には暗号文からContentIdを生成するため、再暗号化時にContentIdが変わるので、
    // 古いContentIdのContentを削除する処理が必要になる
    // 現状は使用していない
    // 理由: 再暗号化では上書き保存により古いデータが自動的に新しいデータに置き換えられる
    // fn delete(&self, content_id: &ContentId) -> Result<(), ContentRepositoryError> {
    //     let mut guard = self
    //         .inner
    //         .lock()
    //         .map_err(|e| ContentRepositoryError::Storage(e.to_string()))?;
    //
    //     guard.remove(content_id.as_str());
    //     Ok(())
    // }
}
