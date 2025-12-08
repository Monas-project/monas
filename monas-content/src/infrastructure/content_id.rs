use crate::domain::content_id::{ContentId, ContentIdGenerator};
use sha2::{Digest, Sha256};

/// シンプルな ContentIdGenerator 実装。
/// v1 では raw_content の SHA-256 ハッシュをそのまま ContentId にする。
/// todo: crslのcid生成を使用する
pub struct Sha256ContentIdGenerator;

impl ContentIdGenerator for Sha256ContentIdGenerator {
    fn generate(&self, raw_content: &[u8]) -> ContentId {
        let mut hasher = Sha256::new();
        hasher.update(raw_content);
        let hash = hasher.finalize();
        let hex = hex::encode(hash);
        ContentId::new(hex)
    }
}
