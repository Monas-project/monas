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

    fn generate_encrypted(&self, plain_cid: &ContentId, ciphertext: &[u8]) -> ContentId {
        // encCid = sha256(plainCid || 0x00 || ciphertext)
        // - 0x00 を挟んで連結境界を明確化（plainCidはUTF-8文字列、ciphertextは任意バイト列）
        let mut hasher = Sha256::new();
        hasher.update(plain_cid.as_str().as_bytes());
        hasher.update([0u8]);
        hasher.update(ciphertext);
        let hash = hasher.finalize();
        let hex = hex::encode(hash);
        ContentId::new(hex)
    }
}
