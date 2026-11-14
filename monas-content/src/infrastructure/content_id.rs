use crate::domain::content_id::{ContentId, ContentIdGenerator};
use sha2::{Digest, Sha256};

/// Simple ContentIdGenerator implementation.
/// In v1, the SHA-256 hash of raw_content is used directly as the ContentId.
/// todo: use crsl's CID generation
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
        // - Insert 0x00 to make the concatenation boundary explicit (plainCid is a UTF-8 string,
        //   ciphertext is arbitrary bytes)
        let mut hasher = Sha256::new();
        hasher.update(plain_cid.as_str().as_bytes());
        hasher.update([0u8]);
        hasher.update(ciphertext);
        let hash = hasher.finalize();
        let hex = hex::encode(hash);
        ContentId::new(hex)
    }

    fn generate_series(&self, initial_plain_cid: &ContentId, created_at: u64) -> ContentId {
        // seriesId = sha256(plainCid || 0x00 || created_at(u64 big-endian))
        let mut hasher = Sha256::new();
        hasher.update(initial_plain_cid.as_str().as_bytes());
        hasher.update([0u8]);
        hasher.update(created_at.to_be_bytes());
        ContentId::new(hex::encode(hasher.finalize()))
    }
}
