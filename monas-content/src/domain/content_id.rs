/// ID that uniquely identifies a Content.
///
/// The actual generation logic and format (hash, CID, etc.) are implemented in a separate
/// library / the infra side; the domain side provides only "the concept of a ContentId" and
/// minimal operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ContentId(String);

impl ContentId {
    pub fn new(value: String) -> Self {
        // Format validation etc. may be added here in the future.
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

/// Port for generating ContentIds.
///
/// Implementations are expected to live in the infra layer, calling a separate library.
pub trait ContentIdGenerator {
    fn generate(&self, raw_content: &[u8]) -> ContentId;

    /// Generates the ciphertext-side identifier (encCid) from the plaintext-derived ContentId
    /// and the ciphertext (encryption output including the IV, etc.).
    ///
    /// Example: `encCid = H(plain_cid || ciphertext)`
    ///
    /// - Intended so that the state node can verify integrity from only `plain_cid` and
    ///   `ciphertext`.
    /// - Assumes the plaintext itself is never passed to the state node.
    fn generate_encrypted(&self, plain_cid: &ContentId, ciphertext: &[u8]) -> ContentId;

    /// Generates the file's key (`series_id`).
    ///
    /// Example: `series_id = H(initial plainCid || 0x00 || creation time)`
    ///
    /// - Decided only once at creation; not changed by edits, re-encryption, or importing the
    ///   latest version. Device-side records, CEKs, and share settings are kept as exactly one
    ///   entry per file under this key.
    /// - Deriving it from the body alone would give separate files created with the same body
    ///   the same key (mixing records, CEKs, and share settings). The creation time is included
    ///   to distinguish them.
    /// - Since it contains a hash of the plaintext, it is not sent to the state node or included
    ///   in share packages. It is still part of the serialized `Content`, so it is stored by the
    ///   content repository (including cloud storage providers when the `filesync` feature is
    ///   enabled).
    fn generate_series(&self, initial_plain_cid: &ContentId, created_at: u64) -> ContentId;
}
