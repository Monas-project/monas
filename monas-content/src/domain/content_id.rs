/// Content を一意に識別するための ID。
///
/// 実際の生成ロジックやフォーマット（ハッシュ・CID 等）は別ライブラリ/infra 側で実装し、
/// ドメイン側では「ContentId という概念」と最小限の操作だけを提供する。
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ContentId(String);

impl ContentId {
    pub fn new(value: String) -> Self {
        // 将来的にフォーマット検証などをここに追加してもよい。
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

/// ContentId を生成するためのポート。
///
/// 実装は別ライブラリを呼び出す infra 層に置く想定。
pub trait ContentIdGenerator {
    fn generate(&self, raw_content: &[u8]) -> ContentId;

    /// 平文由来の ContentId と暗号文（IV等を含む暗号化結果）から、暗号文側の識別子（encCid）を生成する。
    ///
    /// 例: `encCid = H(plain_cid || ciphertext)`
    ///
    /// - state-node 側で `plain_cid` と `ciphertext` だけから整合性検証ができることを意図する。
    /// - 平文そのものを state-node に渡さない前提。
    fn generate_encrypted(&self, plain_cid: &ContentId, ciphertext: &[u8]) -> ContentId;
}
