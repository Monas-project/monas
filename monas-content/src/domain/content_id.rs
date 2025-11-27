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
}
