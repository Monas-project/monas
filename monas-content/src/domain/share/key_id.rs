/// 受信者や鍵を識別するための KeyId（kid）。
///
/// - 実体は公開鍵バイト列のハッシュ先頭 N バイトなどから生成される想定。
/// - 生成ロジック自体は infra 側に委譲し、ドメインでは「不透明な ID」としてのみ扱う。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(Vec<u8>);

impl KeyId {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}


