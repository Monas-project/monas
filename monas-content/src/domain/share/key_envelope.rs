use crate::domain::content_id::ContentId;
use crate::domain::KeyId;

/// 1 人分の CEK ラップ情報。
///
/// - `key_id` ごとに HPKE でラップされた CEK と、その際に生成された `enc` を保持する。
/// - 実際の HPKE アルゴリズムやパラメータは infra 層に委譲し、ここでは「結果としてのバイト列」のみを扱う。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedRecipientKey {
    key_id: KeyId,
    enc: Vec<u8>,
    wrapped_cek: Vec<u8>,
}

impl WrappedRecipientKey {
    pub fn new(key_id: KeyId, enc: Vec<u8>, wrapped_cek: Vec<u8>) -> Self {
        Self {
            key_id,
            enc,
            wrapped_cek,
        }
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub fn enc(&self) -> &[u8] {
        &self.enc
    }

    pub fn wrapped_cek(&self) -> &[u8] {
        &self.wrapped_cek
    }
}

/// CEK をどの方式でラップしたかを表すアルゴリズム。
///
/// - 今フェーズでは HPKE 1 種類のみを想定するが、将来的な拡張に備えて enum として定義しておく。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyWrapAlgorithm {
    /// HPKE による CEK ラップ。
    HpkeV1,
}

/// CEK 配送のための「封筒」。
///
/// - ある時点の `content_id` と `sender_key_id`、および 1 人分の CEK ラップ情報と
///   コンテンツ本体の暗号データを束ねる。
/// - ローカル環境など、単一のパッケージだけで復号を完結させたいユースケースを想定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEnvelope {
    content_id: ContentId,
    key_wrap_algorithm: KeyWrapAlgorithm,
    sender_key_id: KeyId,
    recipient: WrappedRecipientKey,
    ciphertext: Vec<u8>,
}

impl KeyEnvelope {
    pub fn new(
        content_id: ContentId,
        key_wrap_algorithm: KeyWrapAlgorithm,
        sender_key_id: KeyId,
        recipient: WrappedRecipientKey,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            content_id,
            key_wrap_algorithm,
            sender_key_id,
            recipient,
            ciphertext,
        }
    }

    pub fn content_id(&self) -> &ContentId {
        &self.content_id
    }

    pub fn key_wrap_algorithm(&self) -> &KeyWrapAlgorithm {
        &self.key_wrap_algorithm
    }

    pub fn sender_key_id(&self) -> &KeyId {
        &self.sender_key_id
    }

    pub fn recipient(&self) -> &WrappedRecipientKey {
        &self.recipient
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::content_id::ContentId;

    fn cid() -> ContentId {
        ContentId::new("test-content-id".into())
    }

    fn key_id(bytes: &[u8]) -> KeyId {
        KeyId::new(bytes.to_vec())
    }

    #[test]
    fn new_creates_envelope_for_single_recipient() {
        let recipient = WrappedRecipientKey::new(key_id(&[4, 5, 6]), vec![0x01], vec![0x02]);
        let env = KeyEnvelope::new(
            cid(),
            KeyWrapAlgorithm::HpkeV1,
            key_id(&[1, 2, 3]),
            recipient,
            vec![0xAA, 0xBB],
        );

        assert!(matches!(
            env.key_wrap_algorithm(),
            KeyWrapAlgorithm::HpkeV1
        ));
        assert_eq!(env.recipient().key_id().as_bytes(), &[4, 5, 6]);
        assert_eq!(env.ciphertext(), &[0xAA, 0xBB]);
    }
}


