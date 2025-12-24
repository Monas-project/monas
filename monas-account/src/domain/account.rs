pub struct Account {
    key_pair: Box<dyn AccountKeyPair>,
}

/// アカウント = 鍵ペアという前提のシンプルなドメインモデル。
/// 永続化や削除（ストレージから鍵を消す）はインフラ層の責務とし、
/// ドメインでは「署名できること」と「鍵素材へのアクセス」に集中する。
impl Account {
    /// 既に生成済みの鍵ペアからアカウントを構築する。
    pub fn new(key_pair: Box<dyn AccountKeyPair>) -> Self {
        Account { key_pair }
    }

    /// メッセージに署名する。
    pub fn sign(&self, msg: &[u8]) -> (Vec<u8>, Option<u8>) {
        self.key_pair.sign(msg)
    }

    /// 公開鍵バイト列へのアクセス。
    pub fn public_key_bytes(&self) -> &[u8] {
        self.key_pair.public_key_bytes()
    }

    /// 秘密鍵バイト列へのアクセス。
    pub fn secret_key_bytes(&self) -> &[u8] {
        self.key_pair.secret_key_bytes()
    }
}

pub trait AccountKeyPair: Send + Sync {
    fn sign(&self, msg: &[u8]) -> (Vec<u8>, Option<u8>);
    fn public_key_bytes(&self) -> &[u8];

    fn secret_key_bytes(&self) -> &[u8];
}

#[cfg(test)]
mod account_tests {
    use super::*;
    use crate::infrastructure::key_pair::KeyAlgorithm::K256;
    use crate::infrastructure::key_pair::KeyPairGenerateFactory;

    #[test]
    fn create_account_and_use_key_material() {
        let account = Account::new(KeyPairGenerateFactory::generate(K256));

        // 公開鍵・秘密鍵のサイズが想定通りであることを確認
        assert_eq!(account.public_key_bytes().len(), 65);
        assert_eq!(account.secret_key_bytes().len(), 32);

        // 署名が正常に生成できることを確認
        let message = b"test message";
        let (sig, _rec_id) = account.sign(message);
        assert!(!sig.is_empty());
    }
}
