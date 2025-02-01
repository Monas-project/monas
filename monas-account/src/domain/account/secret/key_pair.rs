pub mod k256_key_pair;
use k256_key_pair as k256;

#[derive(Clone)]
pub enum KeyPair {
    K256KeyPair(k256::K256KeyPair),
    //P256KeyPair(P256KeyPair),
    //AesKeyPair(AesKeyPair),
    //RsaKeyPair(RsaKeyPair),
}

#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    K256,
}

impl KeyPair {
    pub fn generate(
        key_type: KeyType,
    ) -> Self {
        match key_type {
            KeyType::K256 => KeyPair::K256KeyPair(k256::K256KeyPair::generate()),
        }
    }
}
