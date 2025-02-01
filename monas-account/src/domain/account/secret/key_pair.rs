pub mod k256_key_pair;
pub mod p256_key_pair;
use k256_key_pair as k256;
use p256_key_pair as p256;

#[derive(Clone)]
pub enum KeyPair {
    K256KeyPair(k256::K256KeyPair),
    P256KeyPair(p256::P256KeyPair),
    //AesKeyPair(AesKeyPair),
    //RsaKeyPair(RsaKeyPair),
}

#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    K256,
    P256
}

impl KeyPair {
    pub fn generate(
        key_type: KeyType,
    ) -> Self {
        match key_type {
            KeyType::K256 => KeyPair::K256KeyPair(k256::K256KeyPair::generate()),
            KeyType::P256 => KeyPair::P256KeyPair(p256::P256KeyPair::generate()),
        }
    }
}
