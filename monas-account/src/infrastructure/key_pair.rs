pub mod k256_key_pair;
pub mod p256_key_pair;

use std::fmt::Debug;
use crate::infrastructure::key_pair::k256_key_pair::K256KeyPair;
use crate::infrastructure::key_pair::p256_key_pair::P256KeyPair;

pub enum KeyPair {
    K256KeyPair(K256KeyPair),
    P256KeyPair(P256KeyPair),
    //AesKeyPair(AesKeyPair),
    //RsaKeyPair(RsaKeyPair),
}


#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    K256,
    P256
}

impl KeyPair {
    pub fn generate(key_type: KeyType) -> KeyPair {
        match key_type {
            KeyType::K256 => KeyPair::K256KeyPair(K256KeyPair::generate()),
            KeyType::P256 => KeyPair::P256KeyPair(P256KeyPair::generate())
        }
    }
}
