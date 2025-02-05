pub mod k256_key_pair;
pub mod p256_key_pair;

use std::fmt::Debug;
use crate::domain::account::secret::key_pair::k256_key_pair::K256KeyPair;
use crate::domain::account::secret::key_pair::p256_key_pair::P256KeyPair;

impl KeyPair {
    pub fn generate(&self) -> Self {
        match self {
            KeyPair::K256KeyPair(_) => KeyPair::K256KeyPair(K256KeyPair::generate()),
            KeyPair::P256KeyPair(_) => KeyPair::P256KeyPair(P256KeyPair::generate())
        }
    }
}

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

