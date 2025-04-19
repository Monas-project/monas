pub mod aes_key_pair;
pub mod p256_key_pair;

use aes_key_pair::AesKeyPair;
use p256_key_pair::P256KeyPair;
use std::fmt::Debug;

/// 暗号化キーペアのインターフェース
pub trait KeyPair: Debug {
    fn public_key(&self) -> String;

    fn encrypt(&self, data: &[u8]) -> Vec<u8>;

    fn decrypt(&self, data: &[u8]) -> Vec<u8>;

    fn clone_box(&self) -> Box<dyn KeyPair>;
}

/// キーペアの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    // AES対称鍵
    Aes,
    // P256非対称鍵
    P256,
}

/// キーペアファクトリ
pub struct KeyPairFactory;

impl KeyPairFactory {
    /// 指定された種類のキーペアを生成
    pub fn generate(key_type: KeyType) -> Box<dyn KeyPair> {
        match key_type {
            KeyType::Aes => Box::new(AesKeyPair::generate()),
            KeyType::P256 => Box::new(P256KeyPair::generate()),
        }
    }
}

impl KeyPair for AesKeyPair {
    fn public_key(&self) -> String{
        self.key_string()
    }

    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.encrypt(data)
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.decrypt(data)
    }

    fn clone_box(&self) -> Box<dyn KeyPair> {
        Box::new(self.clone())
    }
}

impl KeyPair for P256KeyPair {
    fn public_key(&self) -> String {
        self.public_key_string()
    }

    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.encrypt(data)
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.decrypt(data)
    }

    fn clone_box(&self) -> Box<dyn KeyPair> {
        Box::new(self.clone())
    }
}
