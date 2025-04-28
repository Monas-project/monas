#[derive(Debug, Clone)]
pub struct AesKeyPair {
    key: Vec<u8>,
}

impl AesKeyPair {
    pub fn new() -> Self {
        Self {
            key: b"AES_KEY_FOR_TESTING_DO_NOT_USE".to_vec(),
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .zip(self.key.iter().cycle())
            .map(|(d, k)| d ^ k)
            .collect()
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.encrypt(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_key_pair() {
        let key_pair = AesKeyPair::new();
        let data = b"Hello, World!";
        let encrypted = key_pair.encrypt(data);
        assert_ne!(encrypted, data);
        let decrypted = key_pair.decrypt(&encrypted);
        assert_eq!(decrypted, data);
    }
}
