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
