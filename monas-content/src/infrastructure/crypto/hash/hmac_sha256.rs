use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HmacError {
    KeyInitializationError,
    VerificationError,
}

pub struct HmacSha256;

impl HmacSha256 {
    pub fn compute(key: &[u8], data: &[u8]) -> Result<Vec<u8>, HmacError> {
        let mut mac =
            <Hmac<Sha256>>::new_from_slice(key).map_err(|_| HmacError::KeyInitializationError)?;
        mac.update(data);
        let result = mac.finalize();
        Ok(result.into_bytes().to_vec())
    }

    pub fn verify(key: &[u8], data: &[u8], expected_hash: &[u8]) -> Result<(), HmacError> {
        let computed = Self::compute(key, data)?;

        if computed.len() != expected_hash.len() {
            return Err(HmacError::VerificationError);
        }
        let mut result = 0;
        for (a, b) in computed.iter().zip(expected_hash.iter()) {
            result |= a ^ b;
        }

        if result == 0 {
            Ok(())
        } else {
            Err(HmacError::VerificationError)
        }
    }

    pub fn is_verified(key: &[u8], data: &[u8], expected_hash: &[u8]) -> bool {
        Self::verify(key, data, expected_hash).is_ok()
    }
}
