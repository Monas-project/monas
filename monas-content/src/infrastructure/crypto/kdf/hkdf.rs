use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HkdfError {
    ExpansionError,
    OutputTooLong,
    InvalidParameter(&'static str),
}

/// RFC 5869に準拠したHKDFを使用
pub struct HkdfKeyDerivation;

impl HkdfKeyDerivation {
    pub fn derive_key(
        shared_secret: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        length: usize,
    ) -> Result<Vec<u8>, HkdfError> {
        if shared_secret.is_empty() {
            return Err(HkdfError::InvalidParameter("shared_secret cannot be empty"));
        }
        if length == 0 {
            return Err(HkdfError::InvalidParameter("length must be larger than 0"));
        }

        let hkdf = Hkdf::<Sha256>::new(salt, shared_secret);

        // Output Keying Material（出力鍵材料）from RFC 5869
        let mut okm = vec![0u8; length];

        // キー導出
        hkdf.expand(info.unwrap_or(&[]), &mut okm)
            .map_err(|_| HkdfError::ExpansionError)?;
        Ok(okm)
    }

    pub fn derive_aes_256_key(
        shared_secret: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> Result<[u8; 32], HkdfError> {
        let derived = Self::derive_key(shared_secret, salt, info, 32)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived);
        Ok(key)
    }
}
