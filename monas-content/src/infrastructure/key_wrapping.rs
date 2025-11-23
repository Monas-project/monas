use crate::domain::content::encryption::ContentEncryptionKey;
use crate::domain::content_id::ContentId;
use crate::domain::share::encryption::{KeyWrapping, KeyWrappingError};

use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs::prelude::*;
use hpke_rs_rust_crypto::HpkeRustCrypto;

/// HPKE (RFC 9180) を用いた CEK ラップ実装。
///
/// - KEM: DH KEM P-256
/// - KDF: HKDF-SHA256
/// - AEAD: AES-GCM-256
///
/// 受信者の公開鍵は P-256 の uncompressed form (0x04 || X || Y, 65 バイト) として渡されることを想定する。
#[derive(Debug, Default, Clone, Copy)]
pub struct HpkeV1KeyWrapping;

impl HpkeV1KeyWrapping {
    /// この実装で利用する HPKE の設定値を返す。
    fn hpke_config() -> (Mode, KemAlgorithm, KdfAlgorithm, AeadAlgorithm) {
        (
            Mode::Base,
            KemAlgorithm::DhKemP256,
            KdfAlgorithm::HkdfSha256,
            AeadAlgorithm::Aes256Gcm,
        )
    }
}

impl KeyWrapping for HpkeV1KeyWrapping {
    fn wrap_cek(
        &self,
        cek: &ContentEncryptionKey,
        recipient_public_key: &[u8],
        content_id: &ContentId,
    ) -> Result<(Vec<u8>, Vec<u8>), KeyWrappingError> {
        let pk_r = HpkePublicKey::from(recipient_public_key.to_vec());

        let (mode, kem, kdf, aead) = Self::hpke_config();

        let mut hpke = Hpke::<HpkeRustCrypto>::new(mode, kem, kdf, aead);

        // 両方に入れる必要があるかは要検討
        let info = content_id.as_str().as_bytes();
        let aad = content_id.as_str().as_bytes();

        let (enc, wrapped_cek) = hpke
            .seal(&pk_r, info, aad, &cek.0, None, None, None)
            .map_err(|e| KeyWrappingError::CryptoError(format!("hpke seal failed: {e:?}")))?;

        Ok((enc, wrapped_cek))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::content::encryption::ContentEncryptionKey;
    use p256::ecdh::EphemeralSecret;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::{EncodedPoint, PublicKey};
    use rand_core::OsRng;

    fn generate_p256_keypair() -> (Vec<u8>, EphemeralSecret) {
        let mut rng = OsRng;
        let sk = EphemeralSecret::random(&mut rng);
        let pk = PublicKey::from(&sk);
        let encoded: EncodedPoint = pk.to_encoded_point(false); // uncompressed
        (encoded.as_bytes().to_vec(), sk)
    }

    #[test]
    fn wrap_cek_produces_ciphertext() {
        let wrapper = HpkeV1KeyWrapping;
        let cek = ContentEncryptionKey(vec![0x11; 32]);
        let (pk_bytes, _sk) = generate_p256_keypair();
        let cid = ContentId::new("test-content-id".into());

        let (enc, wrapped) = wrapper
            .wrap_cek(&cek, &pk_bytes, &cid)
            .expect("hpke wrap_cek should succeed");

        assert!(!enc.is_empty());
        assert!(!wrapped.is_empty());
    }

    #[test]
    fn wrap_cek_can_be_decrypted_by_hpke_receiver() {
        let wrapper = HpkeV1KeyWrapping;
        let cek = ContentEncryptionKey((0u8..32).collect());
        let cid = ContentId::new("roundtrip-test".into());

        let (mode, kem, kdf, aead) = HpkeV1KeyWrapping::hpke_config();
        let mut hpke = Hpke::<HpkeRustCrypto>::new(mode, kem, kdf, aead);

        let keypair = hpke
            .generate_key_pair()
            .expect("failed to generate HPKE key pair");
        let pk_r = keypair.public_key();
        let sk_r = keypair.private_key();
        let pk_bytes = pk_r.as_slice().to_vec();

        let (enc, wrapped) = wrapper
            .wrap_cek(&cek, &pk_bytes, &cid)
            .expect("hpke wrap_cek should succeed");

        let info = cid.as_str().as_bytes();
        let aad = info;
        let mut ctx = hpke
            .setup_receiver(enc.as_slice(), sk_r, info, None, None, None)
            .expect("hpke setup_receiver should succeed");
        let decrypted = ctx.open(aad, &wrapped).expect("hpke open should succeed");

        assert_eq!(decrypted, cek.0);
    }

    #[test]
    fn decrypt_fails_with_wrong_content_id() {
        let wrapper = HpkeV1KeyWrapping;
        let cek = ContentEncryptionKey(vec![0xAA; 32]);
        let cid = ContentId::new("correct-content-id".into());

        let (mode, kem, kdf, aead) = HpkeV1KeyWrapping::hpke_config();
        let mut hpke = Hpke::<HpkeRustCrypto>::new(mode, kem, kdf, aead);
        let keypair = hpke
            .generate_key_pair()
            .expect("failed to generate HPKE key pair");
        let pk_r = keypair.public_key();
        let sk_r = keypair.private_key();
        let pk_bytes = pk_r.as_slice().to_vec();

        let (enc, wrapped) = wrapper
            .wrap_cek(&cek, &pk_bytes, &cid)
            .expect("hpke wrap_cek should succeed");

        let wrong_cid = ContentId::new("wrong-content-id".into());
        let wrong_info = wrong_cid.as_str().as_bytes();
        let wrong_aad = wrong_info;

        let mut ctx = hpke
            .setup_receiver(enc.as_slice(), sk_r, wrong_info, None, None, None)
            .expect("hpke setup_receiver with wrong info should still build context");

        let result = ctx.open(wrong_aad, &wrapped);
        assert!(
            result.is_err(),
            "decryption should fail with wrong content_id"
        );
    }

    #[test]
    fn wrap_cek_fails_with_invalid_public_key_bytes() {
        let wrapper = HpkeV1KeyWrapping;
        let cek = ContentEncryptionKey(vec![0x42; 32]);
        let cid = ContentId::new("invalid-pk-test".into());
        let invalid_pk = vec![0u8; 10];

        let result = wrapper.wrap_cek(&cek, &invalid_pk, &cid);

        assert!(
            matches!(result, Err(KeyWrappingError::CryptoError(_))),
            "expected CryptoError for invalid public key bytes"
        );
    }
}
