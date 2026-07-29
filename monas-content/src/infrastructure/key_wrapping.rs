use crate::domain::content::encryption::ContentEncryptionKey;
use crate::domain::share::encryption::{EnvelopeAad, KeyWrapping, KeyWrappingError};

use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs::prelude::*;
use hpke_rs_rust_crypto::HpkeRustCrypto;

/// HPKE (RFC 9180) **Auth モード**を用いた CEK ラップ実装。
///
/// - Mode: Auth（送信者認証付き。送信者秘密鍵が KEM 計算に混ざり、
///   受信者は送信者の公開鍵で unwrap する。送信者が本物でなければ復号が失敗する）
/// - KEM: DH KEM P-256
/// - KDF: HKDF-SHA256
/// - AEAD: AES-GCM-256
/// - AAD: `EnvelopeAad`（content_id・recipient_key_id・key_epoch）を束縛する。
///
/// 公開鍵は P-256 の uncompressed form (0x04 || X || Y, 65 バイト)、
/// 秘密鍵は P-256 スカラー (32 バイト) として渡されることを想定する。
#[derive(Debug, Default, Clone, Copy)]
pub struct HpkeV1KeyWrapping;

impl HpkeV1KeyWrapping {
    /// この実装で利用する HPKE の設定値を返す。
    fn hpke_config() -> (Mode, KemAlgorithm, KdfAlgorithm, AeadAlgorithm) {
        (
            Mode::Auth,
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
        sender_private_key: &[u8],
        aad: &EnvelopeAad<'_>,
    ) -> Result<(Vec<u8>, Vec<u8>), KeyWrappingError> {
        let pk_r = HpkePublicKey::from(recipient_public_key.to_vec());
        let sk_s = HpkePrivateKey::from(sender_private_key.to_vec());

        let (mode, kem, kdf, aead) = Self::hpke_config();
        let mut hpke = Hpke::<HpkeRustCrypto>::new(mode, kem, kdf, aead);

        let info = aad.content_id.as_str().as_bytes();
        let aad_bytes = aad.to_bytes();

        let (enc, wrapped_cek) = hpke
            .seal(&pk_r, info, &aad_bytes, &cek.0, None, None, Some(&sk_s))
            .map_err(|e| KeyWrappingError::CryptoError(format!("hpke seal failed: {e:?}")))?;

        Ok((enc, wrapped_cek))
    }

    fn unwrap_cek(
        &self,
        enc: &[u8],
        wrapped_cek: &[u8],
        recipient_private_key: &[u8],
        sender_public_key: &[u8],
        aad: &EnvelopeAad<'_>,
    ) -> Result<ContentEncryptionKey, KeyWrappingError> {
        let (mode, kem, kdf, aead) = Self::hpke_config();
        let hpke = Hpke::<HpkeRustCrypto>::new(mode, kem, kdf, aead);

        let sk_r = HpkePrivateKey::from(recipient_private_key.to_vec());
        let pk_s = HpkePublicKey::from(sender_public_key.to_vec());

        let info = aad.content_id.as_str().as_bytes();
        let aad_bytes = aad.to_bytes();

        let mut ctx = hpke
            .setup_receiver(enc, &sk_r, info, None, None, Some(&pk_s))
            .map_err(|e| {
                KeyWrappingError::CryptoError(format!("hpke setup_receiver failed: {e:?}"))
            })?;

        let cek_bytes = ctx
            .open(&aad_bytes, wrapped_cek)
            .map_err(|e| KeyWrappingError::CryptoError(format!("hpke open failed: {e:?}")))?;

        Ok(ContentEncryptionKey(cek_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::content::encryption::ContentEncryptionKey;
    use crate::domain::content_id::ContentId;
    use crate::domain::KeyId;

    struct TestKeys {
        sender_pk: Vec<u8>,
        sender_sk: Vec<u8>,
        recipient_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    }

    fn generate_keys() -> TestKeys {
        let (_, kem, kdf, aead) = HpkeV1KeyWrapping::hpke_config();
        let mut hpke = Hpke::<HpkeRustCrypto>::new(Mode::Auth, kem, kdf, aead);
        let sender = hpke.generate_key_pair().expect("sender key pair");
        let recipient = hpke.generate_key_pair().expect("recipient key pair");
        TestKeys {
            sender_pk: sender.public_key().as_slice().to_vec(),
            sender_sk: sender.private_key().as_slice().to_vec(),
            recipient_pk: recipient.public_key().as_slice().to_vec(),
            recipient_sk: recipient.private_key().as_slice().to_vec(),
        }
    }

    fn cid() -> ContentId {
        ContentId::new("test-content-id".into())
    }

    fn recipient_key_id() -> KeyId {
        KeyId::new(vec![7, 7, 7])
    }

    fn aad_with<'a>(cid: &'a ContentId, kid: &'a KeyId, epoch: u64) -> EnvelopeAad<'a> {
        EnvelopeAad {
            content_id: cid,
            recipient_key_id: kid,
            key_epoch: epoch,
        }
    }

    #[test]
    fn wrap_unwrap_roundtrip_with_sender_auth() {
        let wrapper = HpkeV1KeyWrapping;
        let cek = ContentEncryptionKey((0u8..32).collect());
        let keys = generate_keys();
        let cid = cid();
        let kid = recipient_key_id();
        let aad = aad_with(&cid, &kid, 0);

        let (enc, wrapped) = wrapper
            .wrap_cek(&cek, &keys.recipient_pk, &keys.sender_sk, &aad)
            .expect("wrap_cek should succeed");

        let decrypted = wrapper
            .unwrap_cek(&enc, &wrapped, &keys.recipient_sk, &keys.sender_pk, &aad)
            .expect("unwrap_cek should succeed");

        assert_eq!(decrypted.0, cek.0);
    }

    #[test]
    fn unwrap_fails_with_wrong_sender_public_key() {
        // 送信者認証の核心: 偽送信者(別鍵)が作った envelope は、
        // 受信者が期待する送信者公開鍵での unwrap に失敗する。
        let wrapper = HpkeV1KeyWrapping;
        let cek = ContentEncryptionKey(vec![0xAA; 32]);
        let keys = generate_keys();
        let attacker = generate_keys();
        let cid = cid();
        let kid = recipient_key_id();
        let aad = aad_with(&cid, &kid, 0);

        // 攻撃者が自分の秘密鍵で envelope を鋳造
        let (enc, wrapped) = wrapper
            .wrap_cek(&cek, &keys.recipient_pk, &attacker.sender_sk, &aad)
            .expect("attacker wrap should succeed");

        // 受信者は正規送信者の公開鍵で unwrap する → 失敗する
        let result = wrapper.unwrap_cek(&enc, &wrapped, &keys.recipient_sk, &keys.sender_pk, &aad);
        assert!(
            matches!(result, Err(KeyWrappingError::CryptoError(_))),
            "forged-sender envelope must fail to unwrap"
        );
    }

    #[test]
    fn unwrap_fails_with_tampered_key_epoch() {
        // AAD 束縛の検証: key_epoch を書き換えた envelope は復号に失敗する。
        let wrapper = HpkeV1KeyWrapping;
        let cek = ContentEncryptionKey(vec![0xBB; 32]);
        let keys = generate_keys();
        let cid = cid();
        let kid = recipient_key_id();

        let (enc, wrapped) = wrapper
            .wrap_cek(
                &cek,
                &keys.recipient_pk,
                &keys.sender_sk,
                &aad_with(&cid, &kid, 1),
            )
            .expect("wrap should succeed");

        let result = wrapper.unwrap_cek(
            &enc,
            &wrapped,
            &keys.recipient_sk,
            &keys.sender_pk,
            &aad_with(&cid, &kid, 2),
        );
        assert!(
            matches!(result, Err(KeyWrappingError::CryptoError(_))),
            "epoch-tampered envelope must fail to unwrap"
        );
    }

    #[test]
    fn unwrap_fails_with_wrong_content_id() {
        let wrapper = HpkeV1KeyWrapping;
        let cek = ContentEncryptionKey(vec![0xCC; 32]);
        let keys = generate_keys();
        let cid = cid();
        let wrong_cid = ContentId::new("wrong-content-id".into());
        let kid = recipient_key_id();

        let (enc, wrapped) = wrapper
            .wrap_cek(
                &cek,
                &keys.recipient_pk,
                &keys.sender_sk,
                &aad_with(&cid, &kid, 0),
            )
            .expect("wrap should succeed");

        let result = wrapper.unwrap_cek(
            &enc,
            &wrapped,
            &keys.recipient_sk,
            &keys.sender_pk,
            &aad_with(&wrong_cid, &kid, 0),
        );
        assert!(
            result.is_err(),
            "decryption should fail with wrong content_id"
        );
    }

    #[test]
    fn unwrap_fails_with_wrong_recipient_key_id() {
        let wrapper = HpkeV1KeyWrapping;
        let cek = ContentEncryptionKey(vec![0xDD; 32]);
        let keys = generate_keys();
        let cid = cid();
        let kid = recipient_key_id();
        let wrong_kid = KeyId::new(vec![8, 8, 8]);

        let (enc, wrapped) = wrapper
            .wrap_cek(
                &cek,
                &keys.recipient_pk,
                &keys.sender_sk,
                &aad_with(&cid, &kid, 0),
            )
            .expect("wrap should succeed");

        let result = wrapper.unwrap_cek(
            &enc,
            &wrapped,
            &keys.recipient_sk,
            &keys.sender_pk,
            &aad_with(&cid, &wrong_kid, 0),
        );
        assert!(
            result.is_err(),
            "decryption should fail with wrong recipient_key_id"
        );
    }

    #[test]
    fn wrap_cek_fails_with_invalid_public_key_bytes() {
        let wrapper = HpkeV1KeyWrapping;
        let cek = ContentEncryptionKey(vec![0x42; 32]);
        let keys = generate_keys();
        let cid = cid();
        let kid = recipient_key_id();
        let invalid_pk = vec![0u8; 10];

        let result = wrapper.wrap_cek(&cek, &invalid_pk, &keys.sender_sk, &aad_with(&cid, &kid, 0));

        assert!(
            matches!(result, Err(KeyWrappingError::CryptoError(_))),
            "expected CryptoError for invalid public key bytes"
        );
    }

    #[test]
    fn unwrap_cek_fails_with_invalid_private_key_bytes() {
        let wrapper = HpkeV1KeyWrapping;
        let cek = ContentEncryptionKey(vec![0x33; 32]);
        let keys = generate_keys();
        let cid = cid();
        let kid = recipient_key_id();
        let aad = aad_with(&cid, &kid, 0);

        let (enc, wrapped) = wrapper
            .wrap_cek(&cek, &keys.recipient_pk, &keys.sender_sk, &aad)
            .expect("wrap should succeed");

        let invalid_sk_bytes = vec![0u8; 10];
        let result = wrapper.unwrap_cek(&enc, &wrapped, &invalid_sk_bytes, &keys.sender_pk, &aad);

        assert!(
            matches!(result, Err(KeyWrappingError::CryptoError(_))),
            "expected CryptoError for invalid private key bytes"
        );
    }
}
