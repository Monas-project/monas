use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{EncodedPoint, PublicKey, SecretKey};
use rand_core::OsRng;

/// 受信者用の P-256 鍵ペアを生成し、
/// - 公開鍵: uncompressed form (0x04 || X || Y, 65バイト) を base64 化
/// - 秘密鍵: 32バイトスカラーを base64 化
/// として標準出力に出すスクリプト。
///
/// サーバ側の `HpkeV1KeyWrapping` は「受信者公開鍵 = P-256 uncompressed」としているので、
/// `recipient_public_key_base64` をそのまま `recipient_public_key_base64` に渡せば OK。
fn main() {
    let mut rng = OsRng;
    let secret_key = SecretKey::random(&mut rng);
    let public_key: PublicKey = secret_key.public_key();
    let encoded: EncodedPoint = public_key.to_encoded_point(false);
    let public_key_bytes = encoded.as_bytes();

    let secret_key_bytes = secret_key.to_bytes();

    let public_key_b64 = BASE64_STANDARD.encode(public_key_bytes);
    let secret_key_b64 = BASE64_STANDARD.encode(secret_key_bytes);

    println!("recipient_public_key_base64: {public_key_b64}");
    println!("recipient_private_key_base64 (安全な場所で保存してください): {secret_key_b64}");
}
