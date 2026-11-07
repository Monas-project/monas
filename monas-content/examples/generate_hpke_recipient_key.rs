use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{EncodedPoint, PublicKey, SecretKey};
use rand_core::OsRng;

/// Developer tool for generating an HPKE recipient key.
///
/// Prints to stdout:
/// - Public key: uncompressed form (0x04 || X || Y, 65 bytes), base64-encoded
/// - Secret key: 32-byte scalar, base64-encoded
///
/// The server-side `HpkeV1KeyWrapping` treats the recipient public key as P-256 uncompressed, so
/// `recipient_public_key_base64` can be passed as-is to the API's `recipient_public_key_base64`.
///
/// This binary is not meant to be included in production containers.
/// Run it as follows:
/// `cargo run -p monas-content --example generate_hpke_recipient_key`
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
    println!("recipient_private_key_base64: {secret_key_b64}");
}
