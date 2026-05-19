use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum JwtSignerError {
    #[error("failed to serialize token payload: {0}")]
    Serialization(String),
    #[error("failed to sign jwt: {0}")]
    Signing(String),
}

#[derive(Debug, Serialize)]
struct JwtHeader {
    alg: String,
    typ: String,
    ver: String,
}

pub fn sign_es256_jwt_payload<P, F>(payload: &P, sign_fn: F) -> Result<String, JwtSignerError>
where
    P: Serialize,
    F: FnOnce(&[u8]) -> Result<Vec<u8>, String>,
{
    let header = JwtHeader {
        alg: "ES256".to_string(),
        typ: "JWT".to_string(),
        ver: "1.0".to_string(),
    };

    let header_json =
        serde_json::to_string(&header).map_err(|e| JwtSignerError::Serialization(e.to_string()))?;
    let payload_json =
        serde_json::to_string(payload).map_err(|e| JwtSignerError::Serialization(e.to_string()))?;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature = sign_fn(signing_input.as_bytes()).map_err(JwtSignerError::Signing)?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

    Ok(format!("{}.{}", signing_input, signature_b64))
}
