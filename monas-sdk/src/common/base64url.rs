use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// Encode as base64url (URL_SAFE_NO_PAD)
pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url (URL_SAFE_NO_PAD)
///
/// - Returns an error message (string) on failure
pub fn decode_base64url(value: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(value).map_err(|e| e.to_string())
}

/// Returns `Ok(vec![])` if `value` is an empty string; otherwise decodes like `decode_base64url`.
pub fn decode_base64url_allow_empty(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() {
        return Ok(vec![]);
    }
    decode_base64url(value)
}
