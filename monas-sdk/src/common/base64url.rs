use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// base64url（URL_SAFE_NO_PAD）でエンコードする
pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// base64url（URL_SAFE_NO_PAD）をデコードする
///
/// - 失敗時はエラーメッセージ（文字列）を返します
pub fn decode_base64url(value: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(value).map_err(|e| e.to_string())
}

/// `value` が空文字の場合は `Ok(vec![])` を返し、それ以外は `decode_base64url` と同様にデコードします。
pub fn decode_base64url_allow_empty(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() {
        return Ok(vec![]);
    }
    decode_base64url(value)
}
