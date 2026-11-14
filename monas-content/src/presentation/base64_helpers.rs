use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;

use crate::domain::{content::encryption::ContentEncryptionKey, KeyId};

// ============================================================================
// Base64 decode helper functions
// ============================================================================

/// Generic helper that decodes base64-encoded bytes.
///
/// # Arguments
/// - `base64_str`: base64-encoded string
/// - `field_name`: field name (used in the error message)
///
/// # Returns
/// - On success: the decoded bytes
/// - On failure: `(StatusCode::BAD_REQUEST, error message)`
pub(super) fn decode_base64(
    base64_str: &str,
    field_name: &str,
) -> Result<Vec<u8>, (StatusCode, String)> {
    BASE64_STANDARD.decode(base64_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid {field_name}: {e}"),
        )
    })
}

/// Helper that decodes a base64-encoded KeyId.
///
/// # Arguments
/// - `base64_str`: base64-encoded KeyId string
/// - `field_name`: field name (used in the error message)
///
/// # Returns
/// - On success: the decoded KeyId
/// - On failure: `(StatusCode::BAD_REQUEST, error message)`
pub(super) fn decode_key_id_base64(
    base64_str: &str,
    field_name: &str,
) -> Result<KeyId, (StatusCode, String)> {
    let bytes = decode_base64(base64_str, field_name)?;
    Ok(KeyId::new(bytes))
}

/// Helper that decodes a base64-encoded ContentEncryptionKey.
///
/// # Arguments
/// - `base64_str`: base64-encoded CEK string
/// - `field_name`: field name (used in the error message)
///
/// # Returns
/// - On success: the decoded ContentEncryptionKey
/// - On failure: `(StatusCode::BAD_REQUEST, error message)`
pub(super) fn decode_cek_base64(
    base64_str: &str,
    field_name: &str,
) -> Result<ContentEncryptionKey, (StatusCode, String)> {
    let bytes = decode_base64(base64_str, field_name)?;
    Ok(ContentEncryptionKey(bytes))
}

/// Helper that decodes base64-encoded bytes (Option-aware).
///
/// # Arguments
/// - `base64_str_opt`: base64-encoded string (Option)
/// - `field_name`: field name (used in the error message)
///
/// # Returns
/// - If `None`: `Ok(None)`
/// - If `Some(base64_str)`: the decode result wrapped in `Some`
/// - On failure: `(StatusCode::BAD_REQUEST, error message)`
pub(super) fn decode_base64_optional(
    base64_str_opt: Option<&str>,
    field_name: &str,
) -> Result<Option<Vec<u8>>, (StatusCode, String)> {
    match base64_str_opt {
        Some(base64_str) => decode_base64(base64_str, field_name).map(Some),
        None => Ok(None),
    }
}
