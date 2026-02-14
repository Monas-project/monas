use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;

use crate::domain::{content::encryption::ContentEncryptionKey, KeyId};

// ============================================================================
// Base64デコードヘルパー関数
// ============================================================================

/// base64エンコードされたバイト列をデコードする汎用ヘルパー関数。
///
/// # 引数
/// - `base64_str`: base64エンコードされた文字列
/// - `field_name`: フィールド名（エラーメッセージに使用）
///
/// # 戻り値
/// - 成功時: デコードされたバイト列
/// - 失敗時: `(StatusCode::BAD_REQUEST, エラーメッセージ)`
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

/// base64エンコードされたKeyIdをデコードするヘルパー関数。
///
/// # 引数
/// - `base64_str`: base64エンコードされたKeyId文字列
/// - `field_name`: フィールド名（エラーメッセージに使用）
///
/// # 戻り値
/// - 成功時: デコードされたKeyId
/// - 失敗時: `(StatusCode::BAD_REQUEST, エラーメッセージ)`
pub(super) fn decode_key_id_base64(
    base64_str: &str,
    field_name: &str,
) -> Result<KeyId, (StatusCode, String)> {
    let bytes = decode_base64(base64_str, field_name)?;
    Ok(KeyId::new(bytes))
}

/// base64エンコードされたContentEncryptionKeyをデコードするヘルパー関数。
///
/// # 引数
/// - `base64_str`: base64エンコードされたCEK文字列
/// - `field_name`: フィールド名（エラーメッセージに使用）
///
/// # 戻り値
/// - 成功時: デコードされたContentEncryptionKey
/// - 失敗時: `(StatusCode::BAD_REQUEST, エラーメッセージ)`
pub(super) fn decode_cek_base64(
    base64_str: &str,
    field_name: &str,
) -> Result<ContentEncryptionKey, (StatusCode, String)> {
    let bytes = decode_base64(base64_str, field_name)?;
    Ok(ContentEncryptionKey(bytes))
}

/// base64エンコードされたバイト列をデコードするヘルパー関数（Option対応）。
///
/// # 引数
/// - `base64_str_opt`: base64エンコードされた文字列（Option）
/// - `field_name`: フィールド名（エラーメッセージに使用）
///
/// # 戻り値
/// - `None`の場合: `Ok(None)`
/// - `Some(base64_str)`の場合: デコード結果を`Some`でラップ
/// - 失敗時: `(StatusCode::BAD_REQUEST, エラーメッセージ)`
pub(super) fn decode_base64_optional(
    base64_str_opt: Option<&str>,
    field_name: &str,
) -> Result<Option<Vec<u8>>, (StatusCode, String)> {
    match base64_str_opt {
        Some(base64_str) => decode_base64(base64_str, field_name).map(Some),
        None => Ok(None),
    }
}
