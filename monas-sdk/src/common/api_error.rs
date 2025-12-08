use serde::{Deserialize, Serialize};
use std::fmt;

/// SDK全体で使用する統一エラー型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "message")]
pub enum ApiError {
    /// 入力データ不足・形式不一致 (400)
    Validation(String),
    /// 認証情報不備・署名無効 (401)
    Unauthorized(String),
    /// 権限なし（所有者でない等） (403)
    Forbidden(String),
    /// リソース不存在 (404)
    NotFound(String),
    /// 競合（同時更新等） (409)
    Conflict(String),
    /// State Nodeとの通信タイムアウト (408)
    Timeout(String),
    /// 予期せぬ例外 (500)
    Internal(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Validation(msg) => write!(f, "Validation error: {}", msg),
            ApiError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            ApiError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            ApiError::NotFound(msg) => write!(f, "Not found: {}", msg),
            ApiError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            ApiError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            ApiError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    /// HTTPステータスコードを返す
    pub fn status_code(&self) -> u16 {
        match self {
            ApiError::Validation(_) => 400,
            ApiError::Unauthorized(_) => 401,
            ApiError::Forbidden(_) => 403,
            ApiError::NotFound(_) => 404,
            ApiError::Conflict(_) => 409,
            ApiError::Timeout(_) => 408,
            ApiError::Internal(_) => 500,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_codes() {
        assert_eq!(ApiError::Validation("test".into()).status_code(), 400);
        assert_eq!(ApiError::Unauthorized("test".into()).status_code(), 401);
        assert_eq!(ApiError::Forbidden("test".into()).status_code(), 403);
        assert_eq!(ApiError::NotFound("test".into()).status_code(), 404);
        assert_eq!(ApiError::Conflict("test".into()).status_code(), 409);
        assert_eq!(ApiError::Timeout("test".into()).status_code(), 408);
        assert_eq!(ApiError::Internal("test".into()).status_code(), 500);
    }

    #[test]
    fn test_serialize_deserialize() {
        let error = ApiError::Validation("invalid input".into());
        let json = serde_json::to_string(&error).unwrap();
        let deserialized: ApiError = serde_json::from_str(&json).unwrap();

        match deserialized {
            ApiError::Validation(msg) => assert_eq!(msg, "invalid input"),
            _ => panic!("unexpected error type"),
        }
    }
}
