use serde::{Deserialize, Serialize};
use std::fmt;

/// Unified error type used across the SDK
///
/// Marked `#[non_exhaustive]`, so adding variants in the future is SemVer-compatible.
/// Downstream crates must always include a `_ =>` fallthrough when matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "message")]
#[non_exhaustive]
pub enum ApiError {
    /// Missing input data / format mismatch (400)
    Validation(String),
    /// Missing/invalid credentials, invalid signature (401)
    Unauthorized(String),
    /// No permission (e.g. not the owner) (403)
    Forbidden(String),
    /// Resource does not exist (404)
    NotFound(String),
    /// Deleted (410). Returned when the State Node has a delete in the content's history.
    /// Distinguished from 404 (e.g. sync has not arrived yet).
    Gone(String),
    /// Conflict (e.g. concurrent update) (409)
    Conflict(String),
    /// Communication timeout with the State Node (408)
    Timeout(String),
    /// Unexpected exception (500)
    Internal(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Validation(msg) => write!(f, "Validation error: {msg}"),
            ApiError::Unauthorized(msg) => write!(f, "Unauthorized: {msg}"),
            ApiError::Forbidden(msg) => write!(f, "Forbidden: {msg}"),
            ApiError::NotFound(msg) => write!(f, "Not found: {msg}"),
            ApiError::Gone(msg) => write!(f, "Gone: {msg}"),
            ApiError::Conflict(msg) => write!(f, "Conflict: {msg}"),
            ApiError::Timeout(msg) => write!(f, "Timeout: {msg}"),
            ApiError::Internal(msg) => write!(f, "Internal error: {msg}"),
        }
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    /// Return the HTTP status code
    pub fn status_code(&self) -> u16 {
        match self {
            ApiError::Validation(_) => 400,
            ApiError::Unauthorized(_) => 401,
            ApiError::Forbidden(_) => 403,
            ApiError::NotFound(_) => 404,
            ApiError::Gone(_) => 410,
            ApiError::Conflict(_) => 409,
            ApiError::Timeout(_) => 408,
            ApiError::Internal(_) => 500,
        }
    }

    /// Convert a ureq send-side error into an `ApiError`.
    ///
    /// `ureq::Error::Timeout(_)` maps to `ApiError::Timeout`; everything else is collapsed into
    /// `ApiError::Internal` (prefixed with `context`).
    pub fn from_ureq_error(context: &str, err: ureq::Error) -> Self {
        match err {
            ureq::Error::Timeout(_) => {
                ApiError::Timeout(format!("{context}: request timed out ({err})"))
            }
            other => ApiError::Internal(format!("{context}: {other}")),
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
        assert_eq!(ApiError::Gone("test".into()).status_code(), 410);
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
