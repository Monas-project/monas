use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::api_error::ApiError;

/// SDK全体で使用する統一レスポンス型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
    pub trace_id: String,
}

impl<T> ApiResponse<T> {
    /// 成功レスポンスを生成
    pub fn success(data: T, trace_id: String) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            trace_id,
        }
    }

    /// エラーレスポンスを生成
    pub fn error(error: ApiError, trace_id: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            trace_id,
        }
    }

    /// 成功レスポンスを自動生成されたtrace_idで生成
    pub fn success_with_new_trace_id(data: T) -> Self {
        Self::success(data, generate_trace_id())
    }

    /// エラーレスポンスを自動生成されたtrace_idで生成
    pub fn error_with_new_trace_id(error: ApiError) -> Self {
        Self::error(error, generate_trace_id())
    }
}

/// トレースIDを生成
pub fn generate_trace_id() -> String {
    format!("trace_{}", &Uuid::new_v4().simple().to_string()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestData {
        value: String,
    }

    #[test]
    fn test_success_response() {
        let data = TestData {
            value: "test".into(),
        };
        let response = ApiResponse::success(data.clone(), "trace_123".into());

        assert!(response.success);
        assert_eq!(response.data, Some(data));
        assert!(response.error.is_none());
        assert_eq!(response.trace_id, "trace_123");
    }

    #[test]
    fn test_error_response() {
        let error = ApiError::NotFound("resource not found".into());
        let response: ApiResponse<TestData> = ApiResponse::error(error, "trace_456".into());

        assert!(!response.success);
        assert!(response.data.is_none());
        assert!(response.error.is_some());
        assert_eq!(response.trace_id, "trace_456");
    }

    #[test]
    fn test_generate_trace_id() {
        let trace_id = generate_trace_id();
        assert!(trace_id.starts_with("trace_"));
        assert_eq!(trace_id.len(), 22); // "trace_" (6) + 16 chars
    }

    #[test]
    fn test_serialize_success_response() {
        let data = TestData {
            value: "test".into(),
        };
        let response = ApiResponse::success(data, "trace_123".into());
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"trace_id\":\"trace_123\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_serialize_error_response() {
        let error = ApiError::Validation("invalid".into());
        let response: ApiResponse<TestData> = ApiResponse::error(error, "trace_789".into());
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"success\":false"));
        assert!(json.contains("\"trace_id\":\"trace_789\""));
        assert!(!json.contains("\"data\""));
    }
}
