use base64::{
    engine::general_purpose::STANDARD as BASE64_STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};
use sha2::{Digest, Sha256};

use crate::common::{generate_trace_id, ApiError, ApiResponse};
use crate::models::state::{
    GetHistoryInput, GetHistoryOutput, GetLatestVersionInput, GetLatestVersionOutput,
    VerifyIntegrityInput, VerifyIntegrityOutput,
};
use crate::models::state_node::{
    StateNodeContentDataResponse, StateNodeContentHistoryResponse, StateNodeErrorResponse,
};

use super::MonasController;

impl MonasController {
    fn validate_state_content_id<T>(content_id: &str, trace_id: String) -> Option<ApiResponse<T>> {
        if content_id.is_empty() {
            return Some(ApiResponse::error(
                ApiError::Validation("content_id must not be empty".into()),
                trace_id,
            ));
        }
        None
    }

    fn state_node_get_string<T>(
        &self,
        url: &str,
        trace_id: String,
    ) -> Result<(u16, String), ApiResponse<T>> {
        let trace_id_for_call = trace_id.clone();
        let resp = ureq::get(url)
            .config()
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(|e| {
                ApiResponse::error(
                    ApiError::Internal(format!("Failed to call State Node: {}", e)),
                    trace_id_for_call,
                )
            })?;

        let status = resp.status().as_u16();
        let body = resp.into_body().read_to_string().map_err(|e| {
            ApiResponse::error(
                ApiError::Internal(format!("Failed to read State Node response body: {}", e)),
                trace_id,
            )
        })?;

        Ok((status, body))
    }

    fn map_state_node_status_error<T>(
        status: u16,
        body: Option<String>,
        trace_id: String,
    ) -> ApiResponse<T> {
        let msg = body.unwrap_or_else(|| format!("State Node returned HTTP {}", status));
        match status {
            400 => ApiResponse::error(ApiError::Validation(msg), trace_id),
            404 => ApiResponse::error(ApiError::NotFound(msg), trace_id),
            408 => ApiResponse::error(ApiError::Timeout(msg), trace_id),
            _ => ApiResponse::error(ApiError::Internal(msg), trace_id),
        }
    }

    fn get_state_node_history<T>(
        &self,
        content_id: &str,
        trace_id: String,
    ) -> Result<StateNodeContentHistoryResponse, ApiResponse<T>> {
        let url = format!("{}/content/{}/history", self.state_node_url, content_id);

        let (status, body) = self.state_node_get_string::<T>(&url, trace_id.clone())?;
        if status >= 400 {
            let msg = serde_json::from_str::<StateNodeErrorResponse>(&body)
                .ok()
                .map(|e| e.error)
                .or_else(|| (!body.is_empty()).then_some(body));
            return Err(Self::map_state_node_status_error(status, msg, trace_id));
        }

        serde_json::from_str::<StateNodeContentHistoryResponse>(&body).map_err(|e| {
            ApiResponse::error(
                ApiError::Internal(format!("Failed to parse State Node response: {}", e)),
                trace_id,
            )
        })
    }

    fn get_state_node_version_data<T>(
        &self,
        content_id: &str,
        version: &str,
        trace_id: String,
    ) -> Result<StateNodeContentDataResponse, ApiResponse<T>> {
        let url = format!(
            "{}/content/{}/version/{}",
            self.state_node_url, content_id, version
        );

        let (status, body) = self.state_node_get_string::<T>(&url, trace_id.clone())?;
        if status >= 400 {
            let msg = serde_json::from_str::<StateNodeErrorResponse>(&body)
                .ok()
                .map(|e| e.error)
                .or_else(|| (!body.is_empty()).then_some(body));
            return Err(Self::map_state_node_status_error(status, msg, trace_id));
        }

        serde_json::from_str::<StateNodeContentDataResponse>(&body).map_err(|e| {
            ApiResponse::error(
                ApiError::Internal(format!("Failed to parse State Node response: {}", e)),
                trace_id,
            )
        })
    }

    /// コンテンツの最新バージョン（CID）を取得する
    pub fn get_latest_version(
        &self,
        input: GetLatestVersionInput,
    ) -> ApiResponse<GetLatestVersionOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }

        let history = match self
            .get_state_node_history::<GetLatestVersionOutput>(&input.content_id, trace_id.clone())
        {
            Ok(h) => h,
            Err(e) => return e,
        };

        let latest = history
            .versions
            .last()
            .cloned()
            .unwrap_or_else(|| input.content_id.clone());

        ApiResponse::success(
            GetLatestVersionOutput {
                content_id: input.content_id,
                latest_version: latest,
                updated_at: None,
            },
            trace_id,
        )
    }

    /// コンテンツの更新履歴を取得する
    pub fn get_history(&self, input: GetHistoryInput) -> ApiResponse<GetHistoryOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }

        let history = match self
            .get_state_node_history::<GetHistoryOutput>(&input.content_id, trace_id.clone())
        {
            Ok(h) => h,
            Err(e) => return e,
        };

        // limit はState Node側に無いので、SDK側で適用（末尾=最新側を優先）
        let mut versions = history.versions;
        let limit = input.limit as usize;
        if limit > 0 && versions.len() > limit {
            versions = versions[versions.len() - limit..].to_vec();
        }

        ApiResponse::success(
            GetHistoryOutput {
                content_id: input.content_id,
                versions,
            },
            trace_id,
        )
    }

    /// 取得したコンテンツの整合性を検証する
    ///
    /// 処理フロー:
    /// 1. コンテンツのハッシュを計算
    /// 2. State Nodeから取得した情報と比較
    /// 3. 一致すれば valid: true
    pub fn verify_integrity(
        &self,
        input: VerifyIntegrityInput,
    ) -> ApiResponse<VerifyIntegrityOutput> {
        let trace_id = generate_trace_id();

        if let Some(response) = Self::validate_state_content_id(&input.content_id, trace_id.clone())
        {
            return response;
        }

        if input.content.is_empty() {
            return ApiResponse::error(
                ApiError::Validation("content must not be empty".into()),
                trace_id,
            );
        }

        let content_bytes = match URL_SAFE_NO_PAD.decode(&input.content) {
            Ok(b) => b,
            Err(e) => {
                return ApiResponse::error(
                    ApiError::Validation(format!("Invalid content base64url: {}", e)),
                    trace_id,
                );
            }
        };

        let computed_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&content_bytes);
            let digest = hasher.finalize();
            format!("{:x}", digest)
        };

        let version_to_check = if let Some(v) = input.expected_version.clone() {
            v
        } else {
            match self.get_state_node_history::<VerifyIntegrityOutput>(
                &input.content_id,
                trace_id.clone(),
            ) {
                Ok(h) => h
                    .versions
                    .last()
                    .cloned()
                    .unwrap_or_else(|| input.content_id.clone()),
                Err(_) => {
                    return ApiResponse::success(
                        VerifyIntegrityOutput {
                            valid: false,
                            computed_hash,
                            reason: Some("failed to fetch history from state node".into()),
                        },
                        trace_id,
                    );
                }
            }
        };

        let state_node_data = match self.get_state_node_version_data::<VerifyIntegrityOutput>(
            &input.content_id,
            &version_to_check,
            trace_id.clone(),
        ) {
            Ok(d) => d,
            Err(_) => {
                return ApiResponse::success(
                    VerifyIntegrityOutput {
                        valid: false,
                        computed_hash,
                        reason: Some(format!(
                            "version not found on state node: {}",
                            version_to_check
                        )),
                    },
                    trace_id,
                );
            }
        };

        let state_bytes = match BASE64_STANDARD.decode(&state_node_data.data) {
            Ok(b) => b,
            Err(e) => {
                return ApiResponse::success(
                    VerifyIntegrityOutput {
                        valid: false,
                        computed_hash,
                        reason: Some(format!("invalid base64 data from state node: {}", e)),
                    },
                    trace_id,
                );
            }
        };

        let valid = content_bytes == state_bytes;
        let reason = if valid {
            None
        } else {
            Some(format!(
                "content mismatch with state node (version={})",
                version_to_check
            ))
        };

        ApiResponse::success(
            VerifyIntegrityOutput {
                valid,
                computed_hash,
                reason,
            },
            trace_id,
        )
    }
}
