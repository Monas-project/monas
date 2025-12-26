use crate::common::{generate_trace_id, ApiError, ApiResponse};
use crate::models::state::{
    GetHistoryInput, GetHistoryOutput, GetLatestVersionInput, GetLatestVersionOutput,
    VerifyIntegrityInput, VerifyIntegrityOutput,
};

use super::MonasController;

impl MonasController {
    /// コンテンツの最新バージョン（CID）を取得する
    pub fn get_latest_version(
        &self,
        _input: GetLatestVersionInput,
    ) -> ApiResponse<GetLatestVersionOutput> {
        let trace_id = generate_trace_id();

        // TODO: monas-state-node から最新バージョンを取得

        ApiResponse::error(
            ApiError::Internal("get_latest_version is not implemented yet".into()),
            trace_id,
        )
    }

    /// コンテンツの更新履歴を取得する
    pub fn get_history(&self, _input: GetHistoryInput) -> ApiResponse<GetHistoryOutput> {
        let trace_id = generate_trace_id();

        // TODO: monas-state-node から履歴を取得

        ApiResponse::error(
            ApiError::Internal("get_history is not implemented yet".into()),
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
        _input: VerifyIntegrityInput,
    ) -> ApiResponse<VerifyIntegrityOutput> {
        let trace_id = generate_trace_id();

        // TODO: ハッシュ計算 + State Node と比較

        ApiResponse::error(
            ApiError::Internal("verify_integrity is not implemented yet".into()),
            trace_id,
        )
    }
}
