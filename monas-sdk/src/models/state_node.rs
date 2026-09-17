use serde::{Deserialize, Serialize};

/// State Nodeへのコンテンツ作成リクエスト
#[derive(Debug, Serialize)]
pub struct StateNodeCreateContentRequest {
    /// Base64エンコードされたコンテンツデータ
    pub data: String,
}

/// State Nodeからのコンテンツ作成レスポンス（`POST /content` → 201 Created）
#[derive(Debug, Deserialize)]
pub struct StateNodeCreateContentResponse {
    #[serde(default)]
    pub content_id: String,
}

/// State Nodeへのコンテンツ更新リクエスト
#[derive(Debug, Serialize)]
pub struct StateNodeUpdateContentRequest {
    /// Base64エンコードされたコンテンツデータ
    pub data: String,
}

/// State Nodeからのコンテンツ更新レスポンス（`PUT /content/:id`）
#[derive(Debug, Deserialize)]
pub struct StateNodeUpdateContentResponse {
    #[serde(default)]
    pub content_id: String,
    #[serde(default)]
    pub updated: bool,
}

/// State Nodeからのコンテンツ削除レスポンス（`DELETE /content/:id`）
#[derive(Debug, Deserialize)]
pub struct StateNodeDeleteContentResponse {
    #[serde(default)]
    pub content_id: String,
    #[serde(default)]
    pub deleted: bool,
}

/// State Nodeからのトークン失効レスポンス（`POST /content/:id/access/invalidate`）
#[derive(Debug, Deserialize)]
pub struct StateNodeInvalidateTokensResponse {
    #[serde(default)]
    pub content_id: String,
    /// この時刻より前に発行されたTokenはすべて無効になる
    #[serde(default)]
    pub new_min_valid_issued_at: u64,
    /// この呼び出しで新しい失効境界を受け取ったメンバー。
    #[serde(default)]
    pub notified_members: Vec<String>,
    /// 失効境界を届けられなかったメンバー。次回 sync まで旧ポリシーで
    /// 認可し続ける = 失効済み Token の書き込みを受理しうる。
    #[serde(default)]
    pub unreached_members: Vec<StateNodeUnreachedMember>,
    /// State Node が自分で commit せず member へ relay した。上の2つは
    /// 「空」ではなく「不明」。
    #[serde(default)]
    pub relayed: bool,
    /// 伝播情報を返す State Node かどうか。旧 State Node のレスポンスには
    /// `notified_members` 等が無く、serde の default で空になる — それを
    /// 「全員に届いた」と読んではいけないので、フィールドの有無を別に取る。
    #[serde(skip)]
    pub reports_reach: bool,
}

impl StateNodeInvalidateTokensResponse {
    /// JSON からパースし、伝播フィールドの有無を `reports_reach` に立てる。
    pub fn from_json(body: &str) -> Result<Self, serde_json::Error> {
        let raw: serde_json::Value = serde_json::from_str(body)?;
        let reports_reach = raw
            .as_object()
            .map(|o| {
                o.contains_key("notified_members")
                    || o.contains_key("unreached_members")
                    || o.contains_key("relayed")
            })
            .unwrap_or(false);
        let mut parsed: Self = serde_json::from_value(raw)?;
        parsed.reports_reach = reports_reach;
        Ok(parsed)
    }
}

/// `StateNodeInvalidateTokensResponse::unreached_members` の1件。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct StateNodeUnreachedMember {
    pub node_id: String,
    pub error: String,
}

/// State Nodeからのコンテンツ履歴レスポンス
#[derive(Debug, Deserialize)]
pub struct StateNodeContentHistoryResponse {
    pub content_id: String,
    pub versions: Vec<String>,
}

/// State Nodeからのコンテンツデータレスポンス
#[derive(Debug, Deserialize)]
pub struct StateNodeContentDataResponse {
    pub content_id: String,
    /// Base64(Standard)エンコードされたデータ
    pub data: String,
    pub version: Option<String>,
}

/// State Nodeのエラーレスポンス
#[derive(Debug, Deserialize)]
pub struct StateNodeErrorResponse {
    pub error: String,
}

#[cfg(test)]
mod invalidate_response_tests {
    use super::*;

    /// A state node from before the propagation report: no lists, no flag.
    /// Must parse as "unknown", never as "everyone reached".
    #[test]
    fn legacy_invalidate_response_does_not_claim_reach() {
        let parsed = StateNodeInvalidateTokensResponse::from_json(
            r#"{"content_id":"c","new_min_valid_issued_at":10}"#,
        )
        .unwrap();
        assert_eq!(parsed.new_min_valid_issued_at, 10);
        assert!(!parsed.reports_reach);
        assert!(parsed.notified_members.is_empty());
        assert!(parsed.unreached_members.is_empty());
    }

    #[test]
    fn invalidate_response_with_reach_fields_is_recognised() {
        let parsed = StateNodeInvalidateTokensResponse::from_json(
            r#"{"content_id":"c","new_min_valid_issued_at":10,
                "notified_members":["n2"],
                "unreached_members":[{"node_id":"n3","error":"timed out"}],
                "relayed":false}"#,
        )
        .unwrap();
        assert!(parsed.reports_reach);
        assert_eq!(parsed.notified_members, vec!["n2"]);
        assert_eq!(parsed.unreached_members.len(), 1);
        assert_eq!(parsed.unreached_members[0].node_id, "n3");
        assert!(!parsed.relayed);
    }

    /// All reached: the lists are present but empty — still "reports reach".
    #[test]
    fn invalidate_response_with_empty_lists_still_reports_reach() {
        let parsed = StateNodeInvalidateTokensResponse::from_json(
            r#"{"content_id":"c","new_min_valid_issued_at":10,
                "notified_members":[],"unreached_members":[],"relayed":false}"#,
        )
        .unwrap();
        assert!(parsed.reports_reach);
    }
}
