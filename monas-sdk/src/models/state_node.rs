use serde::{Deserialize, Serialize};

/// Content creation request to the State Node
#[derive(Debug, Serialize)]
pub struct StateNodeCreateContentRequest {
    /// Base64-encoded content data
    pub data: String,
}

/// Content creation response from the State Node (`POST /content` → 201 Created)
#[derive(Debug, Deserialize)]
pub struct StateNodeCreateContentResponse {
    #[serde(default)]
    pub content_id: String,
}

/// Content update request to the State Node
#[derive(Debug, Serialize)]
pub struct StateNodeUpdateContentRequest {
    /// Base64-encoded content data
    pub data: String,
}

/// Content update response from the State Node (`PUT /content/:id`)
#[derive(Debug, Deserialize)]
pub struct StateNodeUpdateContentResponse {
    #[serde(default)]
    pub content_id: String,
    #[serde(default)]
    pub updated: bool,
}

/// Content deletion response from the State Node (`DELETE /content/:id`)
#[derive(Debug, Deserialize)]
pub struct StateNodeDeleteContentResponse {
    #[serde(default)]
    pub content_id: String,
    #[serde(default)]
    pub deleted: bool,
}

/// Token revocation response from the State Node (`POST /content/:id/access/invalidate`)
#[derive(Debug, Deserialize)]
pub struct StateNodeInvalidateTokensResponse {
    #[serde(default)]
    pub content_id: String,
    /// All tokens issued before this time become invalid
    #[serde(default)]
    pub new_min_valid_issued_at: u64,
    /// Members that received the new revocation boundary in this call.
    #[serde(default)]
    pub notified_members: Vec<String>,
    /// Members the revocation boundary could not be delivered to. They keep authorizing with the
    /// old policy until the next sync = they may accept writes with revoked tokens.
    #[serde(default)]
    pub unreached_members: Vec<StateNodeUnreachedMember>,
    /// The State Node relayed to a member instead of committing itself. The two fields above
    /// are "unknown", not "empty".
    #[serde(default)]
    pub relayed: bool,
    /// Whether the State Node returns propagation info. Responses from older State Nodes lack
    /// `notified_members` etc., which become empty via serde's default — that must not be read
    /// as "reached everyone", so the presence of the fields is captured separately.
    #[serde(skip)]
    pub reports_reach: bool,
}

impl StateNodeInvalidateTokensResponse {
    /// Parse from JSON and set `reports_reach` according to whether propagation fields are present.
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

/// One entry of `StateNodeInvalidateTokensResponse::unreached_members`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct StateNodeUnreachedMember {
    pub node_id: String,
    pub error: String,
}

/// Content history response from the State Node
#[derive(Debug, Deserialize)]
pub struct StateNodeContentHistoryResponse {
    pub content_id: String,
    pub versions: Vec<String>,
}

/// Content data response from the State Node
#[derive(Debug, Deserialize)]
pub struct StateNodeContentDataResponse {
    pub content_id: String,
    /// Base64 (Standard) encoded data
    pub data: String,
    pub version: Option<String>,
}

/// State Node error response
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
