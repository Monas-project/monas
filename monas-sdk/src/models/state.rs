use serde::{Deserialize, Serialize};

// ============================================
// get_latest_version
// ============================================

/// Get-latest-version request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLatestVersionInput {
    pub content_id: String,
}

/// Get-latest-version response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLatestVersionOutput {
    pub content_id: String,
    pub latest_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

// ============================================
// get_history
// ============================================

/// Get-history request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHistoryInput {
    pub content_id: String,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    100
}

/// Get-history response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHistoryOutput {
    pub content_id: String,
    pub versions: Vec<String>,
}

// ============================================
// read_content_from_state_node
// ============================================

/// Verified read request from the State Node.
///
/// - `content_id`: content id on the State Node side (remote id). Used to fetch history and
///   version data and to bind the read signature (`read:{content_id}:{timestamp}`).
/// - `local_content_id`: SDK-local content id (plain CID). Used to look up the CEK and for the
///   post-decryption integrity check (match against the plain CID recomputed from plaintext).
///   There is no local↔remote mapping table, so the caller passes both
///   (same design as `VerifyIntegrityInput`).
/// - `version`: version CID to read. If omitted, the latest version from the State Node
///   history is read.
///
/// What is guaranteed is **only payload authenticity**. It checks that the returned bytes match
/// the requested version CID (CID recomputation + AES-GCM decryption), but does not check
/// whether that version comes from a legitimate writer, is the canonical head of the content
/// series, or is truly the latest. Read-only recipients also hold the CEK, so being able to
/// decrypt with the CEK does not prove write permission.
///
/// A monotonicity check (rollback detection) is **not implemented**. One was added once, but it
/// was removed because it could be bypassed by a version stuffed with fake parents and so gave
/// no protection, while it could not distinguish a legitimate sync delay from an attack from a
/// single response, leaving false positives that broke legitimate reads.
/// Version authenticity requires a trust anchor of owner/writer signatures, tracked in issue #59.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadContentFromStateNodeInput {
    pub content_id: String,
    /// Key of the file (`CreateContentOutput::file_id`) when the owner reads their own file.
    /// The CEK and the plainCid to match (current version) are taken from that file's record.
    /// Specify either this or `local_content_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    /// plainCid of the shared version when a share recipient reads (used to select the CEK
    /// and to match).
    #[serde(default)]
    pub local_content_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Skip verifying that the plaintext CID matches `local_content_id`.
    ///
    /// A share recipient holds the CEK under "the content_id of the shared version", but cannot
    /// know the plaintext CID of versions the owner wrote afterwards. If `true`,
    /// `local_content_id` is used only to select the CEK, and the id the decrypted plaintext
    /// actually points to is returned in `ReadContentFromStateNodeOutput::local_content_id`.
    /// Node CID recomputation and AES-GCM authentication still apply.
    #[serde(default)]
    pub accept_any_version: bool,
}

/// Verified read response from the State Node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadContentFromStateNodeOutput {
    pub content_id: String,
    /// content_id the decrypted plaintext points to. Same as the input `local_content_id` unless
    /// `accept_any_version`.
    pub local_content_id: String,
    /// Version CID actually read (verified by CID recomputation)
    pub version: String,
    /// Decrypted plaintext (base64url)
    pub content: String,
}

// ============================================
// pull_content_from_state_node

/// Pull the latest State Node version into the owner's local record.
///
/// When a recipient delegated write permission writes a new version, the owner's local record
/// falls behind the network head. If the owner then updates or revokes (re-encrypts) in that
/// state, the recipient's version is silently overwritten with the stale local plaintext.
/// This is the "pull" called before that; it adopts only a version that passed a verified read
/// (Node CID recomputation + AES-GCM decryption with own CEK).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullContentFromStateNodeInput {
    /// State Node series ID.
    pub content_id: String,
    /// Key of the file to pull into (`CreateContentOutput::file_id`).
    pub file_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullContentFromStateNodeOutput {
    pub content_id: String,
    /// plainCid of the current version after the pull.
    pub local_content_id: String,
    /// Version CID read (verified).
    pub version: String,
    /// Whether the local record moved (whether the head differed from the local version).
    pub adopted: bool,
    /// Plaintext of the head (base64url).
    pub content: String,
}

// ============================================
// verify_integrity
// ============================================

/// Integrity verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyIntegrityInput {
    pub content_id: String,
    /// Content to verify (base64url)
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<String>,
    /// Key of the target file (`CreateContentOutput::file_id`). If specified, the ciphertext
    /// returned by the State Node is verified by byte comparison with the ciphertext in that
    /// file's record (the State Node holds ciphertext, so it cannot be compared directly with
    /// the plaintext `content`). If unset, it is compared directly with the bytes of `content`
    /// as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
}

/// Integrity verification response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyIntegrityOutput {
    pub valid: bool,
    pub computed_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_latest_version() {
        let output = GetLatestVersionOutput {
            content_id: "test_id".into(),
            latest_version: "v123".into(),
            updated_at: Some("2025-12-05T12:34:56Z".into()),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"latest_version\":\"v123\""));
    }

    #[test]
    fn test_get_history_input_default_limit() {
        let json = r#"{"content_id": "test_id"}"#;
        let input: GetHistoryInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.limit, 100);
    }

    #[test]
    fn test_get_history_input_custom_limit() {
        let json = r#"{"content_id": "test_id", "limit": 50}"#;
        let input: GetHistoryInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.limit, 50);
    }

    #[test]
    fn test_get_history_output() {
        let output = GetHistoryOutput {
            content_id: "test_id".into(),
            versions: vec!["v1".into(), "v2".into()],
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"versions\""));
        assert!(json.contains("\"v1\""));
        assert!(json.contains("\"v2\""));
    }

    #[test]
    fn test_verify_integrity_output_valid() {
        let output = VerifyIntegrityOutput {
            valid: true,
            computed_hash: "abc123".into(),
            reason: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"valid\":true"));
        assert!(!json.contains("reason"));
    }

    #[test]
    fn test_verify_integrity_output_invalid() {
        let output = VerifyIntegrityOutput {
            valid: false,
            computed_hash: "abc123".into(),
            reason: Some("hash mismatch".into()),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"valid\":false"));
        assert!(json.contains("\"reason\":\"hash mismatch\""));
    }
}
