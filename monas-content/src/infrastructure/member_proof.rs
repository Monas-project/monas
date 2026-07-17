//! Client-side verification of owner-issued membership proofs.
//!
//! A membership proof is an ES256 JWT the content owner issues to a state node,
//! attesting that the node is a legitimate member/host of a content. A member
//! node attaches its proof to relay-read responses; the reader verifies it here
//! to confirm the responder is a real member — WITHOUT ever seeing the member
//! list (`docs/design/read-response-integrity.md` §5.1.b).
//!
//! Trust root: the owner public key, recoverable directly from the owner
//! key_id (`user:{hex(pubkey)}`) that the reader already holds in its own
//! delegation token's `iss`. No key-fetch API is needed.
//!
//! JWT format (matching monas-account's `sign_es256_jwt_payload`):
//! `base64url(header).base64url(payload).base64url(sig)`, ES256 = P-256 ECDSA
//! over `SHA-256(signing_input)`, signature as fixed 64-byte r||s.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum MemberProofError {
    #[error("malformed proof token (expected 3 JWT segments)")]
    Malformed,
    #[error("failed to decode proof segment: {0}")]
    Decode(String),
    #[error("failed to parse owner key_id: {0}")]
    OwnerKey(String),
    #[error("proof signature is invalid")]
    BadSignature,
    #[error("proof issuer does not match the content owner")]
    IssuerMismatch,
    #[error("proof is not for content {expected}")]
    ContentMismatch { expected: String },
    #[error("proof does not grant the host capability")]
    NotHostCapability,
    #[error("proof audience does not match the responding node")]
    AudienceMismatch,
    #[error("proof has expired")]
    Expired,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    exp: u64,
    #[allow(dead_code)]
    iat: u64,
    att: Vec<Capability>,
}

#[derive(Deserialize)]
struct Capability {
    with: String,
    can: String,
}

/// Verify an owner-issued membership proof.
///
/// Checks: signature against `owner_key_id`'s public key; `iss == owner_key_id`;
/// audience == `expected_node_id` (the node that answered); the `host`
/// capability is granted for `content_id`; and not expired at `now_secs`.
///
/// `owner_key_id` is `user:{hex(pubkey)}` — the same value the reader carries in
/// its own delegation token's `iss`, so no extra key lookup is required.
pub fn verify_member_proof(
    proof_jwt: &str,
    owner_key_id: &str,
    content_id: &str,
    expected_node_id: &str,
    now_secs: u64,
) -> Result<(), MemberProofError> {
    let mut parts = proof_jwt.split('.');
    let header_b64 = parts.next().ok_or(MemberProofError::Malformed)?;
    let payload_b64 = parts.next().ok_or(MemberProofError::Malformed)?;
    let sig_b64 = parts.next().ok_or(MemberProofError::Malformed)?;
    if parts.next().is_some() {
        return Err(MemberProofError::Malformed);
    }

    // 1. Verify the ES256 signature against the owner's public key.
    let verifying_key = verifying_key_from_owner_key_id(owner_key_id)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| MemberProofError::Decode(e.to_string()))?;
    let signature =
        Signature::try_from(sig_bytes.as_slice()).map_err(|_| MemberProofError::BadSignature)?;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| MemberProofError::BadSignature)?;

    // 2. Decode and check claims.
    let payload_json = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| MemberProofError::Decode(e.to_string()))?;
    let claims: Claims = serde_json::from_slice(&payload_json)
        .map_err(|e| MemberProofError::Decode(e.to_string()))?;

    if claims.iss != owner_key_id {
        return Err(MemberProofError::IssuerMismatch);
    }
    if claims.aud != expected_node_id {
        return Err(MemberProofError::AudienceMismatch);
    }
    if now_secs > claims.exp {
        return Err(MemberProofError::Expired);
    }

    let want_with = format!("monas://content/{content_id}");
    let grants_host = claims
        .att
        .iter()
        .any(|c| c.with == want_with && c.can == "host");
    if !grants_host {
        // Distinguish "wrong content" from "wrong capability" for clearer errors.
        if claims.att.iter().any(|c| c.with == want_with) {
            return Err(MemberProofError::NotHostCapability);
        }
        return Err(MemberProofError::ContentMismatch {
            expected: content_id.to_string(),
        });
    }

    Ok(())
}

/// Recover the P-256 verifying key from an owner key_id of the form
/// `user:{hex(SEC1 pubkey)}`.
fn verifying_key_from_owner_key_id(owner_key_id: &str) -> Result<VerifyingKey, MemberProofError> {
    let hex_pk = owner_key_id
        .strip_prefix("user:")
        .ok_or_else(|| MemberProofError::OwnerKey("key_id must start with `user:`".to_string()))?;
    let pk_bytes = hex::decode(hex_pk).map_err(|e| MemberProofError::OwnerKey(e.to_string()))?;
    VerifyingKey::from_sec1_bytes(&pk_bytes).map_err(|e| MemberProofError::OwnerKey(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};

    struct Owner {
        signing: SigningKey,
        key_id: String,
    }

    fn make_owner() -> Owner {
        // Deterministic key for tests.
        let signing = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let vk = VerifyingKey::from(&signing);
        let sec1 = vk.to_encoded_point(false);
        let key_id = format!("user:{}", hex::encode(sec1.as_bytes()));
        Owner { signing, key_id }
    }

    fn issue_proof(owner: &Owner, aud: &str, content_id: &str, can: &str, exp: u64) -> String {
        let header = serde_json::json!({"alg":"ES256","typ":"JWT","ver":"1.0"});
        let payload = serde_json::json!({
            "iss": owner.key_id,
            "aud": aud,
            "exp": exp,
            "iat": 0,
            "jti": "test",
            "att": [{"with": format!("monas://content/{content_id}"), "can": can}],
        });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig: Signature = owner.signing.sign(signing_input.as_bytes());
        let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{signing_input}.{s}")
    }

    #[test]
    fn accepts_valid_proof() {
        let owner = make_owner();
        let jwt = issue_proof(&owner, "node:n1", "content-1", "host", 1000);
        assert!(verify_member_proof(&jwt, &owner.key_id, "content-1", "node:n1", 500).is_ok());
    }

    #[test]
    fn rejects_wrong_owner_key() {
        let owner = make_owner();
        let other = {
            let signing = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
            let vk = VerifyingKey::from(&signing);
            format!(
                "user:{}",
                hex::encode(vk.to_encoded_point(false).as_bytes())
            )
        };
        let jwt = issue_proof(&owner, "node:n1", "content-1", "host", 1000);
        // Verifying against a different owner key must fail the signature check.
        let err = verify_member_proof(&jwt, &other, "content-1", "node:n1", 500).unwrap_err();
        assert!(matches!(err, MemberProofError::BadSignature));
    }

    #[test]
    fn rejects_wrong_node_audience() {
        let owner = make_owner();
        let jwt = issue_proof(&owner, "node:attacker", "content-1", "host", 1000);
        let err =
            verify_member_proof(&jwt, &owner.key_id, "content-1", "node:n1", 500).unwrap_err();
        assert!(matches!(err, MemberProofError::AudienceMismatch));
    }

    #[test]
    fn rejects_wrong_content() {
        let owner = make_owner();
        let jwt = issue_proof(&owner, "node:n1", "other-content", "host", 1000);
        let err =
            verify_member_proof(&jwt, &owner.key_id, "content-1", "node:n1", 500).unwrap_err();
        assert!(matches!(err, MemberProofError::ContentMismatch { .. }));
    }

    #[test]
    fn rejects_non_host_capability() {
        let owner = make_owner();
        let jwt = issue_proof(&owner, "node:n1", "content-1", "read", 1000);
        let err =
            verify_member_proof(&jwt, &owner.key_id, "content-1", "node:n1", 500).unwrap_err();
        assert!(matches!(err, MemberProofError::NotHostCapability));
    }

    #[test]
    fn rejects_expired() {
        let owner = make_owner();
        let jwt = issue_proof(&owner, "node:n1", "content-1", "host", 100);
        let err =
            verify_member_proof(&jwt, &owner.key_id, "content-1", "node:n1", 500).unwrap_err();
        assert!(matches!(err, MemberProofError::Expired));
    }

    #[test]
    fn rejects_tampered_payload() {
        let owner = make_owner();
        let jwt = issue_proof(&owner, "node:n1", "content-1", "host", 1000);
        // Swap the payload for one granting a different node, keeping the sig.
        let mut parts: Vec<&str> = jwt.split('.').collect();
        let forged_payload = serde_json::json!({
            "iss": owner.key_id, "aud": "node:attacker", "exp": 1000, "iat": 0,
            "jti": "x", "att": [{"with":"monas://content/content-1","can":"host"}],
        });
        let forged = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged_payload).unwrap());
        parts[1] = &forged;
        let tampered = parts.join(".");
        let err = verify_member_proof(&tampered, &owner.key_id, "content-1", "node:attacker", 500)
            .unwrap_err();
        assert!(matches!(err, MemberProofError::BadSignature));
    }

    /// **Parity test** against the real monas-account issuer. Confirms a proof
    /// issued by `AccountService::issue_member_proof` is accepted by our
    /// verifier — end-to-end owner-signing ↔ reader-verification agreement.
    #[test]
    fn accepts_proof_issued_by_real_account_service() {
        use monas_account::application_service::command::{IssueMemberProofRequest, KeyTypeMapper};
        use monas_account::application_service::port::{AccountKeyStore, StoredAccountKey};
        use monas_account::application_service::service::AccountService;

        // In-memory account key store for the owner.
        struct MemStore(std::sync::Mutex<Option<StoredAccountKey>>);
        impl AccountKeyStore for MemStore {
            fn save(
                &self,
                key: &StoredAccountKey,
            ) -> Result<(), monas_account::application_service::port::AccountKeyStoreError>
            {
                *self.0.lock().unwrap() = Some(key.clone());
                Ok(())
            }
            fn load(
                &self,
            ) -> Result<
                Option<StoredAccountKey>,
                monas_account::application_service::port::AccountKeyStoreError,
            > {
                Ok(self.0.lock().unwrap().clone())
            }
            fn delete(
                &self,
            ) -> Result<(), monas_account::application_service::port::AccountKeyStoreError>
            {
                *self.0.lock().unwrap() = None;
                Ok(())
            }
        }

        let store = MemStore(std::sync::Mutex::new(None));
        let owner_account = AccountService::create(&store, KeyTypeMapper::P256).unwrap();
        let owner_key_id = format!("user:{}", hex::encode(owner_account.public_key_bytes()));

        let result = AccountService::issue_member_proof(
            &store,
            IssueMemberProofRequest {
                member_node_id: "node:n1".to_string(),
                content_id: "content-1".to_string(),
                ttl_secs: 3600,
            },
        )
        .unwrap();

        // now well within the token's validity window
        verify_member_proof(
            &result.delegated_token,
            &owner_key_id,
            "content-1",
            "node:n1",
            result.issued_at,
        )
        .expect("real account-issued proof should verify");
    }
}
