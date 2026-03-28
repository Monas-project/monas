use crate::application_service::command::{IssueDelegatedTokenRequest, IssueDelegatedTokenResult, KeyTypeMapper};
use crate::application_service::error::{AccountServiceError, IssueDelegatedTokenError, SignError};
use crate::application_service::port::AccountKeyStore;
use crate::domain::account::Account;
use crate::domain::delegation::{DelegatedCapability, DelegationCapabilityClaim, DelegationClaims};
use crate::infrastructure::jwt_signer::sign_es256_jwt_payload;
use crate::infrastructure::key_pair::{KeyAlgorithm, KeyPairGenerateFactory};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct AccountService;

impl AccountService {
    pub fn create<S: AccountKeyStore>(
        store: &S,
        key_type: KeyTypeMapper,
    ) -> Result<Account, AccountServiceError> {
        let algorithm: KeyAlgorithm = key_type.into();
        let generated_key_pair = KeyPairGenerateFactory::generate(algorithm);
        let account = Account::new(generated_key_pair);

        let stored = crate::application_service::StoredAccountKey {
            algorithm,
            public_key: account.public_key_bytes().to_vec(),
            secret_key: account.secret_key_bytes().to_vec(),
        };

        store.save(&stored)?;
        Ok(account)
    }

    pub fn delete<S: AccountKeyStore>(store: &S) -> Result<(), AccountServiceError> {
        store.delete()?;
        Ok(())
    }

    pub fn sign<S: AccountKeyStore>(
        store: &S,
        msg: &[u8],
    ) -> Result<(Vec<u8>, Option<u8>), SignError> {
        let stored = store.load()?.ok_or(SignError::NotFound)?;

        let key_pair = KeyPairGenerateFactory::from_key_bytes(
            stored.algorithm,
            &stored.public_key,
            &stored.secret_key,
        )?;

        let account = Account::new(key_pair);
        Ok(account.sign(msg))
    }

    pub fn issue_delegated_token<S: AccountKeyStore>(
        store: &S,
        req: IssueDelegatedTokenRequest,
    ) -> Result<IssueDelegatedTokenResult, IssueDelegatedTokenError> {
        if req.content_id.trim().is_empty() {
            return Err(IssueDelegatedTokenError::Validation(
                "content_id must not be empty".to_string(),
            ));
        }
        if req.ttl_secs == 0 {
            return Err(IssueDelegatedTokenError::Validation(
                "ttl_secs must be greater than 0".to_string(),
            ));
        }
        const MAX_TTL_SECS: u64 = 24 * 60 * 60;
        if req.ttl_secs > MAX_TTL_SECS {
            return Err(IssueDelegatedTokenError::Validation(format!(
                "ttl_secs must be <= {MAX_TTL_SECS}"
            )));
        }
        if req.capabilities.is_empty() {
            return Err(IssueDelegatedTokenError::Validation(
                "capabilities must not be empty".to_string(),
            ));
        }

        let recipient_key_id = key_id_from_public_key(&req.recipient_public_key);
        let stored = store
            .load()
            .map_err(IssueDelegatedTokenError::KeyStore)?
            .ok_or(IssueDelegatedTokenError::NotFound)?;

        if stored.algorithm != KeyAlgorithm::P256 {
            return Err(IssueDelegatedTokenError::UnsupportedAlgorithm(format!(
                "{:?}",
                stored.algorithm
            )));
        }

        let owner_key_id = key_id_from_public_key(&stored.public_key);
        let now = unix_now_secs()?;
        let expires_at = now.saturating_add(req.ttl_secs);
        let jti = generate_jti();

        let att: Vec<DelegationCapabilityClaim> = req
            .capabilities
            .iter()
            .map(|capability| match capability {
                DelegatedCapability::Read => DelegationCapabilityClaim {
                    with: format!("monas://content/{}", req.content_id),
                    can: "read".to_string(),
                },
                DelegatedCapability::Write => DelegationCapabilityClaim {
                    with: format!("monas://content/{}", req.content_id),
                    can: "write".to_string(),
                },
            })
            .collect();

        let payload = DelegationClaims {
            iss: owner_key_id,
            aud: recipient_key_id,
            exp: expires_at,
            iat: now,
            jti: jti.clone(),
            att,
        };

        let key_pair = KeyPairGenerateFactory::from_key_bytes(
            stored.algorithm,
            &stored.public_key,
            &stored.secret_key,
        )
        .map_err(IssueDelegatedTokenError::InvalidKey)?;
        let account = Account::new(key_pair);
        let delegated_token = sign_es256_jwt_payload(&payload, |signing_input| {
            let (signature, _recovery_id) = account.sign(signing_input);
            Ok(signature)
        })
        .map_err(IssueDelegatedTokenError::JwtSigning)?;

        Ok(IssueDelegatedTokenResult {
            delegated_token,
            issued_at: now,
            expires_at,
            jti,
        })
    }
}

fn unix_now_secs() -> Result<u64, IssueDelegatedTokenError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| IssueDelegatedTokenError::Time(e.to_string()))
}

fn generate_jti() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn key_id_from_public_key(public_key: &[u8]) -> String {
    format!("user:{}", bytes_to_hex(public_key))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(nibble_to_hex((b >> 4) & 0x0f));
        out.push(nibble_to_hex(b & 0x0f));
    }
    out
}

fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::AccountService;
    use crate::application_service::{
        IssueDelegatedTokenError, IssueDelegatedTokenRequest, KeyTypeMapper, SignError,
    };
    use crate::domain::delegation::{DelegatedCapability, DelegationClaims};
    use crate::infrastructure::key_store::InMemoryAccountKeyStore;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    #[test]
    fn create_k256_stores_valid_account() {
        let store = InMemoryAccountKeyStore::default();
        let account = AccountService::create(&store, KeyTypeMapper::K256).unwrap();
        assert_eq!(account.public_key_bytes().len(), 65);
        assert_eq!(account.secret_key_bytes().len(), 32);
    }

    #[test]
    fn create_p256_stores_valid_account() {
        let store = InMemoryAccountKeyStore::default();
        let account = AccountService::create(&store, KeyTypeMapper::P256).unwrap();
        assert_eq!(account.public_key_bytes().len(), 65);
        assert_eq!(account.secret_key_bytes().len(), 32);
    }

    #[test]
    fn sign_uses_stored_key() {
        let store = InMemoryAccountKeyStore::default();
        let account = AccountService::create(&store, KeyTypeMapper::K256).unwrap();
        let msg = b"sign-test-message";
        let (sig_from_service, _rec_id1) = AccountService::sign(&store, msg).unwrap();
        let (sig_from_account, _rec_id2) = account.sign(msg);
        assert_eq!(sig_from_service, sig_from_account);
    }

    #[test]
    fn sign_uses_stored_key_p256() {
        let store = InMemoryAccountKeyStore::default();
        let account = AccountService::create(&store, KeyTypeMapper::P256).unwrap();
        let msg = b"sign-test-message-p256";
        let (sig_from_service, _rec_id1) = AccountService::sign(&store, msg).unwrap();
        let (sig_from_account, _rec_id2) = account.sign(msg);
        assert_eq!(sig_from_service, sig_from_account);
    }

    #[test]
    fn sign_uses_latest_created_key() {
        let store = InMemoryAccountKeyStore::default();
        AccountService::create(&store, KeyTypeMapper::K256).unwrap();
        let msg = b"override-test-message";
        let account_latest = AccountService::create(&store, KeyTypeMapper::P256).unwrap();
        let (sig_from_service, _rec_id1) = AccountService::sign(&store, msg).unwrap();
        let (sig_from_latest, _rec_id2) = account_latest.sign(msg);
        assert_eq!(sig_from_service, sig_from_latest);
    }

    #[test]
    fn sign_returns_not_found_if_key_missing() {
        let store = InMemoryAccountKeyStore::default();
        let err = AccountService::sign(&store, b"msg").unwrap_err();
        assert!(matches!(err, SignError::NotFound));
    }

    #[test]
    fn delete_removes_stored_key() {
        let store = InMemoryAccountKeyStore::default();
        AccountService::create(&store, KeyTypeMapper::K256).unwrap();
        AccountService::delete(&store).unwrap();
        let err = AccountService::sign(&store, b"after-delete").unwrap_err();
        assert!(matches!(err, SignError::NotFound));
    }

    #[test]
    fn issue_delegated_token_succeeds_with_p256() {
        let owner_store = InMemoryAccountKeyStore::default();
        let recipient_store = InMemoryAccountKeyStore::default();
        let recipient_account = AccountService::create(&recipient_store, KeyTypeMapper::P256).unwrap();
        AccountService::create(&owner_store, KeyTypeMapper::P256).unwrap();

        let req = IssueDelegatedTokenRequest {
            recipient_public_key: recipient_account.public_key_bytes().to_vec(),
            content_id: "cid-123".to_string(),
            capabilities: vec![DelegatedCapability::Read, DelegatedCapability::Write],
            ttl_secs: 3600,
        };

        let issued = AccountService::issue_delegated_token(&owner_store, req).unwrap();
        assert!(!issued.delegated_token.is_empty());
        assert!(issued.expires_at > issued.issued_at);
        assert!(!issued.jti.is_empty());
        let parts: Vec<&str> = issued.delegated_token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: DelegationClaims = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload.att.len(), 2);
        assert_eq!(payload.att[0].with, "monas://content/cid-123");
        assert_eq!(payload.att[0].can, "read");
        assert_eq!(payload.att[1].can, "write");
    }

    #[test]
    fn issue_delegated_token_fails_with_k256_owner_key() {
        let owner_store = InMemoryAccountKeyStore::default();
        let recipient_store = InMemoryAccountKeyStore::default();
        let recipient_account = AccountService::create(&recipient_store, KeyTypeMapper::P256).unwrap();
        AccountService::create(&owner_store, KeyTypeMapper::K256).unwrap();

        let req = IssueDelegatedTokenRequest {
            recipient_public_key: recipient_account.public_key_bytes().to_vec(),
            content_id: "cid-123".to_string(),
            capabilities: vec![DelegatedCapability::Read],
            ttl_secs: 3600,
        };

        let err = AccountService::issue_delegated_token(&owner_store, req).unwrap_err();
        assert!(matches!(err, IssueDelegatedTokenError::UnsupportedAlgorithm(_)));
    }
}
