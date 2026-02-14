# monas-state-node 認証・認可実装計画

## 0. 前提条件・参照ドキュメント

### 0.1 ブランチ情報
- **ブランチ**: `feature/soma/state-node-sync`
- **ベース**: `main`
- **関連PR**: PR #23 (認証・認可基盤)

### 0.2 参照ドキュメント
- **ShareToken設計書**: [Notion - ShareToken ベース Share機能設計書](https://www.notion.so/ShareToken-Share-2e4df72f09c2811a9420f07162682842)
- **実装計画**: `pr-23-implementation-plan.md`
- **UCAN設計**: `ucan-share-design.md`

**重要な設計決定**: 他の機能でHPKEを使用しているため、署名アルゴリズムは **P256 (ES256) のみ**に統一します。K256 (ES256K) はサポートしません。

### 0.3 現在の実装状態

**既存ファイル**:
```
monas-state-node/src/
├── infrastructure/auth/
│   ├── monas_account_adapter.rs   (✅ 存在: DID検証のみ、署名検証なし)
│   └── ucan_adapter.rs             (✅ 存在: AccessPolicy検証のみ、ShareToken未対応)
├── domain/
│   ├── identity.rs                 (✅ 存在)
│   ├── auth_capability.rs          (✅ 存在)
│   └── access_policy.rs            (✅ 存在)
├── port/
│   ├── authentication_service.rs   (✅ 存在)
│   └── authorization_service.rs    (✅ 存在: AuthorizationRequest定義あり)
└── presentation/
    └── http_api.rs                 (✅ 存在: Authorizationヘッダー抽出済み)
```

**未実装**:
- ShareToken構造とJWT解析
- 署名検証ロジック
- リクエスト署名の検証
- テスト用ヘルパー

### 0.4 既存の型定義

```rust
// src/domain/identity.rs
pub struct Identity {
    id: String,           // DID形式: "did:monas:user:alice"
    identity_type: IdentityType,
}

pub enum IdentityType {
    User,
    Node,
    Service,
}

// src/domain/auth_capability.rs
#[derive(Clone, Debug, PartialEq)]
pub enum AuthCapability {
    ReadContent,
    WriteContent,
    DeleteContent,
    ManageMembers,
    ShareContent,
    RevokeAccess,
    ReadMetadata,
}

// src/port/authorization_service.rs (現在の定義)
pub struct AuthorizationRequest {
    pub identity: Identity,
    pub resource: ContentId,
    pub capability: AuthCapability,
    pub token: Option<AuthToken>,
    // request_signature: 追加予定
}

pub enum AuthorizationResult {
    Granted,
    Denied { reason: String },
}

// src/domain/value_objects.rs
pub struct ContentId(String);
```

## 1. 概要

本ブランチ（feature/soma/state-node-sync）では、**monas-state-nodeの変更のみ**で認証・認可機能を実装する。
将来的にはmonas-identityクレートとして分離することを想定しているが、現時点ではE2Eテストと実機テストを可能にすることを優先する。

### 1.1 目標

- ✅ HTTP API経由でのShareToken検証を実装
- ✅ 2種類の署名検証（ShareToken署名 + リクエスト署名）を実装
- ✅ テスト用の鍵生成・署名ヘルパーを実装
- ✅ E2Eテストの実行を可能にする
- ✅ 本番用コードとテストコードを明確に分離
- ✅ P256 (ES256) のみをサポート（HPKEとの統合を考慮）

### 1.2 スコープ外

- ❌ monas-accountクレートの変更
- ❌ monas-contentクレートの変更
- ❌ 委任（proof chain）の実装（Phase 1では実装しない）
- ❌ UCANの完全な仕様準拠（将来的な課題）
- ❌ K256 (ES256K) のサポート（P256/ES256のみに統一）

## 2. アーキテクチャ

### 2.1 モジュール構成

```
monas-state-node/
├── src/
│   ├── infrastructure/auth/
│   │   ├── mod.rs
│   │   ├── monas_account_adapter.rs      (既存)
│   │   ├── ucan_adapter.rs                (既存)
│   │   ├── share_token.rs                 (新規: ShareToken構造・検証)
│   │   ├── signature_verifier.rs          (新規: 署名検証ロジック)
│   │   └── test_helpers.rs                (新規: テスト用ヘルパー)
│   ├── presentation/
│   │   └── http_api.rs                    (拡張: リクエスト署名検証)
│   └── tests/
│       └── integration/
│           └── auth_e2e_test.rs           (新規: E2Eテスト)
```

### 2.2 データフロー

#### 認証フロー（Authentication）
```
Client Request
  └─> Authorization: Bearer <DID>
      └─> MonasAccountAdapter::authenticate()
          └─> DID検証（フォーマット確認）
              └─> Identity返却
```

**Phase 1**: DIDフォーマット検証のみ（署名検証は未実装）

#### 認可フロー（Authorization with ShareToken）
```
Client Request
  ├─> Authorization: Bearer <DID>
  ├─> X-Share-Token: <ShareToken JWT>
  └─> X-Request-Signature: <Signature>
      └─> UcanAdapter::authorize()
          ├─> 1. ShareToken解析
          ├─> 2. ShareToken署名検証（Owner = iss の公開鍵）
          ├─> 3. リクエスト署名検証（Requester の公開鍵）
          ├─> 4. aud一致確認（Requester == ShareToken.aud）
          ├─> 5. 有効期限確認
          ├─> 6. バージョン確認（iat >= min_valid_issued_at）
          └─> 7. Capability確認
              └─> AuthorizationResult返却
```

## 3. 実装タスク

### Phase 1: 基本構造の実装 (P0 - Critical)

#### Task 1.1: ShareToken データ構造
**ファイル**: `src/infrastructure/auth/share_token.rs`

**JWT形式の具体例**:
```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsInZlciI6IjEuMCJ9.eyJpc3MiOiJkaWQ6bW9uYXM6dXNlcjphbGljZSIsImF1ZCI6ImRpZDptb25hczp1c2VyOmJvYiIsImV4cCI6MTcwNjc0NDQwMCwiaWF0IjoxNzA2NzQwODAwLCJqdGkiOiI1NTBlNjFmNy05OGUwLTQ1YzMtYjI4Yy0xZjhkNzJhNmU2YzQiLCJhdHQiOlt7IndpdGgiOiJtb25hczovL2NvbnRlbnQvYWJjMTIzIiwiY2FuIjoiUmVhZCJ9XSwiZmN0IjpudWxsfQ.MEUCIQDxxx...
```

↓ デコードすると ↓

**Header**:
```json
{
  "alg": "ES256",
  "typ": "JWT",
  "ver": "1.0"
}
```

**Payload**:
```json
{
  "iss": "did:monas:user:alice",
  "aud": "did:monas:user:bob",
  "exp": 1706744400,
  "iat": 1706740800,
  "jti": "550e61f7-98e0-45c3-b28c-1f8d72a6e6c4",
  "att": [
    {
      "with": "monas://content/abc123",
      "can": "Read"
    }
  ],
  "fct": null
}
```

**Signature**: (base64url-encoded ECDSA signature)

---

```rust
use serde::{Deserialize, Serialize};
use anyhow::{Context, Result};

/// ShareToken のヘッダー
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareTokenHeader {
    pub alg: String,  // "ES256" (P256)
    pub typ: String,  // "JWT"
    pub ver: String,  // "1.0"
}

/// ShareToken のペイロード
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareTokenPayload {
    pub iss: String,           // 発行者のKeyId（DID形式）
    pub aud: String,           // 受信者のKeyId（DID形式）
    pub exp: Option<u64>,      // 有効期限（Unix timestamp）
    pub iat: u64,              // 発行日時（Unix timestamp）
    pub jti: String,           // 一意識別子（UUID v4）
    pub att: Vec<Capability>,  // 権限リスト
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fct: Option<serde_json::Value>,  // 事実情報
}

/// 単一の権限定義
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub with: String,           // リソース "monas://content/{id}"
    pub can: CapabilityAction,  // アクション
}

/// アクション種別（ShareToken用）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CapabilityAction {
    Read,
    Write,
    Delete,
    Share,
    Revoke,
    Reencrypt,
}

/// AuthCapability（既存）からCapabilityAction（ShareToken）へのマッピング
impl CapabilityAction {
    pub fn from_auth_capability(cap: &crate::domain::auth_capability::AuthCapability) -> Self {
        use crate::domain::auth_capability::AuthCapability;
        match cap {
            AuthCapability::ReadContent | AuthCapability::ReadMetadata => Self::Read,
            AuthCapability::WriteContent => Self::Write,
            AuthCapability::DeleteContent => Self::Delete,
            AuthCapability::ShareContent => Self::Share,
            AuthCapability::RevokeAccess => Self::Revoke,
            AuthCapability::ManageMembers => Self::Share, // ManageMembersはShareに相当
        }
    }

    pub fn to_auth_capability(&self) -> crate::domain::auth_capability::AuthCapability {
        use crate::domain::auth_capability::AuthCapability;
        match self {
            Self::Read => AuthCapability::ReadContent,
            Self::Write => AuthCapability::WriteContent,
            Self::Delete => AuthCapability::DeleteContent,
            Self::Share => AuthCapability::ShareContent,
            Self::Revoke => AuthCapability::RevokeAccess,
            Self::Reencrypt => AuthCapability::ManageMembers, // 暫定マッピング
        }
    }
}

/// ShareToken 本体
pub struct ShareToken {
    pub header: ShareTokenHeader,
    pub payload: ShareTokenPayload,
    pub signature: Vec<u8>,  // 署名（バイナリ形式）
}

impl ShareToken {
    /// JWT文字列からパース
    ///
    /// # Format
    /// `<base64url(header)>.<base64url(payload)>.<base64url(signature)>`
    pub fn from_jwt(jwt: &str) -> Result<Self> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            anyhow::bail!("Invalid JWT format: expected 3 parts, got {}", parts.len());
        }

        // Base64url decode
        let header_bytes = base64::decode_config(parts[0], base64::URL_SAFE_NO_PAD)
            .context("Failed to decode header")?;
        let payload_bytes = base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD)
            .context("Failed to decode payload")?;
        let signature = base64::decode_config(parts[2], base64::URL_SAFE_NO_PAD)
            .context("Failed to decode signature")?;

        // JSON parse
        let header: ShareTokenHeader = serde_json::from_slice(&header_bytes)
            .context("Failed to parse header JSON")?;
        let payload: ShareTokenPayload = serde_json::from_slice(&payload_bytes)
            .context("Failed to parse payload JSON")?;

        Ok(Self {
            header,
            payload,
            signature,
        })
    }

    /// JWT文字列にエンコード
    pub fn to_jwt(&self) -> Result<String> {
        // JSON serialize
        let header_json = serde_json::to_string(&self.header)?;
        let payload_json = serde_json::to_string(&self.payload)?;

        // Base64url encode
        let header_b64 = base64::encode_config(header_json.as_bytes(), base64::URL_SAFE_NO_PAD);
        let payload_b64 = base64::encode_config(payload_json.as_bytes(), base64::URL_SAFE_NO_PAD);
        let signature_b64 = base64::encode_config(&self.signature, base64::URL_SAFE_NO_PAD);

        Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
    }

    /// 署名対象メッセージ（header.payload）を取得
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        let header_json = serde_json::to_string(&self.header)?;
        let payload_json = serde_json::to_string(&self.payload)?;

        let header_b64 = base64::encode_config(header_json.as_bytes(), base64::URL_SAFE_NO_PAD);
        let payload_b64 = base64::encode_config(payload_json.as_bytes(), base64::URL_SAFE_NO_PAD);

        Ok(format!("{}.{}", header_b64, payload_b64).into_bytes())
    }
}

/// エラー型
#[derive(Debug, thiserror::Error)]
pub enum ShareTokenError {
    #[error("Invalid JWT format: {0}")]
    InvalidFormat(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Token expired (exp: {exp}, now: {now})")]
    Expired { exp: u64, now: u64 },

    #[error("Token invalidated (iat: {iat}, min_valid: {min_valid})")]
    Invalidated { iat: u64, min_valid: u64 },

    #[error("Audience mismatch (expected: {expected}, got: {got})")]
    AudienceMismatch { expected: String, got: String },

    #[error("Insufficient capability (required: {required:?}, granted: {granted:?})")]
    InsufficientCapability {
        required: CapabilityAction,
        granted: Vec<CapabilityAction>,
    },

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
```

**依存関係**:
- `base64` (既存) - JWT エンコード/デコード用
- `serde` (既存) - JSON シリアライゼーション用
- `serde_json` (既存)
- `thiserror` (既存) - エラー型定義用

---

#### Task 1.2: 署名検証ロジック
**ファイル**: `src/infrastructure/auth/signature_verifier.rs`

```rust
use anyhow::{Context, Result};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use super::share_token::{ShareToken, ShareTokenError};

pub struct SignatureVerifier;

impl SignatureVerifier {
    /// ShareToken署名を検証（Owner = issの公開鍵で検証）
    ///
    /// # Arguments
    /// * `token` - 検証するShareToken
    /// * `owner_public_key` - Ownerの公開鍵（uncompressed形式、65バイト）
    pub fn verify_share_token_signature(
        token: &ShareToken,
        owner_public_key: &[u8],
    ) -> Result<()> {
        let message = token.signing_message()?;

        // P256署名検証
        let verifying_key = VerifyingKey::from_sec1_bytes(owner_public_key)
            .context("Invalid P256 public key")?;
        let signature = Signature::from_slice(&token.signature)
            .context("Invalid P256 signature format")?;

        verifying_key
            .verify(&message, &signature)
            .map_err(|e| ShareTokenError::SignatureVerificationFailed(e.to_string()))?;

        Ok(())
    }

    /// リクエスト署名を検証（Requesterの公開鍵で検証）
    ///
    /// # Arguments
    /// * `message` - 署名対象メッセージ
    /// * `signature` - 署名（DER形式またはraw形式）
    /// * `requester_public_key` - Requesterの公開鍵（uncompressed形式、65バイト）
    pub fn verify_request_signature(
        message: &[u8],
        signature: &[u8],
        requester_public_key: &[u8],
    ) -> Result<()> {
        let verifying_key = VerifyingKey::from_sec1_bytes(requester_public_key)
            .context("Invalid P256 public key")?;
        let sig = Signature::from_slice(signature)
            .context("Invalid P256 signature format")?;

        verifying_key
            .verify(message, &sig)
            .map_err(|e| ShareTokenError::SignatureVerificationFailed(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_share_token_signature() {
        // P256署名検証のテスト
        // 実装時にテストケースを追加
    }
}
```

**公開鍵フォーマット**:
- **Uncompressed形式**: `0x04` + X座標(32バイト) + Y座標(32バイト) = 65バイト
- monas-accountから取得する公開鍵はこの形式

**依存関係**:
- `p256 = { version = "0.13", features = ["ecdsa"] }` (既存) - ES256署名検証

---

#### Task 1.3: UcanAdapter拡張
**ファイル**: `src/infrastructure/auth/ucan_adapter.rs`

**変更内容**:

1. **ShareToken解析・検証メソッド追加**:
```rust
impl<R> UcanAdapter<R> {
    /// ShareTokenをJWT文字列から解析
    fn parse_share_token(&self, jwt: &str) -> Result<ShareToken>;

    /// ShareToken署名検証（2段階）
    async fn verify_share_token(
        &self,
        token: &ShareToken,
        request_signature: &[u8],
        requester_did: &str,
    ) -> Result<()> {
        // アルゴリズム確認（ES256のみサポート）
        if token.header.alg != "ES256" {
            return Err(anyhow::anyhow!("Unsupported algorithm: {}", token.header.alg));
        }

        // 1. Owner署名検証（issの公開鍵で検証）
        let owner_pubkey = self.get_public_key(&token.payload.iss).await?;
        SignatureVerifier::verify_share_token_signature(token, &owner_pubkey)?;

        // 2. リクエスト署名検証（Requesterの公開鍵で検証）
        let requester_pubkey = self.get_public_key(requester_did).await?;
        let message = self.build_request_message(token)?;
        SignatureVerifier::verify_request_signature(&message, request_signature, &requester_pubkey)?;

        // 3. aud一致確認
        if token.payload.aud != requester_did {
            return Err(anyhow::anyhow!("Audience mismatch"));
        }

        Ok(())
    }

    /// 公開鍵取得（Phase 1: モックまたはハードコード）
    async fn get_public_key(&self, did: &str) -> Result<Vec<u8>>;

    /// リクエストメッセージ構築
    fn build_request_message(&self, token: &ShareToken) -> Result<Vec<u8>>;
}
```

2. **既存メソッドの更新**:
```rust
async fn authorize(&self, request: &AuthorizationRequest) -> Result<AuthorizationResult> {
    // ... 既存のポリシーチェック ...

    // ShareToken検証（新規追加）
    if let Some(token) = &request.token {
        let share_token = self.parse_share_token(token.as_str())?;

        // 2段階署名検証
        if let Some(req_sig) = &request.request_signature {
            self.verify_share_token(
                &share_token,
                req_sig,
                request.identity.id(),
            ).await?;
        } else {
            return Ok(AuthorizationResult::Denied {
                reason: "Request signature required".to_string(),
            });
        }

        // 有効期限確認
        if let Some(exp) = share_token.payload.exp {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            if now > exp {
                return Ok(AuthorizationResult::Denied {
                    reason: "Token expired".to_string(),
                });
            }
        }

        // バージョンチェック（min_valid_issued_at）
        let min_valid = self.get_min_valid_issued_at(&request.resource).await?;
        if let Some(min) = min_valid {
            if share_token.payload.iat < min {
                return Ok(AuthorizationResult::Denied {
                    reason: "Token invalidated".to_string(),
                });
            }
        }

        // Capability確認
        let has_capability = self.check_capability(
            &share_token,
            &request.resource,
            &request.capability,
        )?;

        if has_capability {
            return Ok(AuthorizationResult::Granted);
        }
    }

    // ... 既存のロジック ...
}
```

---

#### Task 1.4: HTTP API拡張
**ファイル**: `src/presentation/http_api.rs`

**変更内容**:

1. **リクエスト署名の抽出**:
```rust
fn extract_request_signature(headers: &HeaderMap) -> Option<Vec<u8>> {
    let sig_header = headers.get("x-request-signature")?.to_str().ok()?;
    base64::decode(sig_header).ok()
}
```

2. **AuthorizationRequestに署名を追加**:
```rust
// domain/auth_capability.rsまたはport/authorization_service.rsを更新
pub struct AuthorizationRequest {
    pub identity: Identity,
    pub resource: ContentId,
    pub capability: AuthCapability,
    pub token: Option<AuthToken>,
    pub request_signature: Option<Vec<u8>>,  // 新規追加
}
```

3. **ハンドラーの更新**:
```rust
async fn update_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpdateContentRequest>,
) -> impl IntoResponse {
    let token = extract_auth_token(&headers);
    let request_signature = extract_request_signature(&headers);  // 新規

    match state.update_content(&data, token.as_ref(), request_signature).await {
        // ...
    }
}
```

---

### Phase 2: テスト用ヘルパー実装 (P0 - Critical)

#### Task 2.1: テスト用鍵生成・署名
**ファイル**: `src/infrastructure/auth/test_helpers.rs`

```rust
#[cfg(test)]
pub mod test_helpers {
    use p256::{ecdsa::SigningKey, SecretKey};
    use rand::rngs::OsRng;
    use crate::infrastructure::auth::share_token::*;

    pub struct TestKeyPair {
        secret_key: SigningKey,
        public_key_bytes: Vec<u8>,
        did: String,
    }

    impl TestKeyPair {
        /// P256鍵ペアを生成
        pub fn generate(identity_type: &str, name: &str) -> Self {
            let secret = SecretKey::random(&mut OsRng);
            let signing_key = SigningKey::from(secret);
            let verifying_key = signing_key.verifying_key();
            let public_key_bytes = verifying_key
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();

            let did = format!("did:monas:{}:{}", identity_type, name);

            Self {
                secret_key: signing_key,
                public_key_bytes,
                did,
            }
        }

        pub fn did(&self) -> &str {
            &self.did
        }

        pub fn public_key(&self) -> &[u8] {
            &self.public_key_bytes
        }

        /// メッセージに署名（P256/ES256）
        pub fn sign(&self, message: &[u8]) -> Vec<u8> {
            use p256::ecdsa::signature::Signer;
            self.secret_key.sign(message).to_vec()
        }

        /// ShareToken生成
        pub fn create_share_token(
            &self,
            recipient: &TestKeyPair,
            resource: &str,
            capabilities: Vec<CapabilityAction>,
            expires_in_secs: Option<u64>,
        ) -> ShareToken {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let header = ShareTokenHeader {
                alg: "ES256".to_string(),
                typ: "JWT".to_string(),
                ver: "1.0".to_string(),
            };

            let payload = ShareTokenPayload {
                iss: self.did.clone(),
                aud: recipient.did.clone(),
                exp: expires_in_secs.map(|s| now + s),
                iat: now,
                jti: uuid::Uuid::new_v4().to_string(),
                att: capabilities.iter().map(|cap| Capability {
                    with: resource.to_string(),
                    can: cap.clone(),
                }).collect(),
                fct: None,
            };

            // 署名
            let mut token = ShareToken {
                header,
                payload,
                signature: Vec::new(),
            };
            let message = token.signing_message().unwrap();
            token.signature = self.sign(&message);

            token
        }

        /// リクエスト署名生成
        pub fn sign_request(&self, share_token: &ShareToken) -> Vec<u8> {
            let message = format!(
                "{}:{}:{}",
                share_token.payload.iss,
                share_token.payload.aud,
                share_token.payload.jti
            );
            self.sign(message.as_bytes())
        }
    }

    /// テスト用公開鍵リポジトリ（モック）
    pub struct TestPublicKeyRepository {
        keys: std::collections::HashMap<String, Vec<u8>>,
    }

    impl TestPublicKeyRepository {
        pub fn new() -> Self {
            Self {
                keys: std::collections::HashMap::new(),
            }
        }

        pub fn register(&mut self, did: &str, public_key: Vec<u8>) {
            self.keys.insert(did.to_string(), public_key);
        }

        pub fn get(&self, did: &str) -> Option<&Vec<u8>> {
            self.keys.get(did)
        }
    }
}
```

---

### Phase 3: E2Eテスト実装 (P1 - High)

#### Task 3.1: 認証・認可E2Eテスト
**ファイル**: `src/tests/integration/auth_e2e_test.rs`

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::auth::test_helpers::test_helpers::*;

    #[tokio::test]
    async fn test_content_creation_with_authentication() {
        // 1. テスト用鍵ペア生成
        let alice = TestKeyPair::generate("user", "alice");

        // 2. アプリケーション起動
        let app = create_test_app().await;

        // 3. 認証トークン（DID）でコンテンツ作成
        let response = app
            .post("/contents")
            .header("Authorization", format!("Bearer {}", alice.did()))
            .json(&json!({
                "data": "test content"
            }))
            .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_share_token_authorization_success() {
        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");

        // 公開鍵をモックリポジトリに登録
        let mut key_repo = TestPublicKeyRepository::new();
        key_repo.register(alice.did(), alice.public_key().to_vec());
        key_repo.register(bob.did(), bob.public_key().to_vec());

        let app = create_test_app_with_key_repo(key_repo).await;

        // 1. Aliceがコンテンツ作成
        let create_response = app
            .post("/contents")
            .header("Authorization", format!("Bearer {}", alice.did()))
            .json(&json!({"data": "shared content"}))
            .await;
        let content_id = create_response.json::<CreateContentResponse>()
            .await
            .content_id;

        // 2. AliceがShareToken発行（Bobに読み取り権限）
        let share_token = alice.create_share_token(
            &bob,
            &format!("monas://content/{}", content_id),
            vec![CapabilityAction::Read],
            Some(3600), // 1時間有効
        );

        // 3. Bobがリクエスト署名を生成
        let request_signature = bob.sign_request(&share_token);

        // 4. BobがShareTokenを使ってコンテンツ取得
        let response = app
            .get(&format!("/contents/{}", content_id))
            .header("Authorization", format!("Bearer {}", bob.did()))
            .header("X-Share-Token", share_token.to_jwt())
            .header("X-Request-Signature", base64::encode(&request_signature))
            .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_share_token_invalid_signature() {
        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");
        let eve = TestKeyPair::generate("user", "eve");

        // Eveが偽造したShareToken（Alice署名を偽造）
        let mut fake_token = alice.create_share_token(
            &bob,
            "monas://content/123",
            vec![CapabilityAction::Read],
            Some(3600),
        );
        fake_token.signature = vec![0u8; 64]; // 偽の署名

        let request_signature = bob.sign_request(&fake_token);

        let response = app
            .get("/contents/123")
            .header("Authorization", format!("Bearer {}", bob.did()))
            .header("X-Share-Token", fake_token.to_jwt())
            .header("X-Request-Signature", base64::encode(&request_signature))
            .await;

        // 署名検証失敗
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_share_token_expired() {
        // 有効期限切れのトークンでアクセス → 403
    }

    #[tokio::test]
    async fn test_share_token_invalidated_by_version() {
        // min_valid_issued_atより古いトークンでアクセス → 403
    }
}
```

---

### Phase 4: Cargo.toml確認 (P0 - Critical)

#### Task 4.1: 依存関係確認

**既存の依存関係**:
```toml
[dependencies]
p256 = { version = "0.13", features = ["ecdsa"] }  # ES256署名検証に使用
```

**注意**: P256 (ES256) のみをサポートするため、新規依存関係の追加は不要です。

---

## 4. 実装順序

### Week 1
- [ ] Task 1.1: ShareToken データ構造
- [ ] Task 1.2: 署名検証ロジック（P256のみ）
- [ ] Task 4.1: Cargo.toml確認（p256依存関係の確認）

### Week 2
- [ ] Task 2.1: テスト用ヘルパー実装
- [ ] Task 1.3: UcanAdapter拡張（基本部分）

### Week 3
- [ ] Task 1.4: HTTP API拡張
- [ ] Task 3.1: E2Eテスト実装

### Week 4
- [ ] テスト修正・デバッグ
- [ ] ドキュメント更新

---

## 5. テスト戦略

### 5.1 ユニットテスト
- `share_token.rs`: JWT解析・エンコード
- `signature_verifier.rs`: 署名検証（P256/ES256）
- `ucan_adapter.rs`: ShareToken検証ロジック

### 5.2 統合テスト
- E2Eテスト（`auth_e2e_test.rs`）
  - 正常系: 認証成功 → 認可成功 → コンテンツアクセス
  - 異常系: 署名不正、有効期限切れ、権限不足

### 5.3 手動テスト（実機）
```bash
# 1. State Node起動
cargo run --bin state-node

# 2. テスト用鍵ペア生成（CLIツール作成予定）
cargo run --bin generate-test-key

# 3. curlでAPIテスト
curl -X POST http://localhost:8080/contents \
  -H "Authorization: Bearer did:monas:user:alice" \
  -H "Content-Type: application/json" \
  -d '{"data": "test"}'
```

---

## 6. 制限事項・TODO

### Phase 1で実装しない機能
- ❌ 委任（proof chain）: `prf`フィールドは定義するが検証しない
- ❌ DID Document解決: 公開鍵はハードコードまたはモックリポジトリから取得
- ❌ 完全なUCAN仕様準拠: 最小限の実装
- ❌ Revocation list: バージョンベース（min_valid_issued_at）のみ

### 将来的な課題
- monas-identityクレートへの分離
- monas-accountとの統合（DID Document、公開鍵管理）
- DID Registry実装
- 委任チェーン検証
- より細かいCapabilityチェック（リソースパターンマッチング）
- K256 (ES256K) サポート（必要に応じて検討）

---

## 7. 成功基準

- ✅ E2Eテストが全てパス
- ✅ HTTP API経由で認証・認可が動作
- ✅ 2種類の署名検証（ShareToken + Request）が動作
- ✅ 不正なトークンを検出できる
- ✅ 有効期限切れトークンを拒否できる
- ✅ バージョンベース無効化が動作

---

## 8. レビューポイント

### セキュリティ
- [ ] 署名検証が確実に行われているか
- [ ] 公開鍵の取得方法は安全か（モック実装の範囲を明確に）
- [ ] タイミング攻撃に対する考慮（署名検証の定数時間性）

### コード品質
- [ ] エラーハンドリングが適切か
- [ ] テストコードが`#[cfg(test)]`で明確に分離されているか
- [ ] 本番コードにテスト用ロジックが混入していないか

### パフォーマンス
- [ ] 署名検証のオーバーヘッドは許容範囲か
- [ ] 公開鍵キャッシュの必要性

---

## 9. min_valid_issued_at の保存場所

**設計**:
- AccessPolicyに`min_valid_issued_at: Option<u64>`フィールドを追加
- sled（既存の永続化層）に保存

**変更箇所**:
```rust
// src/domain/access_policy.rs
pub struct AccessPolicy {
    content_id: ContentId,
    owner: Identity,
    grants: HashMap<Identity, Vec<AuthCapability>>,
    min_valid_issued_at: Option<u64>,  // 新規追加
}

impl AccessPolicy {
    pub fn invalidate_all_tokens(&mut self, at_time: u64) {
        self.min_valid_issued_at = Some(at_time);
    }

    pub fn min_valid_issued_at(&self) -> Option<u64> {
        self.min_valid_issued_at
    }
}
```

## 10. クイックスタートガイド（他のセッション向け）

このセクションは、別セッションで実装を開始する際の手順です。

### Step 1: 環境準備
```bash
# ブランチ確認
git branch
# => * feature/soma/state-node-sync

# 最新の状態を確認
git status
cargo check -p monas-state-node
```

### Step 2: 実装順序（推奨）
1. **Week 1**: Task 1.1 (ShareToken) → Task 1.2 (署名検証/P256のみ) → Task 4.1 (Cargo.toml確認)
2. **Week 2**: Task 2.1 (テストヘルパー) → Task 1.3 (UcanAdapter)
3. **Week 3**: Task 1.4 (HTTP API) → Task 3.1 (E2Eテスト)

### Step 3: 各タスク開始時のチェックリスト
- [ ] セクション「0.3 現在の実装状態」で既存ファイルを確認
- [ ] セクション「0.4 既存の型定義」を読んで既存の構造体を理解
- [ ] 該当タスクのコード例をコピー＆ペーストせず、理解しながら実装
- [ ] コンパイルエラーが出たら、既存の型定義と照らし合わせる
- [ ] テストを書いてから実装（TDD推奨）

### Step 4: 困ったときの参照先
- **ShareTokenの設計**: [Notion設計書](https://www.notion.so/ShareToken-Share-2e4df72f09c2811a9420f07162682842)
- **JWTの具体例**: Task 1.1のJWT形式の具体例を参照
- **署名検証の詳細**: Task 1.2の実装例を参照
- **既存コードとの統合**: セクション0.4の型定義を参照

### Step 5: 実装完了後の確認
- [ ] `cargo check -p monas-state-node` がパス
- [ ] `cargo test -p monas-state-node --lib` がパス
- [ ] E2Eテスト（Task 3.1）が実行できる
- [ ] 手動テスト（curlコマンド）でAPIが動作する

## 11. 次のステップ（このブランチ外）

1. **monas-identityクレート作成**
   - 本実装をベースに独立クレートとして分離
   - monas-accountと統合

2. **monas-content統合**
   - ShareService実装
   - KeyEnvelope生成

3. **委任機能実装**
   - proof chain検証
   - 権限減衰（attenuation）

4. **DID Registry実装**
   - DID Document管理
   - 公開鍵解決

---

## 付録A: よくある質問（FAQ）

### Q1: なぜJWT形式なのか？
A: UCAN仕様がJWTベースであり、将来的な互換性のため。

### Q2: 認証と認可の違いは？
A:
- **認証**: 「誰か」を確認（DID検証）
- **認可**: 「何ができるか」を確認（ShareToken + Capability）

### Q3: なぜ2種類の署名検証が必要？
A:
1. ShareToken署名: Ownerが本当にこのトークンを発行したか
2. リクエスト署名: リクエスト送信者がトークンのaudと一致するか

### Q4: テスト用ヘルパーと本番コードの分離方法は？
A: `#[cfg(test)]`を使用。テストヘルパーは`src/infrastructure/auth/test_helpers.rs`に配置。

### Q5: 公開鍵はどこから取得する？
A: Phase 1ではテスト用モックリポジトリ。将来的にはmonas-accountのDID Registryから取得。

---

## 付録B: トラブルシューティング

### エラー: "Invalid JWT format"
- JWT文字列が`header.payload.signature`の3パーツに分かれているか確認
- Base64URLエンコードが正しいか確認（`=`パディングなし）

### エラー: "Signature verification failed"
- 公開鍵フォーマットがuncompressed (65バイト) か確認
- 署名アルゴリズムがES256であることを確認
- 署名対象メッセージが`header.payload`であることを確認

### エラー: "Audience mismatch"
- ShareToken.payload.audとリクエスト送信者のDIDが一致しているか確認

### コンパイルエラー: 型が見つからない
- `use`文で必要な型をインポートしているか確認
- セクション0.4の既存の型定義を参照

---

**この計画書で不明な点があれば、Notion設計書または既存のコードを参照してください。**
