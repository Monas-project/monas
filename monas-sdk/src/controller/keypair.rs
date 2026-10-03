use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::common::{generate_trace_id, ApiError, ApiResponse};
use crate::models::keypair::{
    CreateSigningAccountOutput, GenerateKeypairInput, GenerateKeypairOutput, KeyType,
};

use monas_account::application_service::{AccountService, KeyTypeMapper};
use monas_account::infrastructure::key_store::InMemoryAccountKeyStore;

use super::MonasController;

impl MonasController {
    /// 署名アカウントを作る。
    ///
    /// SDK が state node へのリクエスト署名と委譲 Token 発行に使う P-256 鍵を新しく
    /// 作り、署名鍵ストアを置き換える。SDK は起動時に鍵を作らないので、利用者が
    /// これを呼ぶまで署名を要する操作は `NotFound` で失敗する。置き換えた後は、
    /// 以前の鍵で作ったコンテンツや受け取った共有はこの SDK から操作できない。
    pub fn create_signing_account(&self) -> ApiResponse<CreateSigningAccountOutput> {
        let trace_id = generate_trace_id();
        match self.account_service.create(KeyTypeMapper::P256) {
            Ok(account) => ApiResponse::success(
                CreateSigningAccountOutput {
                    key_type: KeyType::Secp256r1,
                    public_key: URL_SAFE_NO_PAD.encode(account.public_key_bytes()),
                    private_key: URL_SAFE_NO_PAD.encode(account.secret_key_bytes()),
                },
                trace_id,
            ),
            Err(e) => ApiResponse::error(
                ApiError::Internal(format!("Failed to create signing account: {e}")),
                trace_id,
            ),
        }
    }

    /// 鍵ペアを生成する
    pub fn generate_keypair(
        &self,
        input: GenerateKeypairInput,
    ) -> ApiResponse<GenerateKeypairOutput> {
        let trace_id = generate_trace_id();

        // KeyType → KeyTypeMapper 変換
        let key_type_mapper = match input.key_type {
            KeyType::Secp256k1 => KeyTypeMapper::K256,
            KeyType::Secp256r1 => KeyTypeMapper::P256,
        };

        // 呼び出し元へ返す鍵であり、署名主体の AccountService には書かない。
        let ephemeral = AccountService {
            key_store: InMemoryAccountKeyStore::default(),
        };

        match ephemeral.create(key_type_mapper) {
            Ok(account) => {
                let output = GenerateKeypairOutput {
                    key_type: input.key_type,
                    public_key: URL_SAFE_NO_PAD.encode(account.public_key_bytes()),
                    private_key: URL_SAFE_NO_PAD.encode(account.secret_key_bytes()),
                };
                ApiResponse::success(output, trace_id)
            }
            Err(e) => ApiResponse::error(
                ApiError::Internal(format!("Failed to generate keypair: {e}")),
                trace_id,
            ),
        }
    }
}

#[cfg(test)]
#[allow(deprecated)] // tests intentionally use the test/dev-only constructors
mod tests {
    use super::*;

    /// テスト用コントローラ。generate_keypair は HTTP を使わないため URL は任意のダミー値でよい。
    fn test_controller() -> MonasController {
        MonasController::with_state_node_url("http://127.0.0.1:8080")
    }

    #[test]
    fn test_generate_keypair_secp256k1_success() {
        let controller = test_controller();
        let input = GenerateKeypairInput {
            key_type: KeyType::Secp256k1,
        };

        let response = controller.generate_keypair(input);

        assert!(response.success);
        assert!(response.error.is_none());
        assert!(response.data.is_some());

        let output = response.data.unwrap();
        assert_eq!(output.key_type, KeyType::Secp256k1);
    }

    #[test]
    fn test_generate_keypair_secp256r1_success() {
        let controller = test_controller();
        let input = GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        };

        let response = controller.generate_keypair(input);

        assert!(response.success);
        assert!(response.error.is_none());
        assert!(response.data.is_some());

        let output = response.data.unwrap();
        assert_eq!(output.key_type, KeyType::Secp256r1);
    }

    #[test]
    fn test_generate_keypair_key_length_secp256k1() {
        let controller = test_controller();
        let input = GenerateKeypairInput {
            key_type: KeyType::Secp256k1,
        };

        let response = controller.generate_keypair(input);
        let output = response.data.unwrap();

        // base64url デコードして長さを確認
        let public_key_bytes = URL_SAFE_NO_PAD.decode(&output.public_key).unwrap();
        let private_key_bytes = URL_SAFE_NO_PAD.decode(&output.private_key).unwrap();

        // secp256k1: 公開鍵 65 bytes (非圧縮), 秘密鍵 32 bytes
        assert_eq!(public_key_bytes.len(), 65);
        assert_eq!(private_key_bytes.len(), 32);
    }

    #[test]
    fn test_generate_keypair_key_length_secp256r1() {
        let controller = test_controller();
        let input = GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        };

        let response = controller.generate_keypair(input);
        let output = response.data.unwrap();

        // base64url デコードして長さを確認
        let public_key_bytes = URL_SAFE_NO_PAD.decode(&output.public_key).unwrap();
        let private_key_bytes = URL_SAFE_NO_PAD.decode(&output.private_key).unwrap();

        // secp256r1: 公開鍵 65 bytes (非圧縮), 秘密鍵 32 bytes
        assert_eq!(public_key_bytes.len(), 65);
        assert_eq!(private_key_bytes.len(), 32);
    }

    #[test]
    fn test_generate_keypair_trace_id_format() {
        let controller = test_controller();
        let input = GenerateKeypairInput {
            key_type: KeyType::Secp256k1,
        };

        let response = controller.generate_keypair(input);

        // trace_id が正しい形式か確認
        assert!(response.trace_id.starts_with("trace_"));
        assert_eq!(response.trace_id.len(), 22); // "trace_" (6) + 16 chars
    }

    #[test]
    fn test_generate_keypair_randomness() {
        let controller = test_controller();

        let input1 = GenerateKeypairInput {
            key_type: KeyType::Secp256k1,
        };
        let input2 = GenerateKeypairInput {
            key_type: KeyType::Secp256k1,
        };

        let response1 = controller.generate_keypair(input1);
        let response2 = controller.generate_keypair(input2);

        let output1 = response1.data.unwrap();
        let output2 = response2.data.unwrap();

        // 2回生成しても異なる鍵が生成される
        assert_ne!(output1.public_key, output2.public_key);
        assert_ne!(output1.private_key, output2.private_key);
    }

    #[test]
    fn test_generate_keypair_different_trace_ids() {
        let controller = test_controller();

        let input1 = GenerateKeypairInput {
            key_type: KeyType::Secp256k1,
        };
        let input2 = GenerateKeypairInput {
            key_type: KeyType::Secp256k1,
        };

        let response1 = controller.generate_keypair(input1);
        let response2 = controller.generate_keypair(input2);

        assert_ne!(response1.trace_id, response2.trace_id);
    }

    /// 作った鍵が署名鍵ストアに入り、返した公開鍵と一致する。
    #[test]
    fn create_signing_account_stores_returned_p256_key() {
        use monas_account::application_service::AccountKeyStore;
        use monas_account::infrastructure::key_pair::KeyAlgorithm;

        let controller = test_controller();
        let created = controller.create_signing_account();
        let output = created.data.expect("signing account");
        assert_eq!(output.key_type, KeyType::Secp256r1);

        let stored = controller
            .account_service
            .key_store
            .load()
            .expect("load")
            .expect("stored signing key");
        assert_eq!(stored.algorithm, KeyAlgorithm::P256);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&stored.public_key),
            output.public_key
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&stored.secret_key),
            output.private_key
        );
    }

    /// 2 回目は鍵を置き換える(署名鍵は 1 本だけ)。
    #[test]
    fn create_signing_account_replaces_previous_key() {
        let controller = test_controller();
        let first = controller.create_signing_account().data.expect("first");
        let second = controller.create_signing_account().data.expect("second");
        assert_ne!(first.public_key, second.public_key);

        use monas_account::application_service::AccountKeyStore;
        let stored = controller
            .account_service
            .key_store
            .load()
            .expect("load")
            .expect("key");
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&stored.public_key),
            second.public_key
        );
    }
}
