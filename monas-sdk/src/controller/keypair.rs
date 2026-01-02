use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::common::{generate_trace_id, ApiError, ApiResponse};
use crate::models::keypair::{GenerateKeypairInput, GenerateKeypairOutput, KeyType};

use monas_account::application_service::account_service::KeyTypeMapper;
use monas_account::presentation::account::{self as account_presentation, ReqArguments};

use super::MonasController;

impl MonasController {
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

        // monas-account の presentation 層を呼び出し
        let args = ReqArguments {
            generating_key_type: key_type_mapper,
        };

        match account_presentation::create(args) {
            Ok(response) => {
                let output = GenerateKeypairOutput {
                    key_type: input.key_type,
                    public_key: URL_SAFE_NO_PAD.encode(response.generated_key_pair.public_key()),
                    private_key: URL_SAFE_NO_PAD.encode(response.generated_key_pair.secret_key()),
                };
                ApiResponse::success(output, trace_id)
            }
            Err(e) => ApiResponse::error(
                ApiError::Internal(format!("Failed to generate keypair: {:?}", e)),
                trace_id,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair_secp256k1_success() {
        let controller = MonasController::new();
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
        let controller = MonasController::new();
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
        let controller = MonasController::new();
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
        let controller = MonasController::new();
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
        let controller = MonasController::new();
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
        let controller = MonasController::new();

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
        let controller = MonasController::new();

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
}
