use serde::{Deserialize, Serialize};

/// 鍵の種類
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Secp256k1,
    Secp256r1,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Secp256k1 => write!(f, "secp256k1"),
            KeyType::Secp256r1 => write!(f, "secp256r1"),
        }
    }
}

// ============================================
// generate_keypair
// ============================================

/// 鍵ペア生成のリクエスト
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeypairInput {
    pub key_type: KeyType,
}

/// 鍵ペア生成のレスポンス
#[derive(Clone, Serialize, Deserialize)]
pub struct GenerateKeypairOutput {
    pub key_type: KeyType,
    /// 公開鍵（base64url）
    pub public_key: String,
    /// 秘密鍵（base64url）
    pub private_key: String,
}

// 秘密鍵が Debug 出力経由でログや panic メッセージへ混入するのを防ぐため、
// derive(Debug) ではなく private_key を "<redacted>" に固定する手書き実装を用いる。
impl std::fmt::Debug for GenerateKeypairOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerateKeypairOutput")
            .field("key_type", &self.key_type)
            .field("public_key", &self.public_key)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_type_serialization() {
        let k256 = KeyType::Secp256k1;
        let json = serde_json::to_string(&k256).unwrap();
        assert_eq!(json, "\"secp256k1\"");

        let p256 = KeyType::Secp256r1;
        let json = serde_json::to_string(&p256).unwrap();
        assert_eq!(json, "\"secp256r1\"");
    }

    #[test]
    fn test_key_type_deserialization() {
        let k256: KeyType = serde_json::from_str("\"secp256k1\"").unwrap();
        assert_eq!(k256, KeyType::Secp256k1);

        let p256: KeyType = serde_json::from_str("\"secp256r1\"").unwrap();
        assert_eq!(p256, KeyType::Secp256r1);
    }

    #[test]
    fn test_generate_keypair_input() {
        let input = GenerateKeypairInput {
            key_type: KeyType::Secp256k1,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"key_type\":\"secp256k1\""));
    }

    #[test]
    fn test_generate_keypair_output() {
        let output = GenerateKeypairOutput {
            key_type: KeyType::Secp256k1,
            public_key: "A9C2oMamPJwStcOm".into(),
            private_key: "w13wjJT3L08Mg9jI".into(),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"public_key\":\"A9C2oMamPJwStcOm\""));
        assert!(json.contains("\"private_key\":\"w13wjJT3L08Mg9jI\""));
    }

    #[test]
    fn debug_output_redacts_private_key() {
        let output = GenerateKeypairOutput {
            key_type: KeyType::Secp256k1,
            public_key: "pub_abc_visible".into(),
            private_key: "super_secret_priv_xyz".into(),
        };
        let dbg = format!("{:?}", output);
        assert!(
            !dbg.contains("super_secret_priv_xyz"),
            "Debug must not leak private_key. got: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "expected <redacted> marker, got: {dbg}"
        );
        assert!(
            dbg.contains("pub_abc_visible"),
            "public_key should remain visible, got: {dbg}"
        );
    }
}
