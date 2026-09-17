use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use base64::Engine;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// 受信者や鍵を識別するための KeyId（kid）。
///
/// - 実体は公開鍵バイト列のハッシュ先頭 N バイトなどから生成される想定。
/// - 生成ロジック自体は infra 側に委譲し、ドメインでは「不透明な ID」としてのみ扱う。
///
/// serde 表現は **base64url 文字列**である。`Vec<u8>` の派生実装だと JSON では
/// 配列になり、`Share.recipients` のように `HashMap<KeyId, _>` のキーとして使った
/// 瞬間に `key must be a string` でシリアライズが落ちる（JSON のオブジェクトキーは
/// 文字列に限られる）。KeyId は API 境界でも base64url で表現されるため、
/// 永続化表現もそれに揃えている。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(Vec<u8>);

impl KeyId {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl Serialize for KeyId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64_URL.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        let bytes = BASE64_URL
            .decode(encoded.as_bytes())
            .map_err(|e| D::Error::custom(format!("invalid base64url KeyId: {e}")))?;
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn serializes_as_base64url_string_not_byte_array() {
        let key_id = KeyId::new(vec![1, 2, 3, 250]);
        let json = serde_json::to_string(&key_id).unwrap();
        assert_eq!(json, "\"AQID-g\"");
    }

    #[test]
    fn round_trips_through_json() {
        let key_id = KeyId::new(vec![0, 127, 128, 255, 42]);
        let json = serde_json::to_string(&key_id).unwrap();
        let decoded: KeyId = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, key_id);
    }

    /// これがこの実装の存在理由。派生 `Serialize` だと KeyId は JSON 配列になり、
    /// map のキーに使った時点で `key must be a string` で落ちる。
    #[test]
    fn works_as_a_json_map_key() {
        let mut map = HashMap::new();
        map.insert(KeyId::new(vec![9, 8, 7]), "recipient");

        let json = serde_json::to_string(&map).expect("KeyId must serialize as a JSON object key");
        assert_eq!(json, "{\"CQgH\":\"recipient\"}");

        let decoded: HashMap<KeyId, String> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded[&KeyId::new(vec![9, 8, 7])], "recipient");
    }

    #[test]
    fn rejects_malformed_base64() {
        let err = serde_json::from_str::<KeyId>("\"not valid base64!!\"").unwrap_err();
        assert!(err.to_string().contains("invalid base64url KeyId"));
    }
}
