use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use base64::Engine;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// KeyId (kid) identifying a recipient or a key.
///
/// - Expected to be derived from e.g. the first N bytes of a hash of the public key bytes.
/// - The derivation logic is delegated to infra; the domain treats it only as an opaque ID.
///
/// The serde representation is a **base64url string**. With the derived `Vec<u8>` impl it becomes
/// an array in JSON, and serialization fails with `key must be a string` as soon as it is used as
/// a `HashMap<KeyId, _>` key, as in `Share.recipients` (JSON object keys must be strings). Since
/// the SDK API also represents KeyId as base64url, the persisted representation matches it (the
/// standalone monas-content HTTP API uses standard Base64 instead).
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

    /// This is why this impl exists. With a derived `Serialize`, KeyId becomes a JSON array and
    /// fails with `key must be a string` once used as a map key.
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
