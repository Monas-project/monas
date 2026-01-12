
## APIエンドポイントでの動作確認

### 0. ローカルサーバー起動

```bash
cargo run --package monas-content

# output
monas-content server listening on http://127.0.0.1:4001
```

### APIエンドポイントのテスト

```bash
curl -X GET http://localhost:4001/health

# output
ok
```

### 再暗号化機能の動作確認

#### 1. コンテンツの作成

```bash
CONTENT_RESPONSE=$(curl -s -X POST http://localhost:4001/contents \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-document.txt",
    "path": "/documents/test-document.txt",
    "content_base64": "SGVsbG8gV29ybGQ="
  }')

CONTENT_ID=$(echo $CONTENT_RESPONSE | jq -r '.content_id')
echo "Created content_id: $CONTENT_ID"

# output
Created content_id: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
```

#### 2. HPKE公開鍵の生成

```bash
cargo run -p monas-content --example generate_hpke_recipient_key

# output:
recipient_public_key_base64: BPvw+NPco4Y7U9VXHfJuAivu+9u3aNBd/OD9nMKf8ULy2OR5j6bRVsezorDcjniFbAOjZuYHCw6K0H1lYE8QrA4=
recipient_private_key_base64: EiN9xQvCQjcaDsnuutkyHxFzS2qkkv0nG84vP3WnwDI=
```

#### 3. Owner権限の付与

```bash
OWNER_KEY_ID_BYTES="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
OWNER_KEY_ID_BASE64=$(echo -n $OWNER_KEY_ID_BYTES | xxd -r -p | base64)

RECIPIENT_PUBLIC_KEY_BASE64="BPvw+NPco4Y7U9VXHfJuAivu+9u3aNBd/OD9nMKf8ULy2OR5j6bRVsezorDcjniFbAOjZuYHCw6K0H1lYE8QrA4="

curl -X POST http://localhost:4001/shares \
  -H "Content-Type: application/json" \
  -d "{
    \"content_id\": \"$CONTENT_ID\",
    \"sender_key_id_base64\": \"$OWNER_KEY_ID_BASE64\",
    \"recipient_public_key_base64\": \"$RECIPIENT_PUBLIC_KEY_BASE64\",
    \"permission\": \"owner\"
  }" | jq '.'


# output
{
  "content_id": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
  "sender_key_id": "ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8=",
  "recipient_key_id": "c67YE5U+5sqUbpvfsZ1HSA==",
  "permission": "owner",
  "enc_base64": "BCPIlxiHPZ/KtOUR1RT4cb4RgyN5hD+qSBxw64gJtU7x54RXyhp9b7po8cYUWXlkCYuSp8Ps+4Sdnn9VJhumI/M=",
  "wrapped_cek_base64": "G1AHC8pGaBmUmKBfhBxckgDpd0lHDdz+y2zyi33VdIbR28JvcHjEzk5Sxj3H/1D7",
  "ciphertext_base64": "Z24nyjD6U0VvAtv4VlCzLGOZYi44Yrs0mv7Z"
}
```

#### 4. revoke対象のユーザにRead権限を付与

```bash
REVOKED_KEY_ID_BYTES="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
REVOKED_KEY_ID_BASE64=$(echo -n $REVOKED_KEY_ID_BYTES | xxd -r -p | base64)

REVOKED_USER_KEY_OUTPUT=$(cargo run -p monas-content --example generate_hpke_recipient_key 2>/dev/null)
REVOKED_USER_PUBLIC_KEY_BASE64=$(echo "$REVOKED_USER_KEY_OUTPUT" | grep "recipient_public_key_base64" | cut -d' ' -f2)

curl -X POST http://localhost:4001/shares \
  -H "Content-Type: application/json" \
  -d "{
    \"content_id\": \"$CONTENT_ID\",
    \"sender_key_id_base64\": \"$OWNER_KEY_ID_BASE64\",
    \"recipient_public_key_base64\": \"$REVOKED_USER_PUBLIC_KEY_BASE64\",
    \"permission\": \"read\"
  }" | jq '.'

# output
{
  "content_id": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
  "sender_key_id": "ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8=",
  "recipient_key_id": "aaYU5bTUYjAPkzezKe/oaA==",
  "permission": "read",
  "enc_base64": "BAVJbOGWeRFeNDAFNR5QKmzXgACBMunutuyyBCLTPMtfFRXhi/ab3cZysZbMQV5peOYvzGNUBzE2aJWP26X5B78=",
  "wrapped_cek_base64": "Rg1bD16+3R+d1AOrJNBOd1xF7qTv8ru2WRugoaqh73j+i7N95RJIDkDG2HzYRsT0",
  "ciphertext_base64": "Z24nyjD6U0VvAtv4VlCzLGOZYi44Yrs0mv7Z"
}
```

#### 5. Shareでの確認

```bash
curl -X GET http://localhost:4001/shares/$CONTENT_ID | jq '.'

# output
{
  "content_id": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
  "recipients": [
    {
      "recipient_key_id": "c67YE5U+5sqUbpvfsZ1HSA==",
      "permissions": [
        "owner"
      ]
    },
    {
      "recipient_key_id": "aaYU5bTUYjAPkzezKe/oaA==",
      "permissions": [
        "read"
      ]
    }
  ]
}
```

#### 6. 再暗号化の実行

```bash
OWNER_KEY_ID_BASE64="c67YE5U+5sqUbpvfsZ1HSA=="
REVOKED_KEY_ID_BASE64="aaYU5bTUYjAPkzezKe/oaA=="

REENCRYPT_RESPONSE=$(curl -s -X POST http://localhost:4001/contents/$CONTENT_ID/reencrypt \
  -H "Content-Type: application/json" \
  -d "{
    \"requester_key_id_base64\": \"$OWNER_KEY_ID_BASE64\",
    \"revoked_key_id_base64\": \"$REVOKED_KEY_ID_BASE64\"
  }")

echo "Reencrypt response: $REENCRYPT_RESPONSE"

echo $REENCRYPT_RESPONSE | jq '.'

# output
{
  "content_id": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
  "series_id": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
  "name": "test-document.txt",
  "path": "/documents/test-document.txt",
  "updated_at": "2026-01-12T12:13:05.406817+00:00",
  "encrypted_content_base64": "PebMd20Y4dr2LQVG1uJ80U0VpnNkL1Ntj5pt"
}
```

#### 7. 再暗号化後の確認

```bash
NEW_CONTENT_ID=$(echo $REENCRYPT_RESPONSE | jq -r '.content_id')
echo "New content_id (same): $NEW_CONTENT_ID"

curl -s -X GET http://localhost:4001/contents/$NEW_CONTENT_ID/fetch | jq '.'

# output
{
  "content_id": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
  "series_id": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
  "name": "test-document.txt",
  "path": "/documents/test-document.txt",
  "status": "Active",
  "content_base64": "SGVsbG8gV29ybGQ="
}
```

#### 8. エラーケースの確認

##### 8.1. Owner権限がない場合（403 Forbidden）

```bash
CONTENT_ID=a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
NON_OWNER_KEY_ID_BASE64=$(echo -n 'non-owner-key-id-bytes' | base64)
REVOKED_KEY_ID_BASE64="aaYU5bTUYjAPkzezKe/oaA=="

curl -X POST http://localhost:4001/contents/$CONTENT_ID/reencrypt \
  -H "Content-Type: application/json" \
  -d "{
    \"requester_key_id_base64\": \"$NON_OWNER_KEY_ID_BASE64\",
    \"revoked_key_id_base64\": \"$REVOKED_KEY_ID_BASE64\"
  }"

# output
owner permission denied: requester_key_id=KeyId([110, 111, 110, 45, 111, 119, 110, 101, 114, 45, 107, 101, 121, 45, 105, 100, 45, 98, 121, 116, 101, 115]), content_id=a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
```