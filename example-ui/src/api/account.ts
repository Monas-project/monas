import { gateway } from "./http";

// Keys via the gateway (monas-sdk).
//   POST /keypair  { key_type } → { key_type, public_key, private_key }  (base64url)
//   POST /account                → { key_type, public_key, private_key }  (base64url)
export type KeyType = "secp256r1" | "secp256k1";

export interface GenerateKeypairOutput {
  key_type: KeyType;
  public_key: string; // base64url
  private_key: string; // base64url
}

// Ephemeral keypair (used for sharing recipients). Does NOT touch the
// gateway's signing account.
export function generateKeypair(keyType: KeyType) {
  return gateway<GenerateKeypairOutput>("/keypair", {
    method: "POST",
    body: { key_type: keyType },
  });
}

// Create this device's signing account. The gateway's SDK replaces its one
// P-256 signing key with a new one and returns it: the SDK signs every
// state-node request with it and it is the audience of delegated tokens, and
// the UI uses the same key to open share envelopes. The gateway never creates
// this key on its own — only this call does.
export function createSigningAccount() {
  return gateway<GenerateKeypairOutput>("/account", { method: "POST" });
}
