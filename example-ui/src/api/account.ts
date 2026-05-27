// Keypair generation via the gateway (monas-sdk `generate_keypair`).
//   POST /keypair  { key_type } → { key_type, public_key, private_key }  (base64url)
import { gateway, createAccountKey } from "./http";
import { standardBase64ToBase64Url } from "./crypto";

export type KeyType = "secp256r1" | "secp256k1";

export interface GenerateKeypairOutput {
  key_type: KeyType;
  public_key: string; // base64url
  private_key: string; // base64url
}

// Ephemeral keypair (used for sharing recipients). Does NOT register a signing
// key with the account service.
export function generateKeypair(keyType: KeyType) {
  return gateway<GenerateKeypairOutput>("/keypair", {
    method: "POST",
    body: { key_type: keyType },
  });
}

// Create the signing account directly on monas-account. This both registers
// the key the SDK uses to sign state-node requests AND returns a keypair we can
// use as an identity. Keys are converted to base64url for consistency with the
// gateway/SDK models.
export async function createSigningAccount(keyType: KeyType): Promise<GenerateKeypairOutput> {
  const acct = await createAccountKey(keyType === "secp256r1" ? "P256" : "K256");
  return {
    key_type: keyType,
    public_key: standardBase64ToBase64Url(acct.public_key_base64),
    private_key: standardBase64ToBase64Url(acct.secret_key_base64),
  };
}
