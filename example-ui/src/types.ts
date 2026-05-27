// Shared domain types for the example UI.

export type EntryKind = "file" | "folder";

export type Permission = "read" | "write";

export type KeyType = "secp256r1" | "secp256k1";

// A recipient a file has been shared with. We keep the KeyEnvelope material so
// the demo can later unwrap + decrypt (HPKE round-trip) to prove access.
export interface ShareGrant {
  recipientPublicKeyB64Url: string;
  recipientLabel?: string;
  permissions: Permission[];
  senderKeyId: string;
  recipientKeyId: string;
  envelope: { enc: string; wrapped_cek: string; ciphertext: string };
  grantedAt: number;
}

// One row in the Drive. Folders are purely logical (path prefixes); only files
// carry Monas content/crypto state.
export interface Entry {
  id: string; // local UI id (uuid)
  kind: EntryKind;
  name: string;
  parentPath: string; // logical folder path, e.g. "/" or "/Docs"
  sizeBytes: number;
  mimeType?: string;
  createdAt: number;
  updatedAt: number;

  // --- Monas content state (files only) ---
  localContentId?: string; // SDK content_id (encCid) — used for fetch/share/CEK
  remoteContentId?: string; // state-node Content Network id
  seriesId?: string; // logical series across versions
  syncedToStateNode: boolean;
  versionCount: number;
  shares: ShareGrant[];
}

export interface Identity {
  label: string;
  keyType: KeyType;
  publicKeyB64Url: string;
  privateKeyB64Url: string;
  /** Registered with monas-account as the signing key (enables content ops). */
  isSigningAccount?: boolean;
}
