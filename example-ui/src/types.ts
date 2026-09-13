// Shared domain types for the example UI.

export type EntryKind = "file" | "folder";

export type Permission = "read" | "write";

export type KeyType = "secp256r1" | "secp256k1";

// What the file browser is showing. "folder" is normal path-based browsing;
// the others are flat, drive-wide filtered listings driven from the sidebar.
export type View =
  | { kind: "folder" }
  | { kind: "all" } // every file, across all folders
  | { kind: "synced" } // files registered on a state-node
  | { kind: "shared" }; // files with at least one share

// A KeyEnvelope as returned by the gateway. `key_epoch` advances on every CEK
// rotation (revoke); the recipient rejects envelopes older than the epoch it
// has already recorded, so it must be carried through untouched.
export interface KeyEnvelopeData {
  enc: string;
  wrapped_cek: string;
  ciphertext: string;
  key_epoch: number;
}

// The capability token the gateway issues alongside a share (JWT, P-256).
export interface DelegatedAccessToken {
  delegated_token: string;
  issued_at: number;
  expires_at: number;
  jti: string;
}

// A recipient a file has been shared with. We keep the KeyEnvelope material so
// the demo can later unwrap + decrypt (HPKE round-trip) to prove access, and so
// the owner can hand the recipient a share package at any time.
export interface ShareGrant {
  recipientPublicKeyB64Url: string;
  recipientLabel?: string;
  permissions: Permission[];
  senderKeyId: string;
  recipientKeyId: string;
  /** Sender public key the recipient TOFU-pins. HPKE runs in Auth mode, so
   *  unwrap is only possible against the key that actually did the wrap —
   *  the recipient needs this, not the (self-asserted) sender_key_id. */
  senderPublicKeyB64Url: string;
  envelope: KeyEnvelopeData;
  delegatedAccess?: DelegatedAccessToken;
  grantedAt: number;
  /** Set when a revoke of *another* recipient rotated the CEK and reissued
   *  this grant's envelope. The recipient must process the new envelope
   *  before it can decrypt again. */
  reissuedAt?: number;
}

// Everything a recipient on another device needs to unwrap and read a share.
// The owner copies this out of the Share dialog and sends it over any channel
// (chat, mail, …); the recipient pastes it into "Import shared". It is not
// secret on its own — the CEK inside is HPKE-wrapped to the recipient's key —
// but it is a capability, so treat it like a link to the file.
export interface SharePackage {
  kind: "monas-share";
  v: 1;
  name: string;
  mimeType?: string;
  sizeBytes: number;
  /** Owner-side SDK content id: what the envelope's ciphertext decrypts to,
   *  and the id the recipient's SDK files the CEK under. */
  content_id: string;
  /** State-node Content Network id (series). */
  remote_content_id?: string;
  sender_public_key: string;
  recipient_public_key: string;
  recipient_key_id: string;
  permissions: Permission[];
  key_envelope: KeyEnvelopeData;
  delegated_access?: DelegatedAccessToken;
  shared_at: number;
}

// A share this device *received*: the package, plus which local identity it
// was addressed to. Kept on the entry so "Open" can unwrap again later.
export interface ReceivedShare {
  senderPublicKeyB64Url: string;
  recipientPublicKeyB64Url: string;
  recipientLabel: string;
  recipientKeyId: string;
  permissions: Permission[];
  envelope: KeyEnvelopeData;
  delegatedAccess?: DelegatedAccessToken;
  receivedAt: number;
  /** Plain content id of the newest version *this device* wrote to the
   *  owner's Content Network (write shares only). The entry's localContentId
   *  stays the id the envelope decrypts to, so this is how the preview tells
   *  "your edit" apart from "the owner edited since sharing". */
  writtenVersionId?: string;
}

// One row in the Drive. Folders are purely logical (path prefixes); only files
// carry Monas content/crypto state.
export interface NetworkHead {
  /** Node CID of the head version as the state node reports it. Unknown right
   *  after this device wrote the head itself (the write returns plain ids). */
  version?: string;
  /** Plain content id the head's plaintext addresses to (verified read). */
  localId: string;
  checkedAt: number;
}

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
  /** What the Content Network's head looked like when this device last
   *  checked (a verified read). `localId` is the plain content id the head's
   *  plaintext addresses to — comparing it with what this device holds is how
   *  "up to date" is told from "newer on network". */
  networkHead?: NetworkHead;
  /** Set when the last check failed (unreachable node, voided token, …);
   *  `networkHead` is then whatever the previous successful check saw. */
  networkCheckError?: string;
  shares: ShareGrant[];
  /** Present when this file was shared *to* this device by someone else.
   *  Opening it unwraps the envelope again; deleting it only removes it from
   *  this Drive; editing it (write shares) writes straight to the owner's
   *  Content Network with the delegated token. */
  receivedShare?: ReceivedShare;
}

export interface Identity {
  label: string;
  keyType: KeyType;
  publicKeyB64Url: string;
  privateKeyB64Url: string;
  /** Registered with monas-account as the signing key (enables content ops). */
  isSigningAccount?: boolean;
}
