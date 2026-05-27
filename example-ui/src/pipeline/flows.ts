// Flow builders: each returns the ordered StepSpec[] for one Drive action.
//
// With the SDK, a single gateway call does the whole orchestration server-side
// (CEK → AES-256-CTR → SHA-256 CID → storage → state-node + signing). So each
// flow has ONE real gateway call, surrounded by illustrative steps that narrate
// the protocol and read ids out of the response. The real call is noted in each
// step's title; illustrative steps have a short min duration for legibility.

import * as contentApi from "../api/content";
import * as shareApi from "../api/share";
import { byteLengthOfBase64Url, short } from "../api/crypto";
import type { Entry, Identity, Permission } from "../types";
import type { StepSpec } from "./types";

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// ---------------------------------------------------------------- create
export function createFileFlow(input: {
  name: string;
  contentBase64Url: string;
  sizeBytes: number;
  contentType?: string;
}): StepSpec[] {
  return [
    {
      title: "Generate content key (CEK)",
      hint: "AES-256",
      kind: "crypto",
      minMs: 240,
      exec: async () => "monas-sdk generates a fresh 256-bit Content Encryption Key",
    },
    {
      title: "Encrypt content · gateway call",
      hint: "monas-sdk · AES-256-CTR",
      kind: "crypto",
      minMs: 160,
      exec: async (ctx) => {
        const resp = await contentApi.createContent({
          contentBase64Url: input.contentBase64Url,
          name: input.name,
          contentType: input.contentType,
        });
        ctx.create = resp;
        return `Plaintext (${fmtBytes(input.sizeBytes)}) encrypted with a random IV`;
      },
    },
    {
      title: "Compute content address (CID)",
      hint: "SHA-256",
      kind: "address",
      minMs: 220,
      exec: async (ctx) => {
        const r = ctx.create as contentApi.CreateContentOutput;
        return `encCid = ${short(r.content_id)}`;
      },
    },
    {
      title: "Store encrypted blob",
      hint: "monas-filesync",
      kind: "storage",
      minMs: 240,
      exec: async () => "Ciphertext persisted via storage abstraction — never the plaintext",
    },
    {
      title: "Register on state-node",
      hint: "Content Network · signed",
      kind: "state",
      minMs: 220,
      exec: async (ctx) => {
        const r = ctx.create as contentApi.CreateContentOutput;
        return r.remote_content_id
          ? `Content Network ${short(r.remote_content_id)} · request signed via account (P-256)`
          : "Registered on state-node";
      },
    },
    {
      title: "Select members & init CRDT",
      hint: "Kademlia XOR · DAG-CRDT",
      kind: "state",
      minMs: 260,
      exec: async () => "Member nodes chosen by XOR distance; CRDT DAG initialized (LWW merge)",
    },
  ];
}

// ---------------------------------------------------------------- update
export function updateFileFlow(input: {
  entry: Entry;
  contentBase64Url: string;
  sizeBytes: number;
  name?: string; // when the editor changed the name, carry it to the SDK
}): StepSpec[] {
  const { entry } = input;
  return [
    {
      title: "Re-encrypt updated content · gateway call",
      hint: "monas-sdk · AES-256-CTR",
      kind: "crypto",
      minMs: 160,
      exec: async (ctx) => {
        const resp = await contentApi.updateContent({
          localContentId: entry.localContentId!,
          remoteContentId: entry.remoteContentId || entry.localContentId!,
          contentBase64Url: input.contentBase64Url,
          name: input.name ?? entry.name,
        });
        ctx.update = resp;
        return `New ciphertext (${fmtBytes(input.sizeBytes)}) written with a fresh IV`;
      },
    },
    {
      title: "Recompute content address",
      hint: "SHA-256",
      kind: "address",
      minMs: 200,
      exec: async (ctx) => {
        const r = ctx.update as contentApi.UpdateContentOutput;
        return `new version ${short(r.version_id)} · series ${short(r.series_id)}`;
      },
    },
    {
      title: "Apply CRDT update on state-node",
      hint: "Update op · signed",
      kind: "state",
      minMs: 220,
      exec: async () => "Update op merged (LWW) and propagated to member nodes; signed via account",
    },
  ];
}

// ---------------------------------------------------------------- open / preview
export function openFileFlow(input: { entry: Entry }): StepSpec[] {
  const { entry } = input;
  return [
    {
      title: "Locate Content Network",
      hint: "state-node",
      kind: "state",
      minMs: 160,
      exec: async () =>
        entry.remoteContentId
          ? `Resolved network ${short(entry.remoteContentId)}`
          : "Fetching directly from local content store",
    },
    {
      title: "Fetch & decrypt · gateway call",
      hint: "monas-sdk · AES-256-CTR",
      kind: "verify",
      minMs: 200,
      exec: async (ctx) => {
        const resp = await contentApi.getContent(entry.localContentId!);
        ctx.get = resp;
        const n = byteLengthOfBase64Url(resp.content);
        return `${fmtBytes(n)} of plaintext recovered with the CEK`;
      },
    },
  ];
}

// ---------------------------------------------------------------- delete
export function deleteFileFlow(input: { entry: Entry }): StepSpec[] {
  const { entry } = input;
  return [
    {
      title: "Delete & tombstone · gateway call",
      hint: "monas-sdk",
      kind: "cleanup",
      minMs: 200,
      exec: async (ctx) => {
        const resp = await contentApi.deleteContent({
          localContentId: entry.localContentId!,
          remoteContentId: entry.remoteContentId || entry.localContentId!,
        });
        ctx.delete = resp;
        return "Ciphertext removed; Content Network tombstoned (CRDT history kept for offline nodes)";
      },
    },
    {
      title: "Purge local key material",
      hint: "CEK",
      kind: "cleanup",
      minMs: 160,
      exec: async () => "CEK discarded from the local key store",
    },
  ];
}

// ---------------------------------------------------------------- share
export function shareFlow(input: {
  entry: Entry;
  identity: Identity;
  recipientPublicKeyB64Url: string;
  recipientLabel?: string;
  permissions: Permission[];
  recipientPrivateKeyB64Url?: string; // when present, run an unwrap+decrypt proof
}): StepSpec[] {
  const { entry, identity } = input;
  const steps: StepSpec[] = [
    {
      title: "Wrap CEK for recipient · gateway call",
      hint: "HPKE · DH-KEM P-256",
      kind: "share",
      minMs: 180,
      exec: async (ctx) => {
        const grant = await shareApi.shareContent({
          contentId: entry.localContentId!,
          senderPublicKeyB64Url: identity.publicKeyB64Url,
          recipientPublicKeyB64Url: input.recipientPublicKeyB64Url,
          permissions: input.permissions,
        });
        ctx.share = grant;
        return `KeyEnvelope created (RFC 9180 HPKE) for KeyId ${short(grant.recipient_key_id, 8, 6)}`;
      },
    },
    {
      title: "Issue capability token",
      hint: "JWT · P-256",
      kind: "state",
      minMs: 200,
      exec: async (ctx) => {
        const g = ctx.share as shareApi.ShareContentOutput;
        if (g.delegated_access) return `AuthToken issued · jti ${short(g.delegated_access.jti, 6, 4)}`;
        return `Capability: ${input.permissions.join(", ")} on monas://content/${short(entry.localContentId!, 6, 4)}`;
      },
    },
    {
      title: "Deliver envelope to recipient",
      hint: "out-of-band",
      kind: "share",
      minMs: 200,
      exec: async () => "KeyEnvelope + token handed to the recipient directly",
    },
  ];

  if (input.recipientPrivateKeyB64Url) {
    steps.push({
      title: "Recipient unwraps & decrypts · gateway call",
      hint: "HPKE open · AES-256-CTR",
      kind: "verify",
      minMs: 180,
      exec: async (ctx) => {
        const g = ctx.share as shareApi.ShareContentOutput;
        const res = await shareApi.decryptSharedContent({
          contentId: entry.localContentId!,
          privateKeyB64Url: input.recipientPrivateKeyB64Url!,
          senderKeyId: g.sender_key_id,
          recipientKeyId: g.recipient_key_id,
          keyEnvelope: g.key_envelope,
        });
        const n = byteLengthOfBase64Url(res.content);
        return `Round-trip OK · ${fmtBytes(n)} of plaintext recovered as the recipient`;
      },
    });
  }
  return steps;
}

// ---------------------------------------------------------------- revoke
export function revokeFlow(input: {
  entry: Entry;
  identity: Identity;
  recipientPublicKeyB64Url: string;
}): StepSpec[] {
  const { entry, identity } = input;
  return [
    {
      title: "Re-encrypt under new CEK",
      hint: "AES-256-CTR",
      kind: "crypto",
      minMs: 240,
      exec: async () =>
        "A fresh CEK is generated and the content re-encrypted so old keys no longer open it",
    },
    {
      title: "Revoke share · gateway call",
      hint: "monas-sdk",
      kind: "cleanup",
      minMs: 180,
      exec: async (ctx) => {
        const r = await shareApi.revokeShare({
          contentId: entry.localContentId!,
          senderPublicKeyB64Url: identity.publicKeyB64Url,
          recipientPublicKeyB64Url: input.recipientPublicKeyB64Url,
        });
        ctx.revoke = r;
        return `Access revoked=${r.revoked}; remaining users re-wrapped`;
      },
    },
    {
      title: "Invalidate prior tokens",
      hint: "min_valid_issued_at",
      kind: "state",
      minMs: 200,
      exec: async () => "Token cutoff advanced on the state-node; previously issued tokens are void",
    },
  ];
}
