// Flow builders: each returns the ordered StepSpec[] for one Drive action.
//
// With the SDK, a single gateway call does the whole orchestration server-side
// (CEK → AES-256-GCM → SHA-256 CID → storage → state-node + signing). So each
// flow has ONE real gateway call, surrounded by illustrative steps that narrate
// the protocol and read ids out of the response. The real call is noted in each
// step's title; illustrative steps have a short min duration for legibility.

import * as contentApi from "../api/content";
import * as shareApi from "../api/share";
import * as stateApi from "../api/stateNode";
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
      hint: "monas-sdk · AES-256-GCM",
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
      hint: "monas-sdk · AES-256-GCM",
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
      hint: "monas-sdk · AES-256-GCM",
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

// ------------------------------------------------- verified read (state node)
// Distinct from openFileFlow: that one reads the gateway's own local store and
// never touches the network. This pulls the crsl-lib Node from the state node
// (relayed to a member if the contacted node isn't one) and verifies it before
// showing anything — CID recomputation, AES-GCM decryption, plain CID recheck.
export function readFromStateNodeFlow(input: {
  entry: Entry;
  version?: string; // omit to read the newest version the state node reports
}): StepSpec[] {
  const { entry } = input;
  return [
    {
      title: "Sign read request",
      hint: "read:{content_id}:{ts}",
      kind: "state",
      minMs: 180,
      exec: async () =>
        "Read signed via the account key, bound to this content id and timestamp (5-min freshness window)",
    },
    {
      title: "Fetch version from state-node · gateway call",
      hint: "relay → member · verified",
      kind: "verify",
      minMs: 200,
      exec: async (ctx) => {
        const resp = await stateApi.readFromStateNode({
          contentId: entry.remoteContentId || entry.localContentId!,
          localContentId: entry.localContentId!,
          version: input.version,
        });
        ctx.read = resp;
        const n = byteLengthOfBase64Url(resp.content);
        return `Version ${short(resp.version)} returned · ${fmtBytes(n)} of plaintext`;
      },
    },
    {
      title: "Verify payload authenticity",
      hint: "CID recompute · AES-GCM · plain CID",
      kind: "verify",
      minMs: 220,
      exec: async (ctx) => {
        const r = ctx.read as stateApi.ReadFromStateNodeOutput;
        return (
          `Node CBOR re-hashed to ${short(r.version)}, decrypted under the CEK and the ` +
          `plaintext re-addressed to ${short(r.local_content_id)} — a non-member relay ` +
          `cannot forge this. (Version freshness is NOT proven — issue #59.)`
        );
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
      hint: "HPKE Auth · DH-KEM P-256",
      kind: "share",
      minMs: 180,
      exec: async (ctx) => {
        const grant = await shareApi.shareContent({
          contentId: entry.localContentId!,
          senderPublicKeyB64Url: identity.publicKeyB64Url,
          senderPrivateKeyB64Url: identity.privateKeyB64Url,
          recipientPublicKeyB64Url: input.recipientPublicKeyB64Url,
          permissions: input.permissions,
        });
        ctx.share = grant;
        return (
          `KeyEnvelope created (RFC 9180 HPKE, Auth mode) for KeyId ` +
          `${short(grant.recipient_key_id, 8, 6)} · epoch ${grant.key_envelope.key_epoch}`
        );
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
      hint: "HPKE Auth open · AES-256-GCM",
      kind: "verify",
      minMs: 180,
      exec: async (ctx) => {
        const g = ctx.share as shareApi.ShareContentOutput;
        const res = await shareApi.decryptSharedContent({
          contentId: entry.localContentId!,
          privateKeyB64Url: input.recipientPrivateKeyB64Url!,
          // Auth-mode unwrap is bound to the sender's key, TOFU-pinned on the
          // recipient's first envelope for this content.
          senderPublicKeyB64Url: g.sender_public_key,
          recipientKeyId: g.recipient_key_id,
          keyEnvelope: g.key_envelope,
        });
        const n = byteLengthOfBase64Url(res.content);
        return `Round-trip OK · ${fmtBytes(n)} of plaintext recovered as the recipient (sender key pinned)`;
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
      // Order matters and is the reverse of what reads naturally: tokens are
      // invalidated BEFORE the CEK is rotated. The other way round leaves a
      // window between re-encryption and invalidation in which the revoked
      // recipient can still write.
      title: "Invalidate prior tokens",
      hint: "min_valid_issued_at",
      kind: "state",
      minMs: 200,
      exec: async () =>
        "Token cutoff advanced on the state-node first — before rotation, so the revoked recipient cannot write in between",
    },
    {
      title: "Revoke & re-encrypt under new CEK · gateway call",
      hint: "monas-sdk · AES-256-GCM",
      kind: "cleanup",
      minMs: 180,
      exec: async (ctx) => {
        const r = await shareApi.revokeShare({
          contentId: entry.localContentId!,
          remoteContentId: entry.remoteContentId,
          senderPublicKeyB64Url: identity.publicKeyB64Url,
          senderPrivateKeyB64Url: identity.privateKeyB64Url,
          recipientPublicKeyB64Url: input.recipientPublicKeyB64Url,
        });
        ctx.revoke = r;
        const reissued = r.reissued_envelopes?.length ?? 0;
        const cutoff = r.token_invalidated_at
          ? ` · token cutoff ${r.token_invalidated_at}`
          : "";
        return `Access revoked=${r.revoked} · ${reissued} surviving recipient(s) re-wrapped${cutoff}`;
      },
    },
    {
      title: "Reissue envelopes to surviving recipients",
      hint: "HPKE Auth · new key_epoch",
      kind: "share",
      minMs: 200,
      exec: async (ctx) => {
        const r = ctx.revoke as shareApi.RevokeShareOutput;
        const reissued = r.reissued_envelopes ?? [];
        if (reissued.length === 0)
          return "No other recipients — nothing to reissue";
        const epoch = reissued[0].key_envelope.key_epoch;
        return (
          `${reissued.length} envelope(s) reissued at epoch ${epoch}; each recipient must ` +
          `process theirs or it can no longer decrypt`
        );
      },
    },
  ];
}
