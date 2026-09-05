// The share package: what the owner copies out of the Share dialog and the
// recipient pastes into "Import shared". One JSON document, self-describing
// (`kind` + `v`), so a recipient can tell a package from any other pasted
// text and a future format change cannot be mistaken for this one.
import type { Entry, Permission, ShareGrant, SharePackage } from "./types";

export function buildSharePackage(entry: Entry, grant: ShareGrant): SharePackage {
  return {
    kind: "monas-share",
    v: 1,
    name: entry.name,
    mimeType: entry.mimeType,
    sizeBytes: entry.sizeBytes,
    content_id: entry.localContentId!,
    remote_content_id: entry.remoteContentId,
    sender_public_key: grant.senderPublicKeyB64Url,
    recipient_public_key: grant.recipientPublicKeyB64Url,
    recipient_key_id: grant.recipientKeyId,
    permissions: grant.permissions,
    key_envelope: grant.envelope,
    delegated_access: grant.delegatedAccess,
    shared_at: grant.reissuedAt ?? grant.grantedAt,
  };
}

export function serializeSharePackage(pkg: SharePackage): string {
  return JSON.stringify(pkg, null, 2);
}

export class SharePackageError extends Error {}

const PERMISSIONS: Permission[] = ["read", "write"];

function str(o: Record<string, unknown>, key: string): string {
  const v = o[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new SharePackageError(`share package is missing “${key}”`);
  }
  return v;
}

/** Parse pasted text into a package, or throw a `SharePackageError` that says
 *  what is wrong in words a person can act on. */
export function parseSharePackage(text: string): SharePackage {
  let raw: unknown;
  try {
    raw = JSON.parse(text.trim());
  } catch {
    throw new SharePackageError("that is not a share package — expected the JSON copied from the owner's Share dialog");
  }
  if (typeof raw !== "object" || raw === null) {
    throw new SharePackageError("that is not a share package — expected a JSON object");
  }
  const o = raw as Record<string, unknown>;
  if (o.kind !== "monas-share") {
    throw new SharePackageError("that is not a Monas share package (kind ≠ monas-share)");
  }
  if (o.v !== 1) {
    throw new SharePackageError(`unsupported share package version ${String(o.v)} (this UI reads v1)`);
  }

  const env = o.key_envelope;
  if (typeof env !== "object" || env === null) {
    throw new SharePackageError("share package is missing “key_envelope”");
  }
  const e = env as Record<string, unknown>;
  if (typeof e.key_epoch !== "number") {
    throw new SharePackageError("share package envelope has no key_epoch");
  }

  const permissions = Array.isArray(o.permissions)
    ? (o.permissions.filter((p): p is Permission => PERMISSIONS.includes(p as Permission)) as Permission[])
    : [];
  if (permissions.length === 0) {
    throw new SharePackageError("share package grants no permission");
  }

  const delegated = o.delegated_access;
  return {
    kind: "monas-share",
    v: 1,
    name: str(o, "name"),
    mimeType: typeof o.mimeType === "string" ? o.mimeType : undefined,
    sizeBytes: typeof o.sizeBytes === "number" ? o.sizeBytes : 0,
    content_id: str(o, "content_id"),
    remote_content_id: typeof o.remote_content_id === "string" ? o.remote_content_id : undefined,
    sender_public_key: str(o, "sender_public_key"),
    recipient_public_key: str(o, "recipient_public_key"),
    recipient_key_id: str(o, "recipient_key_id"),
    permissions,
    key_envelope: {
      enc: str(e, "enc"),
      wrapped_cek: str(e, "wrapped_cek"),
      ciphertext: str(e, "ciphertext"),
      key_epoch: e.key_epoch,
    },
    delegated_access:
      typeof delegated === "object" && delegated !== null
        ? (delegated as SharePackage["delegated_access"])
        : undefined,
    shared_at: typeof o.shared_at === "number" ? o.shared_at : Date.now(),
  };
}

/** Copy to the clipboard. Returns false when the browser refuses (no
 *  permission, insecure context) so the caller can fall back to "select the
 *  text yourself". */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through */
  }
  return false;
}
