// Browser-side helpers. The protocol crypto (CEK, AES-256-CTR, HPKE, CID) all
// runs server-side inside monas-sdk via the gateway. Here we only need base64 /
// base64url plumbing, because the SDK models exchange bytes as base64url.

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

// --- base64url (no padding) — the encoding every SDK model uses ---
export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  return base64ToBytes(b64 + pad);
}

export function utf8ToBase64Url(text: string): string {
  return bytesToBase64Url(new TextEncoder().encode(text));
}

export function base64UrlToUtf8(b64url: string): string {
  return new TextDecoder().decode(base64UrlToBytes(b64url));
}

// For <img src="data:...;base64,...">, which needs standard base64.
export function base64UrlToStandard(b64url: string): string {
  return bytesToBase64(base64UrlToBytes(b64url));
}

// monas-account returns keys as standard base64; the gateway/SDK want base64url.
export function standardBase64ToBase64Url(b64: string): string {
  return bytesToBase64Url(base64ToBytes(b64));
}

export async function fileToBase64Url(file: File): Promise<string> {
  return bytesToBase64Url(new Uint8Array(await file.arrayBuffer()));
}

export function byteLengthOfBase64Url(b64url: string): number {
  return base64UrlToBytes(b64url).length;
}

export function uuid(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return "id-" + Math.random().toString(36).slice(2) + Date.now().toString(36);
}

// Abbreviate a long id/hash for display: "head…tail".
export function short(s: string, head = 12, tail = 8): string {
  if (!s) return "—";
  if (s.length <= head + tail + 1) return s;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}
