// Endpoint configuration.
//
// The UI talks to a single backend: monas-gateway, which embeds monas-sdk and
// orchestrates everything (encrypt → store → sign → state-node). The SDK holds
// the signing account in-process; there is no separate account service.
// By default the gateway is reached through the same-origin Vite proxy
// (see vite.config.ts), which forwards to your local gateway and avoids CORS.
// You can repoint it (e.g. at a hosted gateway) from the Settings panel; a
// cross-origin URL must send permissive CORS headers.

export interface EndpointConfig {
  /** monas-gateway base URL (the only backend the UI calls). */
  gateway: string;
}

export const PROXY_DEFAULTS: EndpointConfig = {
  gateway: "/api",
};

/**
 * Largest file body the UI will encrypt and send (create, upload, edit).
 *
 * State nodes push a content's whole history to the other members on create,
 * revoke and delete, and a push much past ~256 KiB is dropped by the peer
 * connection. With the ciphertext sent as raw bytes, 64 KB was measured to
 * create, share, revoke and delete end to end on the hosted 4-node demo.
 * Each revoke or edit adds a full copy of the body to the history, so larger
 * bodies — or many versions — can still miss the immediate push and only
 * reach other members on the next periodic sync. See README "File size limit".
 */
export const MAX_FILE_BYTES = 64 * 1024;

export const GATEWAY_PRESETS: { label: string; value: string }[] = [
  { label: "Local (Vite proxy → Docker)", value: "/api" },
  { label: "Local (direct :3000)", value: "http://127.0.0.1:3000" },
];

const STORAGE_KEY = "monas.endpoints.v2";

export function loadEndpoints(): EndpointConfig {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      // Only `gateway` is read: configs saved by older UIs also carry an
      // `accountService` URL for the separate account server they called.
      const parsed = JSON.parse(raw) as Partial<EndpointConfig>;
      return { gateway: parsed.gateway ?? PROXY_DEFAULTS.gateway };
    }
  } catch {
    /* ignore malformed config */
  }
  return { ...PROXY_DEFAULTS };
}

export function saveEndpoints(cfg: EndpointConfig): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(cfg));
}
