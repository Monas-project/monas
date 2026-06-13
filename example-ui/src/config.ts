// Endpoint configuration.
//
// The UI talks to a single backend: monas-gateway, which embeds monas-sdk and
// orchestrates everything (encrypt → store → state-node → sign via account).
// By default the gateway is reached through the same-origin Vite proxy
// (see vite.config.ts), which forwards to your local gateway and avoids CORS.
// You can repoint it (e.g. at a hosted gateway) from the Settings panel; a
// cross-origin URL must send permissive CORS headers.

export interface EndpointConfig {
  /** monas-gateway base URL (the main backend the UI calls). */
  gateway: string;
  /**
   * monas-account base URL. Used only for "create account" — the UI seeds the
   * P-256 signing key here, because the gateway's /keypair is stateless and
   * does not register a signing key with the account service.
   */
  accountService: string;
}

export const PROXY_DEFAULTS: EndpointConfig = {
  gateway: "/api",
  accountService: "/account-api",
};

export const GATEWAY_PRESETS: { label: string; value: string }[] = [
  { label: "Local (Vite proxy → Docker)", value: "/api" },
  { label: "Local (direct :3000)", value: "http://127.0.0.1:3000" },
  { label: "Public API", value: "https://gateway.monas.example" },
];

const STORAGE_KEY = "monas.endpoints.v2";

export function loadEndpoints(): EndpointConfig {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<EndpointConfig>;
      return { ...PROXY_DEFAULTS, ...parsed };
    }
  } catch {
    /* ignore malformed config */
  }
  return { ...PROXY_DEFAULTS };
}

export function saveEndpoints(cfg: EndpointConfig): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(cfg));
}
