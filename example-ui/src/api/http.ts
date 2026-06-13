import { loadEndpoints } from "../config";

// SDK error envelope: { type, message } tagged enum.
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public kind: string = "Internal",
    public traceId?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

interface SdkApiError {
  type: string;
  message: string;
}
interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: SdkApiError;
  trace_id: string;
}

function gatewayBase(): string {
  return loadEndpoints().gateway.replace(/\/+$/, "");
}

export function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  /** Add an X-Request-Timestamp header (required by state-touching endpoints). */
  timestamp?: boolean;
  headers?: Record<string, string>;
}

// Calls the gateway and unwraps the SDK ApiResponse<T>. Throws ApiError on
// transport failure or a non-success envelope.
export async function gateway<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const url = gatewayBase() + path;
  const headers: Record<string, string> = { ...(opts.headers || {}) };
  let body: BodyInit | undefined;
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  if (opts.timestamp) headers["X-Request-Timestamp"] = String(nowUnix());

  let res: Response;
  try {
    res = await fetch(url, {
      method: opts.method || (opts.body !== undefined ? "POST" : "GET"),
      headers,
      body,
    });
  } catch (e) {
    throw new ApiError(
      0,
      `Network error reaching the gateway (${url}). Is monas-gateway running and the endpoint correct? ${
        (e as Error).message
      }`,
    );
  }

  const text = await res.text();
  let parsed: ApiResponse<T> | null = null;
  if (text) {
    try {
      parsed = JSON.parse(text) as ApiResponse<T>;
    } catch {
      parsed = null;
    }
  }

  if (parsed && parsed.success === false && parsed.error) {
    throw new ApiError(res.status, parsed.error.message, parsed.error.type, parsed.trace_id);
  }
  if (!res.ok) {
    throw new ApiError(res.status, text || res.statusText);
  }
  if (parsed && "success" in parsed) {
    return parsed.data as T;
  }
  return undefined as T;
}

// Health probe for the connection indicator (gateway GET /health → 200).
export async function probeGateway(): Promise<boolean> {
  try {
    const res = await fetch(gatewayBase() + "/health", { method: "GET" });
    return res.ok;
  } catch {
    return false;
  }
}

// --- monas-account service (only used to create the signing key) ---
// This service returns plain JSON (not the SDK ApiResponse envelope) and keys
// in standard base64.
export interface AccountCreateResponse {
  algorithm: string;
  public_key_base64: string;
  secret_key_base64: string;
}

export async function createAccountKey(keyType: "P256" | "K256"): Promise<AccountCreateResponse> {
  const base = loadEndpoints().accountService.replace(/\/+$/, "");
  let res: Response;
  try {
    res = await fetch(base + "/accounts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key_type: keyType }),
    });
  } catch (e) {
    throw new ApiError(
      0,
      `Network error reaching the account service (${base}). Is monas-account running? ${
        (e as Error).message
      }`,
    );
  }
  const text = await res.text();
  if (!res.ok) throw new ApiError(res.status, text || res.statusText);
  return JSON.parse(text) as AccountCreateResponse;
}
