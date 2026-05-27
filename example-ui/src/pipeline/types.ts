// A "pipeline" models one user action (create / update / share / revoke /
// delete / open) as an ordered list of steps. Each step maps to either a real
// API call or an illustrative phase of the protocol (CEK generation, AES
// encryption, CID addressing, state-node sync, HPKE wrap). The PipelinePanel
// renders these live so the encryption + state-node work behind a Drive action
// is visible rather than hidden behind a single spinner.

export type StepKind =
  | "key" // keypair / KeyId
  | "crypto" // CEK gen, AES-256-CTR, re-encryption
  | "address" // SHA-256 CID computation
  | "storage" // filesync provider save/fetch
  | "state" // state-node / Content Network / CRDT
  | "share" // HPKE wrap / unwrap
  | "verify" // decrypt / round-trip check
  | "cleanup"; // delete / revoke

export type StepStatus = "pending" | "running" | "done" | "error" | "skipped";

export interface StepView {
  id: string;
  title: string;
  hint: string; // short technical label, e.g. "AES-256-CTR"
  kind: StepKind;
  status: StepStatus;
  detail?: string; // populated at runtime (ids, sizes, responses)
  error?: string;
  optional?: boolean;
}

export interface RunView {
  id: string;
  op: string; // "Create", "Share", ...
  target: string; // entry name
  status: "running" | "done" | "error";
  steps: StepView[];
  startedAt: number;
  finishedAt?: number;
}

// Shared mutable context threaded through a run's steps.
export interface RunContext {
  [key: string]: unknown;
}

export interface StepSpec {
  title: string;
  hint: string;
  kind: StepKind;
  // Return a human-readable detail string (shown under the step), or void.
  // Throw to mark the step failed.
  exec: (ctx: RunContext) => Promise<string | void>;
  // Optional steps don't fail the whole run if they error (e.g. best-effort
  // state-node sync when a public node enforces auth the demo can't satisfy).
  optional?: boolean;
  // Minimum visible duration so fast/illustrative steps don't flash by.
  minMs?: number;
}
