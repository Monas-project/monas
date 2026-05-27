import { uuid } from "../api/crypto";
import { ApiError } from "../api/http";
import type { RunContext, RunView, StepSpec, StepView } from "./types";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export interface RunResult {
  ok: boolean;
  ctx: RunContext;
  run: RunView;
}

// Execute steps sequentially, emitting an updated RunView snapshot after every
// state change so the UI can animate progress.
export async function runPipeline(
  op: string,
  target: string,
  specs: StepSpec[],
  onUpdate: (run: RunView) => void,
  initialCtx: RunContext = {},
): Promise<RunResult> {
  const steps: StepView[] = specs.map((s) => ({
    id: uuid(),
    title: s.title,
    hint: s.hint,
    kind: s.kind,
    status: "pending",
    optional: s.optional,
  }));

  const run: RunView = {
    id: uuid(),
    op,
    target,
    status: "running",
    steps,
    startedAt: Date.now(),
  };

  const ctx: RunContext = initialCtx;
  const emit = () => onUpdate({ ...run, steps: run.steps.map((s) => ({ ...s })) });
  emit();

  let hadRequiredError = false;

  for (let i = 0; i < specs.length; i++) {
    const spec = specs[i];
    const step = run.steps[i];

    // If a required step already failed, skip the rest.
    if (hadRequiredError) {
      step.status = "skipped";
      emit();
      continue;
    }

    step.status = "running";
    emit();

    const started = Date.now();
    try {
      const detail = await spec.exec(ctx);
      const elapsed = Date.now() - started;
      if (spec.minMs && elapsed < spec.minMs) await sleep(spec.minMs - elapsed);
      if (typeof detail === "string") step.detail = detail;
      step.status = "done";
      emit();
    } catch (e) {
      const elapsed = Date.now() - started;
      if (spec.minMs && elapsed < spec.minMs) await sleep(spec.minMs - elapsed);
      const msg =
        e instanceof ApiError
          ? `${e.message}${e.status ? ` (HTTP ${e.status})` : ""}`
          : (e as Error).message;
      step.status = "error";
      step.error = msg;
      emit();
      if (!spec.optional) hadRequiredError = true;
    }
  }

  run.status = hadRequiredError ? "error" : "done";
  run.finishedAt = Date.now();
  emit();

  return { ok: !hadRequiredError, ctx, run };
}
