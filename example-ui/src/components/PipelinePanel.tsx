import type { RunView, StepView } from "../pipeline/types";
import { Activity, Check, X, Chevron, iconForKind } from "./icons";

function StepNode({ step }: { step: StepView }) {
  if (step.status === "running") return <span className="spinner" />;
  if (step.status === "done") return <Check size={13} />;
  if (step.status === "error") return <X size={13} />;
  return iconForKind(step.kind, 12);
}

function StepRow({ step }: { step: StepView }) {
  return (
    <div className={`step ${step.status}`}>
      <div className="rail">
        <span className="node">
          <StepNode step={step} />
        </span>
      </div>
      <div className="body">
        <div className="title">
          {step.title}
          <span className="hint">{step.hint}</span>
        </div>
        {step.detail && step.status !== "error" && (
          <div className="detail">{step.detail}</div>
        )}
        {step.error && (
          <div className="detail err">
            {step.error}
            {step.optional ? " · non-blocking" : ""}
          </div>
        )}
        {step.status === "skipped" && !step.error && (
          <div className="detail">skipped</div>
        )}
      </div>
    </div>
  );
}

function RunCard({ run }: { run: RunView }) {
  return (
    <div className="run">
      <div className="run-head">
        <span className="op">{run.op}</span>
        <span className="tgt">{run.target}</span>
        <span className={`run-status ${run.status}`}>
          {run.status === "running"
            ? "running"
            : run.status === "done"
            ? "complete"
            : "failed"}
        </span>
      </div>
      {run.steps.map((s) => (
        <StepRow key={s.id} step={s} />
      ))}
    </div>
  );
}

export function PipelinePanel({
  runs,
  collapsed,
  onToggle,
  onClear,
}: {
  runs: RunView[];
  collapsed: boolean;
  onToggle: () => void;
  onClear: () => void;
}) {
  if (collapsed) {
    return (
      <aside className="pipeline collapsed">
        <button
          className="icon-btn"
          style={{ margin: "10px auto" }}
          title="Show protocol activity"
          onClick={onToggle}
        >
          <Activity />
        </button>
      </aside>
    );
  }
  return (
    <aside className="pipeline">
      <div className="pipe-head">
        <Activity size={16} />
        Protocol activity
        <span className="spacer" />
        {runs.length > 0 && (
          <button className="btn ghost sm" onClick={onClear}>
            Clear
          </button>
        )}
        <button className="icon-btn" title="Collapse" onClick={onToggle}>
          <Chevron />
        </button>
      </div>
      <div className="pipe-scroll">
        {runs.length === 0 ? (
          <div className="pipe-empty">
            Every action (create, update, share, revoke, delete) runs through
            Monas: <b>CEK → AES-256-CTR → SHA-256 CID → storage → state-node</b>.
            <br />
            <br />
            Run an action and the steps appear here live.
          </div>
        ) : (
          runs.map((r) => <RunCard key={r.id} run={r} />)
        )}
      </div>
    </aside>
  );
}
