import { useSyncExternalStore } from "react";
import { uuid } from "../api/crypto";
import { Check, X } from "./icons";

export interface ToastItem {
  id: string;
  kind: "info" | "success" | "error";
  text: string;
}

let items: ToastItem[] = [];
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());

export function pushToast(text: string, kind: ToastItem["kind"] = "info") {
  const id = uuid();
  items = [...items, { id, kind, text }];
  emit();
  setTimeout(() => {
    items = items.filter((t) => t.id !== id);
    emit();
  }, kind === "error" ? 5200 : 3200);
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function Toasts() {
  const list = useSyncExternalStore(subscribe, () => items, () => items);
  return (
    <div className="toasts">
      {list.map((t) => (
        <div key={t.id} className={`toast ${t.kind}`}>
          {t.kind === "success" ? (
            <Check size={15} />
          ) : t.kind === "error" ? (
            <X size={15} />
          ) : (
            <span className="dot" />
          )}
          {t.text}
        </div>
      ))}
    </div>
  );
}
