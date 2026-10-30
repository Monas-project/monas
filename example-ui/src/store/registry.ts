// The Drive's file list. Neither monas-content nor the state-node expose a
// queryable listing with names, so the UI keeps its own registry of what it
// created (persisted locally). This is example-app glue, not protocol.
import { createStore } from "./store";
import type { Entry } from "../types";

// v4: owner files are addressed by the SDK's file key (`Entry.fileId`), not
// by the plain content id, and the gateway keeps its records under that key.
// A v3 entry has no file key the gateway knows, so there is nothing to
// migrate; this starts clean rather than surfacing entries that only fail on
// open.
const store = createStore<Entry[]>("monas.registry.v4", []);

// Registries written before folders were removed may hold folder rows. They
// never carried Monas content, so drop them; the files that sat "inside" them
// were only tagged with a path and simply appear in the list.
const isFolderRow = (e: Entry) => (e as { kind?: string }).kind === "folder";
if (store.get().some(isFolderRow)) store.set((prev) => prev.filter((e) => !isFolderRow(e)));

export const useEntries = () => store.use();

export function allEntries(): Entry[] {
  return store.get();
}

export function addEntry(entry: Entry) {
  store.set((prev) => [...prev, entry]);
}

export function updateEntry(id: string, patch: Partial<Entry>) {
  store.set((prev) =>
    prev.map((e) => (e.id === id ? { ...e, ...patch, updatedAt: Date.now() } : e)),
  );
}

// Bookkeeping that is not a modification of the file (sync-status checks):
// records the patch without touching `updatedAt`, so the Modified column
// keeps meaning "when the content last changed".
export function noteEntry(id: string, patch: Partial<Entry>) {
  store.set((prev) => prev.map((e) => (e.id === id ? { ...e, ...patch } : e)));
}

export function removeEntry(id: string) {
  store.set((prev) => prev.filter((e) => e.id !== id));
}
