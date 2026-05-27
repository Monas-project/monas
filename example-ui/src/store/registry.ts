// The Drive's file/folder list. Neither monas-content nor the state-node expose
// a queryable listing with names/paths, so the UI keeps its own registry of
// what it created (persisted locally). This is example-app glue, not protocol.
import { createStore } from "./store";
import type { Entry } from "../types";

const store = createStore<Entry[]>("monas.registry.v2", []);

export const useEntries = () => store.use();

export function allEntries(): Entry[] {
  return store.get();
}

export function entriesIn(parentPath: string): Entry[] {
  return store
    .get()
    .filter((e) => e.parentPath === parentPath)
    .sort((a, b) => {
      if (a.kind !== b.kind) return a.kind === "folder" ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
}

export function addEntry(entry: Entry) {
  store.set((prev) => [...prev, entry]);
}

export function updateEntry(id: string, patch: Partial<Entry>) {
  store.set((prev) =>
    prev.map((e) => (e.id === id ? { ...e, ...patch, updatedAt: Date.now() } : e)),
  );
}

export function removeEntry(id: string) {
  store.set((prev) => prev.filter((e) => e.id !== id));
}

// Recursively collect a folder and everything under it (for cascade delete).
export function descendantsOf(folderPath: string): Entry[] {
  return store
    .get()
    .filter((e) => e.parentPath === folderPath || e.parentPath.startsWith(folderPath + "/"));
}

export function folderPath(parentPath: string, name: string): string {
  return parentPath === "/" ? `/${name}` : `${parentPath}/${name}`;
}
