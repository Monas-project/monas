// The Drive's file list. Neither monas-content nor the state-node expose a
// queryable listing with names, so the UI keeps its own registry of what it
// created (persisted locally). This is example-app glue, not protocol.
import { createStore } from "./store";
import type { Entry } from "../types";

// v3: content encryption moved from AES-256-CTR to AES-256-GCM and KeyEnvelope
// gained `key_epoch`, so every v2 entry points at ciphertext the backend can no
// longer decrypt and every v2 share grant carries an envelope the recipient now
// rejects. There is nothing to migrate — the ids are dead — so this starts
// clean rather than surfacing entries that only fail on open.
const store = createStore<Entry[]>("monas.registry.v3", []);

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

// A grant's envelope opens only for the id it was wrapped for. Grants saved
// before `envelopeContentId` was recorded fall back to the entry's current
// id, which is right until that id moves (owner edit, head pull, revoke).
// Pin it to the id the entry had just before the move, so packages built
// afterwards still name the id the envelope is bound to.
function applyPatch(e: Entry, patch: Partial<Entry>): Entry {
  const next = { ...e, ...patch };
  const moved = patch.localContentId !== undefined && patch.localContentId !== e.localContentId;
  if (!moved || !e.localContentId || e.receivedShare) return next;
  const from = e.localContentId;
  return {
    ...next,
    shares: next.shares.map((s) => (s.envelopeContentId ? s : { ...s, envelopeContentId: from })),
  };
}

export function updateEntry(id: string, patch: Partial<Entry>) {
  store.set((prev) =>
    prev.map((e) => (e.id === id ? { ...applyPatch(e, patch), updatedAt: Date.now() } : e)),
  );
}

// Bookkeeping that is not a modification of the file (sync-status checks):
// records the patch without touching `updatedAt`, so the Modified column
// keeps meaning "when the content last changed".
export function noteEntry(id: string, patch: Partial<Entry>) {
  store.set((prev) => prev.map((e) => (e.id === id ? applyPatch(e, patch) : e)));
}

export function removeEntry(id: string) {
  store.set((prev) => prev.filter((e) => e.id !== id));
}
