// Identities held by this browser. The active one is "you" (the sender for
// shares). Additional ones let you demo sharing to another account — the UI
// then holds the recipient's private key and can prove the HPKE round-trip.
//
// NOTE: the gateway's /keypair is stateless (it just returns a fresh keypair).
// For content create/update/delete the SDK signs state-node requests via the
// monas-account service, which must already hold a P-256 key. See the README.
import { createStore } from "./store";
import type { Identity } from "../types";

interface IdentityState {
  identities: Identity[];
  activeLabel: string | null;
}

const store = createStore<IdentityState>("monas.identities.v2", {
  identities: [],
  activeLabel: null,
});

export const useIdentities = () => store.use();

export function getIdentities(): Identity[] {
  return store.get().identities;
}

export function getActive(): Identity | null {
  const s = store.get();
  return s.identities.find((i) => i.label === s.activeLabel) || s.identities[0] || null;
}

export function addIdentity(identity: Identity, makeActive = false) {
  store.set((prev) => {
    const identities = [...prev.identities.filter((i) => i.label !== identity.label), identity];
    return {
      identities,
      activeLabel: makeActive || !prev.activeLabel ? identity.label : prev.activeLabel,
    };
  });
}

export function setActive(label: string) {
  store.set((prev) => ({ ...prev, activeLabel: label }));
}

export function removeIdentity(label: string) {
  store.set((prev) => {
    const identities = prev.identities.filter((i) => i.label !== label);
    return {
      identities,
      activeLabel: prev.activeLabel === label ? identities[0]?.label ?? null : prev.activeLabel,
    };
  });
}
