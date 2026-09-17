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

// Older UIs appended a signing account on every POST /accounts, but that
// endpoint replaces the backend's ONE key. Array order records creation order;
// activeLabel only recorded UI switching and cannot change the backend key.
// There is no account read endpoint to reconcile against. Retain old private
// keys for envelope decryption, but persist their demotion so removing the
// current account never resurrects an overwritten signing key.
const signingAccounts = store.get().identities.filter((i) => i.isSigningAccount);
if (signingAccounts.length > 1) {
  const current = signingAccounts[signingAccounts.length - 1];
  store.set((prev) => ({
    identities: prev.identities.map((i) =>
      i.isSigningAccount && i !== current ? { ...i, isSigningAccount: false } : i,
    ),
    activeLabel: current.label,
  }));
}

export const useIdentities = () => store.use();

export function getIdentities(): Identity[] {
  return store.get().identities;
}

// "You" is this device's signing account: monas-account holds exactly one key,
// and it is the key the SDK signs state-node requests with and the audience of
// every delegated token issued to this device. Anything else in the list is a
// legacy keypair-only identity that cannot act on the network.
export function getActive(): Identity | null {
  const s = store.get();
  return (
    s.identities.find((i) => i.isSigningAccount) ||
    s.identities.find((i) => i.label === s.activeLabel) ||
    s.identities[0] ||
    null
  );
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
