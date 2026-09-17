// Minimal localStorage-backed observable store, consumed via useSyncExternalStore.
import { useSyncExternalStore } from "react";

export function createStore<T>(key: string, initial: T) {
  let value: T = load();
  const listeners = new Set<() => void>();

  function load(): T {
    try {
      const raw = localStorage.getItem(key);
      if (raw) return JSON.parse(raw) as T;
    } catch {
      /* ignore */
    }
    return initial;
  }

  function persist() {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {
      /* quota / private mode — keep in memory */
    }
  }

  function get(): T {
    return value;
  }

  function set(next: T | ((prev: T) => T)) {
    value = typeof next === "function" ? (next as (p: T) => T)(value) : next;
    persist();
    listeners.forEach((l) => l());
  }

  function subscribe(l: () => void) {
    listeners.add(l);
    return () => listeners.delete(l);
  }

  function use(): T {
    return useSyncExternalStore(subscribe, get, get);
  }

  return { get, set, subscribe, use };
}
