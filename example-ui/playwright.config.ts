import { defineConfig, devices } from "@playwright/test";

// The UI is only meaningful against a running stack (vite → monas-gateway →
// a 4-node state-node cluster), so there is no webServer block here: the
// stack is started out of band and these tests attach to it. See README.
export default defineConfig({
  testDir: "./tests",
  // The protocol work behind a single click (encrypt → CID → state-node
  // round-trip across 4 nodes) is genuinely slow; the defaults are far too
  // tight and would report protocol latency as a test failure.
  timeout: 180_000,
  expect: { timeout: 30_000 },
  // These tests share one gateway and one localStorage-backed registry, so
  // they cannot run concurrently against each other.
  workers: 1,
  fullyParallel: false,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_URL || "http://localhost:5174",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
