import { defineConfig, devices } from "@playwright/test";

// Real-stack journeys (tests-e2e/): every test mutates content on the live
// state-node network through the local gateway, so this config is split from
// the cheap UI suite (playwright.config.ts) and run on demand:
//   npm run test:e2e
// The stack is started out of band exactly as for `npm test` — the only extra
// requirement is that the gateway's MONAS_STATE_NODE_URL points at a node that
// is actually up.
export default defineConfig({
  testDir: "./tests-e2e",
  // A journey chains many protocol round trips; give each test real headroom.
  timeout: 600_000,
  expect: { timeout: 30_000 },
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
