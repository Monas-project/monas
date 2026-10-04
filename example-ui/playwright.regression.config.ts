import { defineConfig, devices } from "@playwright/test";

// No running gateway/account/state nodes required. Never reuse a live UI server.
export default defineConfig({
  testDir: "./tests-regression",
  timeout: 30_000,
  expect: { timeout: 4_000 },
  workers: 1,
  reporter: "list",
  outputDir: "/tmp/monas-ui-regression-results",
  use: { baseURL: "http://127.0.0.1:5198", serviceWorkers: "block", trace: "retain-on-failure" },
  webServer: {
    command: "npx vite --host 127.0.0.1 --port 5198 --strictPort",
    url: "http://127.0.0.1:5198",
    reuseExistingServer: false,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
