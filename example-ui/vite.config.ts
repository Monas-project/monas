import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// The browser talks to same-origin `/api/*`; Vite proxies it to monas-gateway.
// This avoids CORS during local development. The target is configurable via
// .env (see .env.example) so it can point at whatever port your Docker maps.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const gatewayTarget = env.VITE_GATEWAY_TARGET || "http://127.0.0.1:3000";
  const accountTarget = env.VITE_ACCOUNT_TARGET || "http://127.0.0.1:4002";

  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/api": {
          target: gatewayTarget,
          changeOrigin: true,
          rewrite: (p: string) => p.replace(/^\/api/, ""),
        },
        // Only used by "create account" to seed the monas-account signing key.
        "/account-api": {
          target: accountTarget,
          changeOrigin: true,
          rewrite: (p: string) => p.replace(/^\/account-api/, ""),
        },
      },
    },
  };
});
