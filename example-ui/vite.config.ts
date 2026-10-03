import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// The browser talks to same-origin `/api/*`; Vite proxies it to monas-gateway.
// This avoids CORS during local development. The target is configurable via
// .env (see .env.example) so it can point at whatever port your Docker maps.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const gatewayTarget = env.VITE_GATEWAY_TARGET || "http://127.0.0.1:3000";
  // A second, independent gateway standing in for "another person's device"
  // (own CEK store, own signing key). The cross-device share journey points
  // one browser context at it via Settings; see scripts/second-device.sh.
  const gateway2Target = env.VITE_GATEWAY2_TARGET || "http://127.0.0.1:3001";

  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/api2": {
          target: gateway2Target,
          changeOrigin: true,
          rewrite: (p: string) => p.replace(/^\/api2/, ""),
        },
        "/api": {
          target: gatewayTarget,
          changeOrigin: true,
          rewrite: (p: string) => p.replace(/^\/api/, ""),
        },
      },
    },
  };
});
