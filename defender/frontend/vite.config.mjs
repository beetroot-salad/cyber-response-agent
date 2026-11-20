// The app's Vite configuration (#1540 F1, F7). Production output works under the ingress's CSP: nothing is inlined, so
// no `data:` URI, and assets are served from the app's own origin.
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const upstream = process.env.DEFENDER_INGRESS_API_UPSTREAM;

export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", assetsInlineLimit: 0, target: "es2022", cssCodeSplit: false },
  // `bun run dev` (F7): the origin the dev realm registers, instead of the ingress (no CSP), `/api` to the ingress's
  // own upstream.
  server: {
    host: "localhost",
    port: 8000,
    strictPort: true,
    ...(upstream ? { proxy: { "/api": { target: `http://${upstream}` } } } : {}),
  },
  // The generated tests (`*.generated.test.ts`, exhaustive oracles) run as their own step, `bun run test:generated`:
  // the build tests run `bun run test` dozens of times, and these would multiply into minutes there (#1581).
  test: {
    include: process.env.GENERATED_TESTS === "1" ? ["src/**/*.generated.test.{ts,tsx}"] : ["src/**/*.test.{ts,tsx}"],
    exclude:
      process.env.GENERATED_TESTS === "1"
        ? ["**/node_modules/**"]
        : ["**/node_modules/**", "src/**/*.generated.test.{ts,tsx}"],
  },
});
