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
  // The test steps, each a project its script names (`vitest run --project <name>`), so the build reads no test
  // setting and a name that matches no project is refused (a bare `vitest run` runs them all). The generated tests
  // (`*.generated.test.ts`, exhaustive oracles, `bun run test:generated`) and the jsdom ones (`*.dom.test.tsx`,
  // `bun run test:dom`) are kept out of `bun run test`: the build tests run that dozens of times, and these would
  // multiply into minutes there (#1581, #1598).
  test: {
    projects: [
      {
        extends: true,
        test: {
          name: "unit",
          include: ["src/**/*.test.{ts,tsx}"],
          exclude: ["**/node_modules/**", "src/**/*.generated.test.{ts,tsx}", "src/**/*.dom.test.{ts,tsx}"],
        },
      },
      { extends: true, test: { name: "generated", include: ["src/**/*.generated.test.{ts,tsx}"] } },
      { extends: true, test: { name: "dom", include: ["src/**/*.dom.test.{ts,tsx}"], environment: "jsdom" } },
    ],
  },
});
