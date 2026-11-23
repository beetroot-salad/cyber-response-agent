// The app's Vite configuration (#1540 F1, F7). Production output works under the ingress's CSP: nothing is inlined, so
// no `data:` URI, and assets are served from the app's own origin.
import { request } from "node:http";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const upstream = process.env.DEFENDER_INGRESS_API_UPSTREAM;
const forgeDomain = process.env.DEFENDER_FORGE_DOMAIN;
const forgeUpstream = process.env.DEFENDER_INGRESS_FORGE_UPSTREAM;

// `bun run dev` only (#1592): a request for the Forgejo site's host goes to Forgejo whole, as `.devcontainer/dev-app.sh`
// names them, so its pages and its sign-in callback work beside the app on the one port. This is not the edge: no
// allowlist, and the sign-in start keeps its Cookie header. The edge's rules are the ingress's (CI's `forgejo-live`).
function forgeSite(domain, target) {
  const at = target.lastIndexOf(":");
  const hostname = target.slice(0, at);
  const port = Number(target.slice(at + 1));
  return {
    name: "forge-site",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if ((req.headers.host ?? "").replace(/:\d+$/, "") !== domain) return next();
        const out = request({ hostname, port, method: req.method, path: req.url, headers: req.headers }, (answer) => {
          res.writeHead(answer.statusCode ?? 502, answer.headers);
          answer.pipe(res);
        });
        out.on("error", () => {
          res.statusCode = 502;
          res.end();
        });
        req.pipe(out);
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), ...(forgeDomain && forgeUpstream ? [forgeSite(forgeDomain, forgeUpstream)] : [])],
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
