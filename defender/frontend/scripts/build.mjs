// The frontend build (#1161 S2, B8, #1540 F1): the generated sources, the type check and the source check (any failure
// fails the build and nothing is written to dist/), the app by Vite, then the address matcher alone, in library mode.
import { spawnSync } from "node:child_process";
import { rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");

function fail(message) {
  console.error(`build: ${message}`);
  process.exit(1);
}

// A failed build leaves no `index.html`, so dist/ goes first.
rmSync(dist, { recursive: true, force: true });
for (const script of ["generate.mjs", "check.mjs"]) {
  const ran = spawnSync(process.execPath, [path.join(root, "scripts", script)], { cwd: root, stdio: "inherit" });
  if (ran.status !== 0) fail(`${script.replace(".mjs", "")} failed`);
}

await build({ root, logLevel: "warn" });
// The matcher alone (no DOM), for Bun and Node: the module the app imports.
await build({
  root,
  configFile: false,
  publicDir: false,
  logLevel: "warn",
  build: {
    outDir: dist,
    emptyOutDir: false,
    target: "es2022",
    lib: { entry: path.join(root, "src", "addresses.ts"), formats: ["es"], fileName: () => "addresses.mjs" },
  },
});
