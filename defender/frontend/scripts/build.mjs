// The frontend build (#1161 S2, B8, #1540 F1): the generated sources, the type check and the source check, the app by
// Vite, then the address matcher alone, in library mode. Everything is written to `dist-staging/`, which replaces `dist/`
// only once every step has succeeded (F1 b): `dist/` is only ever one whole build, and a failed build, at any step,
// leaves the previous one being served as it was.
import { existsSync, renameSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";
import { check } from "./source-check.mjs";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");
const staging = path.join(root, "dist-staging");
const previous = path.join(root, "dist-previous");

async function main() {
  // Run in this process, so the build does not depend on which runtime started it. On a bad input it exits non-zero
  // itself, before anything is written.
  await import("./generate.mjs");
  const problems = check();
  if (problems.length > 0) {
    for (const problem of problems) console.error(problem);
    throw new Error("check failed");
  }
  await build({ root, logLevel: "warn", build: { outDir: staging, emptyOutDir: true } });
  // The matcher alone (no DOM), for Bun and Node: the module the app imports.
  await build({
    root,
    configFile: false,
    publicDir: false,
    logLevel: "warn",
    build: {
      outDir: staging,
      emptyOutDir: false,
      target: "es2022",
      lib: { entry: path.join(root, "src", "addresses.ts"), formats: ["es"], fileName: () => "addresses.mjs" },
    },
  });
  // Two renames: the old build steps aside and the new one takes its name, so `dist/` is missing only between them.
  if (existsSync(dist)) renameSync(dist, previous);
  renameSync(staging, dist);
  rmSync(previous, { recursive: true, force: true });
}

rmSync(staging, { recursive: true, force: true });
rmSync(previous, { recursive: true, force: true });
try {
  await main();
} catch (error) {
  console.error(`build: ${error.message}`);
  process.exitCode = 1;
} finally {
  rmSync(staging, { recursive: true, force: true });
}
