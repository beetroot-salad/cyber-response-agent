// The frontend build (#1161 S2, B8, #1540 F1): the generated sources, the type check and the source check, the app by
// Vite, then the address matcher alone, in library mode. Each build is written to a folder of its own under
// `dist-builds/`, and `dist` is a link to the build being served. Only a whole build is linked, and the link is
// replaced in one rename, which can't be caught halfway: `dist` is always one whole build, and a failed or killed
// build, at any step, leaves the previous one served as it was (F1 b).
//
// A browser may still hold the previous build's `index.html`, which names that build's files under `assets/` (named by
// their content, so a name never means other bytes). The new build keeps those files beside its own, so such a page
// still loads; a page two builds old gets 404 for them, and a reload fixes it.
import { cpSync, existsSync, lstatSync, readdirSync, readFileSync, readlinkSync, renameSync, rmSync, symlinkSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";
import { check } from "./source-check.mjs";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");
const builds = path.join(root, "dist-builds");
const name = `${Date.now()}-${process.pid}`;
const fresh = path.join(builds, name);
/** Vite's list of the files a build wrote, read to tell a build's own `assets/` files from those it kept. */
const MANIFEST = path.join(".vite", "manifest.json");

/** The build folder `dist` links to, or null: no build yet, or a `dist` folder from before builds were linked. */
function served() {
  if (!existsSync(dist) || !lstatSync(dist).isSymbolicLink()) return null;
  return path.resolve(root, readlinkSync(dist));
}

/** The files under `assets/` that the build in `folder` wrote itself (its manifest's), not the ones it kept. */
function ownAssets(folder) {
  const manifest = JSON.parse(readFileSync(path.join(folder, MANIFEST), "utf8"));
  const files = Object.values(manifest).flatMap((chunk) => [chunk.file, ...(chunk.css ?? []), ...(chunk.assets ?? [])]);
  return [...new Set(files)].filter((file) => file.startsWith("assets/"));
}

async function main() {
  // Run in this process, so the build does not depend on which runtime started it. On a bad input it exits non-zero
  // itself, before anything is written.
  await import("./generate.mjs");
  const problems = check();
  if (problems.length > 0) {
    for (const problem of problems) console.error(problem);
    throw new Error("check failed");
  }
  await build({ root, logLevel: "warn", build: { outDir: fresh, emptyOutDir: true, manifest: true } });
  // The matcher alone (no DOM), for Bun and Node: the module the app imports.
  await build({
    root,
    configFile: false,
    publicDir: false,
    logLevel: "warn",
    build: {
      outDir: fresh,
      emptyOutDir: false,
      target: "es2022",
      lib: { entry: path.join(root, "src", "addresses.ts"), formats: ["es"], fileName: () => "addresses.mjs" },
    },
  });
  const before = served();
  if (before !== null && existsSync(path.join(before, MANIFEST))) {
    for (const file of ownAssets(before)) {
      if (!existsSync(path.join(fresh, file))) cpSync(path.join(before, file), path.join(fresh, file));
    }
  }
  if (existsSync(dist) && before === null) {
    // A `dist` folder from before builds were linked: once, it steps aside so the link can take its name.
    renameSync(dist, path.join(builds, `${name}-unlinked`));
  }
  const link = path.join(root, `dist-link-${name}`);
  symlinkSync(path.relative(root, fresh), link);
  renameSync(link, dist); // the swap: one rename over the old link
  for (const old of readdirSync(builds)) {
    if (old !== name) rmSync(path.join(builds, old), { recursive: true, force: true });
  }
}

/** Remove what a killed build left: a build folder `dist` does not link to, and a link never swapped in. */
function sweep() {
  const kept = served();
  if (existsSync(builds)) {
    for (const old of readdirSync(builds)) {
      const folder = path.join(builds, old);
      if (folder !== kept) rmSync(folder, { recursive: true, force: true });
    }
    if (readdirSync(builds).length === 0) rmSync(builds, { recursive: true, force: true });
  }
  for (const entry of readdirSync(root)) {
    if (entry.startsWith("dist-link-")) rmSync(path.join(root, entry), { force: true });
  }
}

sweep();
try {
  await main();
} catch (error) {
  console.error(`build: ${error.message}`);
  process.exitCode = 1;
} finally {
  sweep();
}
