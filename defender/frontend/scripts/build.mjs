// The frontend build (#1161 S2, B8, #1540 F1): the app by Vite, then the address matcher alone, in library mode. Each
// build is written to a folder of its own under `dist-builds/`, and `dist` is a link to the build being served. Only a
// whole build is linked, and the link is replaced in one rename, which can't be caught halfway: `dist` is always one
// whole build, and a failed or killed build, at any step, leaves the previous one served as it was (F1 b).
//
// A browser may still hold the previous build's `index.html`, which names that build's files under `assets/` (named by
// their content, so a name never means other bytes). The new build keeps those files beside its own, so such a page
// still loads; a page two builds old gets 404 for them, and a reload fixes it.
import {
  cpSync,
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  renameSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build as vite } from "vite";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");
const builds = path.join(root, "dist-builds");
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

/** The app, then the address matcher alone (no DOM, for Bun and Node: the module the app imports), into `folder`.
 * Vite's report of a source it could not build is the problem; any other fault is this script's own, and is thrown. */
async function bundle(folder) {
  try {
    await vite({ root, logLevel: "warn", build: { outDir: folder, emptyOutDir: true, manifest: true } });
    await vite({
      root,
      configFile: false,
      publicDir: false,
      logLevel: "warn",
      build: {
        outDir: folder,
        emptyOutDir: false,
        target: "es2022",
        lib: { entry: path.join(root, "src", "addresses.ts"), formats: ["es"], fileName: () => "addresses.mjs" },
      },
    });
    return [];
  } catch (error) {
    return [error.message];
  }
}

/** Swap the build in `folder` in for the served one, keeping the served build's own `assets/` files beside its own. */
function swapIn(folder, name) {
  const before = served();
  if (before !== null && existsSync(path.join(before, MANIFEST))) {
    for (const file of ownAssets(before)) {
      if (!existsSync(path.join(folder, file))) cpSync(path.join(before, file), path.join(folder, file));
    }
  }
  if (existsSync(dist) && before === null) {
    // A `dist` folder from before builds were linked: once, it steps aside so the link can take its name.
    renameSync(dist, path.join(builds, `${name}-unlinked`));
  }
  const link = path.join(root, `dist-link-${name}`);
  symlinkSync(path.relative(root, folder), link);
  renameSync(link, dist); // the swap: one rename over the old link
}

/** Remove every build folder `dist` does not link to, and any link never swapped in: a killed build's, or the one just
 * replaced. */
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

/** The build step (after generate and check, `scripts/run.mjs`): the problems that stopped it, or none. Whatever
 * stopped it, what it left is swept. */
export async function build() {
  const name = `${Date.now()}-${process.pid}`;
  const folder = path.join(builds, name);
  sweep();
  try {
    const problems = await bundle(folder);
    if (problems.length === 0) swapIn(folder, name);
    return problems;
  } finally {
    sweep();
  }
}
