// Spec: loadConfig (§9.9) — the §9.9 defaults, the FLOWDECK_CONFIG file overlay, and the per-block
// merge that lets a config file set one sub-field while keeping the base for the rest. loadConfig reads
// env + one JSON file; both are isolated here (FLOWDECK_* cleared, a tmp file) so the merge is pinned
// deterministically — the default permissionMode ("auto") and the nested defaults/stages merge otherwise
// ship untested (the fakeConfig helper is a hand-built literal, never loadConfig's own overlay).

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "../src/config";

// The FLOWDECK_* knobs loadConfig reads — cleared per test so a host env never leaks into a default.
const ENV_KEYS = [
  "FLOWDECK_CONFIG",
  "FLOWDECK_PERMISSION_MODE",
  "FLOWDECK_MODEL",
  "FLOWDECK_EFFORT",
  "FLOWDECK_RUN_ROOT",
  "FLOWDECK_LABEL",
  "FLOWDECK_POOL",
  "FLOWDECK_POLL_MS",
  "FLOWDECK_WORKER_TICK_MS",
  "FLOWDECK_PORT",
] as const;

let dir: string;
let saved: Record<string, string | undefined>;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "flowdeck-cfg-"));
  saved = {};
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  rmSync(dir, { recursive: true, force: true });
});

// Write a JSON config into the tmp dir and point FLOWDECK_CONFIG at it.
function withFile(obj: unknown): void {
  const p = join(dir, "flowdeck.config.json");
  writeFileSync(p, JSON.stringify(obj));
  process.env.FLOWDECK_CONFIG = p;
}

describe("loadConfig — §9.9 defaults (no config file)", () => {
  it("defaults permissionMode to 'auto' and leaves model/effort empty", () => {
    const cfg = loadConfig();
    expect(cfg.permissionMode).toBe("auto");
    expect(cfg.defaults).toEqual({ model: "", effort: "" });
    expect(cfg.stages).toEqual({});
  });
});

describe("loadConfig — the FLOWDECK_CONFIG file overlay + per-block merge", () => {
  it("a file that sets only stages.review.model keeps the base defaults + permissionMode", () => {
    withFile({ stages: { review: { model: "opus" } } });
    const cfg = loadConfig();
    expect(cfg.stages.review).toEqual({ model: "opus" });
    expect(cfg.defaults).toEqual({ model: "", effort: "" }); // base kept, not wiped by the partial overlay
    expect(cfg.permissionMode).toBe("auto");
  });

  it("a file that sets only defaults.effort keeps the base defaults.model (per-sub-field merge)", () => {
    withFile({ defaults: { effort: "high" } });
    expect(loadConfig().defaults).toEqual({ model: "", effort: "high" });
  });

  it("a file permissionMode overrides the 'auto' default", () => {
    withFile({ permissionMode: "acceptEdits" });
    expect(loadConfig().permissionMode).toBe("acceptEdits");
  });
});
