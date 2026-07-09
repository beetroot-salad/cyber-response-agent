// loadConfig (§9.9) — one injected Config, built from §9.9 defaults, overlaid by an optional JSON
// config file (FLOWDECK_CONFIG) and a few env knobs. JSON (not TOML) for V1 to stay zero-dep — the
// shape is identical. Config is injected everywhere; this reads it once at boot, never in the hot path.

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Config } from "./contract";

function defaults(): Config {
  return {
    runRoot: process.env.FLOWDECK_RUN_ROOT ?? join(homedir(), ".flowdeck"),
    label: process.env.FLOWDECK_LABEL ?? "flow",
    pool: Number(process.env.FLOWDECK_POOL ?? 2),
    pollMs: Number(process.env.FLOWDECK_POLL_MS ?? 30000),
    workerTickMs: Number(process.env.FLOWDECK_WORKER_TICK_MS ?? 1000),
    port: Number(process.env.FLOWDECK_PORT ?? 8765),
    permissionMode: process.env.FLOWDECK_PERMISSION_MODE ?? "auto",
    // Global fallback (§9.9) — empty model/effort means "let the claude CLI pick its own default".
    defaults: { model: process.env.FLOWDECK_MODEL ?? "", effort: process.env.FLOWDECK_EFFORT ?? "" },
    stages: {},
    repos: [],
    sessionHost: { kind: "vscode" },
  };
}

export function loadConfig(): Config {
  const base = defaults();
  const path = process.env.FLOWDECK_CONFIG;
  if (!path || !existsSync(path)) return base;
  const file = JSON.parse(readFileSync(path, "utf8")) as Partial<Config>;
  return {
    ...base,
    ...file,
    // Deep-merge the nested blocks so a file that sets only one sub-field keeps the base for the rest.
    defaults: { ...base.defaults, ...file.defaults },
    stages: { ...base.stages, ...file.stages },
    sessionHost: { ...base.sessionHost, ...file.sessionHost },
  };
}
