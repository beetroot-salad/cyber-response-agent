// A Config for tests — the injected §9.9 object, never a file read. Overridable per test so a
// case can flip a single field (a second repo, a `command` session host, a model override) without
// restating the whole shape. The defaults mirror the §9.9 local/single-repo defaults.

import type { Config } from "../../src/contract";

export function fakeConfig(over: Partial<Config> = {}): Config {
  return {
    runRoot: "/run",
    label: "flow",
    pool: 2,
    pollMs: 30000,
    workerTickMs: 1000,
    port: 8765,
    permissionMode: "acceptEdits",
    model: "",
    repos: [{ name: "owner/repo", root: "/clone/owner/repo", base: "origin/main" }],
    sessionHost: { kind: "vscode" },
    ...over,
  };
}
