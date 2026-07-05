// The entrypoint (§9.8): boot the process from the loaded config, then log where the board lives.
// Run with `bun src/main.ts` (config via FLOWDECK_CONFIG / FLOWDECK_* env, §9.9).

import { boot } from "./boot";
import { loadConfig } from "./config";

const cfg = loadConfig();
boot(cfg);
console.log(`flowdeck — board + /rpc on http://localhost:${cfg.port}  (runRoot ${cfg.runRoot}, ${cfg.repos.length} repo(s))`);
