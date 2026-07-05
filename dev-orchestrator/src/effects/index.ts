// realEffects — compose the real subprocess effects into the one injected `Effects` seam (§9.7.1).
// The engine never widens; only this layer becomes real. now()/uuid() are wall clock / real uuid
// (the fake's stable clock + counter stand in under test).

import type { Config, Effects } from "../contract";
import { makeHeadlessEffects } from "./claude";
import { makeGhEffects } from "./gh";
import { makeGitEffects } from "./git";
import { makeReap } from "./reap";
import { makeSessionHostEffects } from "./session_host";

export function realEffects(cfg: Config): Effects {
  return {
    ...makeGitEffects(cfg),
    ...makeHeadlessEffects(cfg),
    ...makeSessionHostEffects(cfg),
    kill: makeReap(cfg),
    gh: makeGhEffects(cfg),
    now: () => new Date().toISOString(),
    uuid: () => crypto.randomUUID(),
  };
}
