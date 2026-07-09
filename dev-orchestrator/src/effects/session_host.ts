// The interactive session host (§2, §9.7.1): pure command/doc builders + one detached `exec`. Only
// *Open* is required (the §2 capability table), so every adapter reduces to a template fill. The
// board never parents the session (§2) — a discuss run resolves via the card's Done/Discard button.

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import type { CardState, Config } from "../contract";
import { tuningArgv } from "./claude";
import { repoConfigFor } from "./git";

type CardRef = Pick<CardState, "repo" | "issue_number" | "worktree_path">;
interface Launch {
  sid: string;
  resume?: string;
}

/** discuss opens at the card's worktree, else the repo's main checkout root (§6.6). */
function openCwd(card: CardRef, cfg: Config): string {
  return card.worktree_path ?? repoConfigFor(card.repo, cfg).root;
}

/** kind="command" / "tmux": fill the {cwd}{resume}{sid}{tuning} template into an argv. `{tuning}`
 *  expands to discuss's `--model`/`--effort` (§9.9), empty when unset. */
export function sessionHostArgv(cfg: Config, card: CardRef, launch: Launch): string[] {
  const tmpl = cfg.sessionHost.command;
  if (!tmpl) throw new Error("session_host.command is required for kind=command/tmux");
  const resume = launch.resume ? `--resume ${launch.resume}` : "";
  return tmpl
    .replace(/\{cwd\}/g, openCwd(card, cfg))
    .replace(/\{resume\}/g, resume)
    .replace(/\{sid\}/g, launch.sid)
    .replace(/\{tuning\}/g, tuningArgv("discuss", cfg).join(" "))
    .split(/\s+/)
    .filter(Boolean);
}

/** kind="vscode": a .code-workspace with a folderOpen task that seeds the claude session (§2). Carried
 *  OUTSIDE the repo (in the run root) so the tracked .vscode/ is never mutated. */
export function vscodeWorkspaceDoc(cfg: Config, card: CardRef, launch: Launch) {
  const resume = launch.resume ? `--resume ${launch.resume} ` : "";
  const tuning = tuningArgv("discuss", cfg);
  const tuningStr = tuning.length ? ` ${tuning.join(" ")}` : "";
  return {
    folders: [{ path: openCwd(card, cfg) }],
    settings: { "task.allowAutomaticTasks": "on" },
    tasks: {
      version: "2.0.0",
      tasks: [
        {
          label: "flowdeck: claude session",
          type: "shell",
          command: `claude ${resume}--session-id ${launch.sid}${tuningStr}`,
          runOptions: { runOn: "folderOpen" },
          presentation: { reveal: "always", panel: "dedicated" },
          problemMatcher: [],
        },
      ],
    },
  };
}

// --- imperative shell -------------------------------------------------------

function detach(argv: string[]): void {
  // Fire-and-forget: the board does not parent an interactive session (§2).
  Bun.spawn(argv, { stdin: "ignore", stdout: "ignore", stderr: "ignore" }).unref();
}

export function makeSessionHostEffects(cfg: Config) {
  return {
    spawnSession(card: CardState, resume?: string): void {
      // discuss session ids fall back to reading ~/.claude (§2 capability table) — we generate one
      // for hosts that can carry --session-id; persisting it onto the run is a documented follow-up.
      const launch: Launch = { sid: crypto.randomUUID(), resume };
      switch (cfg.sessionHost.kind) {
        case "vscode": {
          const wsPath = join(cfg.runRoot, `issue-${card.issue_number}.code-workspace`);
          writeFileSync(wsPath, JSON.stringify(vscodeWorkspaceDoc(cfg, card, launch), null, 2));
          detach(["code", wsPath]);
          return;
        }
        case "command":
        case "tmux":
          detach(sessionHostArgv(cfg, card, launch));
          return;
        default:
          throw new Error(`session host kind '${cfg.sessionHost.kind}' is not wired in this slice`);
      }
    },
  };
}
