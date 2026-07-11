// The headless `claude -p` effect (§9.7.1): pure argv/prompt/parse builders + a `Bun.spawn` shell
// under `setsid` (one process group per run). session_id is assigned + persisted BEFORE the spawn
// by the worker (§9.7), so parseRunResult only confirms what the run reported; pr_number is
// discovered post-run via `gh pr list --head`.

import type { CardState, Config, RunResult, RunRow, RunStage } from "../contract";
import { repoConfigFor } from "./git";
import { writePidfile } from "./reap";

type CardRef = Pick<CardState, "repo" | "issue_number" | "worktree_path">;

/** Per-stage prompt — one skill per stage, cold-started from the issue (§7.5, §1.8). Wording is
 *  tunable; what's fixed is: names the repo + issue, and dispatches each stage to its own skill. */
export function headlessPrompt(run: Pick<RunRow, "stage">, card: Pick<CardState, "repo" | "issue_number">): string {
  const at = `${card.repo} issue #${card.issue_number}`;
  switch (run.stage) {
    case "write_tests":
      return `Run the write-tests skill for ${at}: turn the approved design captured in the issue into an executable test spec, commit it on the branch, and stop. Do not implement.`;
    case "write_code":
      return `Run the write-code-from-spec skill for ${at}: implement the code against the committed test spec, ship a PR, and watch CI until it is green.`;
    case "review":
      return [
        `Run /code-review --fix for ${at}.`,
        `Apply every fix you're confident in directly — don't hold back to only the trivial ones — then re-green the PR (push commits, get CI green before finishing).`,
        `Look past the diff: a smell or bug in the code this change touches or depends on counts even when it isn't in the changed lines.`,
        `Read the prior review trail for this work — the follow-up issues already filed and earlier review comments on the PR — and reconcile what was skipped before: do the cheap cleanups that were deferred, fix-or-file bugs in related (out-of-diff) code, and leave only genuine design choices for a human.`,
        `File a follow-up issue for anything you surface but don't fix inline — name the finding and where it lives.`,
      ].join(" ");
    default:
      return `Run the ${run.stage} skill for ${at}.`;
  }
}

/** Resolve a stage's model + effort (§9.9): a `stages[stage]` override wins per-field, else
 *  `defaults`, else "" (which omits the flag so the claude CLI applies its own default). */
export function stageTuning(stage: RunStage, cfg: Config): { model: string; effort: string } {
  const over = cfg.stages[stage] ?? {};
  return {
    model: over.model ?? cfg.defaults.model ?? "",
    effort: over.effort ?? cfg.defaults.effort ?? "",
  };
}

/** A stage's `--model` / `--effort` flags (each omitted when empty). Shared by the headless argv
 *  and the interactive session-host launch, so both honor the same per-stage tuning (§9.9). */
export function tuningArgv(stage: RunStage, cfg: Config): string[] {
  const { model, effort } = stageTuning(stage, cfg);
  const argv: string[] = [];
  if (model) argv.push("--model", model);
  if (effort) argv.push("--effort", effort);
  return argv;
}

/** `setsid claude -p <prompt> --session-id <sid> --output-format json …` — the full spawn argv. */
export function headlessArgv(run: Pick<RunRow, "stage">, card: CardRef, sessionId: string, cfg: Config): string[] {
  const argv = [
    "setsid",
    "claude",
    "-p",
    headlessPrompt(run, card),
    "--session-id",
    sessionId,
    "--output-format",
    "json",
    "--permission-mode",
    cfg.permissionMode,
    "--add-dir",
    card.worktree_path ?? "",
  ];
  argv.push(...tuningArgv(run.stage, cfg));
  return argv;
}

/** ok = exit 0 AND the run's json result reported is_error === false. Anything unconfirmable
 *  (non-zero exit, missing/true is_error, unparseable stdout) is a failure — never claim success. */
export function parseRunResult(exitCode: number, stdout: string, prNumber?: number): RunResult {
  let isError = true;
  let sessionId: string | undefined;
  try {
    const j = JSON.parse(stdout) as { is_error?: boolean; session_id?: string };
    isError = j.is_error !== false;
    sessionId = j.session_id;
  } catch {
    isError = true;
  }
  return { ok: exitCode === 0 && !isError, session_id: sessionId, pr_number: prNumber };
}

const PR_BEARING: readonly RunStage[] = ["write_code", "review"];

// --- imperative shell -------------------------------------------------------

/** Discover the PR the run shipped, by branch head (write_code / review only). */
function discoverPr(card: CardRef, cfg: Config): number | undefined {
  try {
    const repo = repoConfigFor(card.repo, cfg);
    const p = Bun.spawnSync(["gh", "pr", "list", "-R", repo.name, "--head", `flow/issue-${card.issue_number}`, "--json", "number"]);
    if (p.exitCode !== 0) return undefined;
    const rows = JSON.parse(p.stdout.toString()) as { number: number }[];
    return rows[0]?.number;
  } catch {
    return undefined;
  }
}

export function makeHeadlessEffects(cfg: Config) {
  return {
    spawnHeadless(run: RunRow, card: CardState, sessionId: string): { pid: number; done: Promise<RunResult> } {
      const argv = headlessArgv(run, card, sessionId, cfg);
      const proc = Bun.spawn(argv, { cwd: card.worktree_path ?? undefined, stdout: "pipe", stderr: "pipe" });
      const pid = proc.pid;
      writePidfile(cfg.runRoot, run.id, pid);
      const done = (async (): Promise<RunResult> => {
        const [exitCode, stdout] = await Promise.all([proc.exited, new Response(proc.stdout).text()]);
        const pr = PR_BEARING.includes(run.stage) ? discoverPr(card, cfg) : undefined;
        return parseRunResult(exitCode, stdout, pr);
      })();
      return { pid, done };
    },
  };
}
