// The GitHub effect (§9.7.1): pure parsers + a thin `gh` shell. Grounded against the installed CLI:
// `gh issue create` has NO --json (it prints the issue URL); `gh pr view --json state` already
// distinguishes MERGED from CLOSED (no mergedAt read).

import type { Config, IssueRef, PrState } from "../contract";

/** `gh issue create` prints the new issue's URL — take the trailing /issues/<n>. */
export function parseIssueNumberFromUrl(stdout: string): number {
  const m = stdout.match(/\/issues\/(\d+)\b/);
  if (!m) throw new Error(`no issue number in gh output: ${stdout.trim()}`);
  return Number(m[1]);
}

/** `gh issue list --json number,title` → IssueRef[], stamped with the repo it was listed from. */
export function parseIssueList(json: string, repo: string): IssueRef[] {
  const rows = JSON.parse(json) as { number: number; title: string }[];
  return rows.map((r) => ({ repo, issue_number: r.number, title: r.title }));
}

/** `gh pr view --json state` → the drift signal. Unknown state throws (never silently "open"). */
export function parsePrState(json: string): PrState {
  const state = (JSON.parse(json) as { state: string }).state;
  switch (state) {
    case "MERGED":
      return "merged";
    case "CLOSED":
      return "closed";
    case "OPEN":
      return "open";
    default:
      throw new Error(`unrecognized PR state: ${state}`);
  }
}

// --- imperative shell -------------------------------------------------------

function runGh(argv: string[]): string {
  const p = Bun.spawnSync(["gh", ...argv]);
  if (p.exitCode !== 0) throw new Error(`gh ${argv.join(" ")} failed: ${p.stderr.toString().trim()}`);
  return p.stdout.toString();
}

export function makeGhEffects(cfg: Config) {
  return {
    issueCreate(input: { repo: string; title: string; body?: string }): { issue_number: number } {
      const argv = ["issue", "create", "-R", input.repo, "--title", input.title, "--label", cfg.label];
      if (input.body) argv.push("--body", input.body);
      return { issue_number: parseIssueNumberFromUrl(runGh(argv)) };
    },
    // The poller calls this repo-agnostically ({ label }), so list every configured repo and union.
    issueList(input: { repo?: string; label?: string }): IssueRef[] {
      const label = input.label ?? cfg.label;
      const repos = input.repo ? cfg.repos.filter((r) => r.name === input.repo) : cfg.repos;
      const out: IssueRef[] = [];
      for (const repo of repos) {
        try {
          const json = runGh(["issue", "list", "-R", repo.name, "--label", label, "--state", "open", "--json", "number,title"]);
          out.push(...parseIssueList(json, repo.name));
        } catch {
          /* a per-repo list blip skips that repo, never the whole poll (SB-I) */
        }
      }
      return out;
    },
    prStatus(input: { repo: string; pr_number: number }): PrState {
      return parsePrState(runGh(["pr", "view", String(input.pr_number), "-R", input.repo, "--json", "state"]));
    },
  };
}
