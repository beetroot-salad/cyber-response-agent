// The git-worktree effect (§9.7.1): pure path/argv/parse builders + a thin `git -C` shell. The
// path ENCODES the repo (`<owner>__<name>`) so the card-less reconcile sweep can recover the owning
// repo for `git -C` from a path alone.

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { CardState, Config, RepoConfig } from "../contract";

type CardRef = Pick<CardState, "repo" | "issue_number">;

/** "owner/name" → "owner__name" — the path-safe repo segment (and its inverse below). */
function repoSlug(repo: string): string {
  return repo.replace(/\//g, "__");
}

/** The configured repo for a "owner/name", or throw (a card must name a configured repo). */
export function repoConfigFor(repo: string, cfg: Config): RepoConfig {
  const r = cfg.repos.find((x) => x.name === repo);
  if (!r) throw new Error(`no configured repo '${repo}'`);
  return r;
}

/** Deterministic worktree path — a pure fn of the card (§9.7). */
export function worktreePath(card: CardRef, cfg: Config): string {
  return `${cfg.runRoot}/wt/${repoSlug(card.repo)}/issue-${card.issue_number}`;
}

export function worktreeBranch(card: Pick<CardState, "issue_number">): string {
  return `flow/issue-${card.issue_number}`;
}

/** `git <these>` — add -B <branch> <path> <base>, rooted at the repo's local clone. */
export function worktreeAddArgv(card: CardRef, cfg: Config): string[] {
  const repo = repoConfigFor(card.repo, cfg);
  return ["-C", repo.root, "worktree", "add", "-B", worktreeBranch(card), worktreePath(card, cfg), repo.base];
}

/** `git <these>` — remove --force <path>, rooted at the repo clone. */
export function worktreeRemoveArgv(repoRoot: string, path: string): string[] {
  return ["-C", repoRoot, "worktree", "remove", "--force", path];
}

/** Every `worktree <path>` line from `git worktree list --porcelain` (the main checkout included). */
export function parseWorktreePorcelain(stdout: string): string[] {
  const PREFIX = "worktree ";
  return stdout
    .split("\n")
    .filter((l) => l.startsWith(PREFIX))
    .map((l) => l.slice(PREFIX.length).trim());
}

/** Keep only trees under `<runRoot>/wt/` — drops each repo's own main checkout (§9.7). */
export function underRunRoot(paths: string[], runRoot: string): string[] {
  const prefix = `${runRoot}/wt/`;
  return paths.filter((p) => p.startsWith(prefix));
}

/** Recover the owning repo's clone root from an orphan worktree PATH alone (the sweep has no card). */
export function repoRootForPath(path: string, cfg: Config): string {
  const prefix = `${cfg.runRoot}/wt/`;
  const rel = path.startsWith(prefix) ? path.slice(prefix.length) : path;
  const slug = rel.split("/")[0];
  const repo = cfg.repos.find((r) => repoSlug(r.name) === slug);
  if (!repo) throw new Error(`no configured repo for worktree path '${path}'`);
  return repo.root;
}

// --- imperative shell -------------------------------------------------------

function runGit(argv: string[]): string {
  const p = Bun.spawnSync(["git", ...argv]);
  if (p.exitCode !== 0) throw new Error(`git ${argv.join(" ")} failed: ${p.stderr.toString().trim()}`);
  return p.stdout.toString();
}

export function makeGitEffects(cfg: Config) {
  return {
    createWorktree(card: CardState): string {
      const path = worktreePath(card, cfg);
      const repo = repoConfigFor(card.repo, cfg);
      // Idempotent retry (§9.7): if the tree is already registered, reuse it — no reset.
      const existing = parseWorktreePorcelain(runGit(["-C", repo.root, "worktree", "list", "--porcelain"]));
      if (existing.includes(path)) return path;
      mkdirSync(dirname(path), { recursive: true });
      runGit(worktreeAddArgv(card, cfg));
      return path;
    },
    removeWorktree(card: CardState): void {
      if (!card.worktree_path) return;
      const repo = repoConfigFor(card.repo, cfg);
      runGit(worktreeRemoveArgv(repo.root, card.worktree_path));
      try {
        runGit(["-C", repo.root, "worktree", "prune"]);
      } catch {
        /* prune is best-effort */
      }
    },
    removeWorktreePath(path: string): void {
      const root = repoRootForPath(path, cfg);
      runGit(worktreeRemoveArgv(root, path));
      try {
        runGit(["-C", root, "worktree", "prune"]);
      } catch {
        /* prune is best-effort */
      }
    },
    listWorktrees(): string[] {
      const all: string[] = [];
      for (const repo of cfg.repos) {
        try {
          all.push(...parseWorktreePorcelain(runGit(["-C", repo.root, "worktree", "list", "--porcelain"])));
        } catch {
          /* a per-repo blip skips that repo, never the whole sweep */
        }
      }
      return underRunRoot(all, cfg.runRoot);
    },
  };
}
