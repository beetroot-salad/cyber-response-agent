// Spec: the git-worktree effect builders (§9.7.1). Pure fns — a path/argv/parse is a total
// function of (card, cfg, stdout), so no real `git` runs here; the imperative `git -C` shell is
// verified by running (§10). The path scheme is load-bearing: it ENCODES the repo, so the
// card-less reconcile sweep (`removeWorktreePath`) can recover the owning repo for `git -C`.

import { describe, expect, it } from "bun:test";
import {
  parseWorktreePorcelain,
  repoRootForPath,
  underRunRoot,
  worktreeAddArgv,
  worktreeBranch,
  worktreePath,
  worktreeRemoveArgv,
} from "../src/effects/git";
import { fakeConfig } from "./support/config";

const cfg = fakeConfig(); // runRoot "/run"; repo owner/repo → root "/clone/owner/repo", base "origin/main"
const card = { repo: "owner/repo", issue_number: 3 };

describe("worktree path + branch — a pure fn of the card", () => {
  it("encodes <owner>__<name> in the path so an orphan path recovers its repo", () => {
    expect(worktreePath(card, cfg)).toBe("/run/wt/owner__repo/issue-3");
  });

  it("names the branch flow/issue-<n>", () => {
    expect(worktreeBranch(card)).toBe("flow/issue-3");
  });

  it("is deterministic — the same card re-derives the SAME path (idempotent retry, §9.7)", () => {
    expect(worktreePath(card, cfg)).toBe(worktreePath({ ...card }, cfg));
  });
});

describe("worktree argv — git args after the `git` token", () => {
  it("add -B <branch> <path> <base>, rooted at the repo's local clone", () => {
    expect(worktreeAddArgv(card, cfg)).toEqual([
      "-C",
      "/clone/owner/repo",
      "worktree",
      "add",
      "-B",
      "flow/issue-3",
      "/run/wt/owner__repo/issue-3",
      "origin/main",
    ]);
  });

  it("remove --force <path>, rooted at the repo clone", () => {
    expect(worktreeRemoveArgv("/clone/owner/repo", "/run/wt/owner__repo/issue-3")).toEqual([
      "-C",
      "/clone/owner/repo",
      "worktree",
      "remove",
      "--force",
      "/run/wt/owner__repo/issue-3",
    ]);
  });
});

describe("porcelain parse + run-root filter — listWorktrees' pure half", () => {
  // `git worktree list --porcelain` — blocks of worktree/HEAD/branch, blank-line separated. The
  // main checkout is ALWAYS listed, so it must be filtered out (§9.7 "under the run root").
  const porcelain = [
    "worktree /clone/owner/repo",
    "HEAD abc123",
    "branch refs/heads/main",
    "",
    "worktree /run/wt/owner__repo/issue-3",
    "HEAD def456",
    "branch refs/heads/flow/issue-3",
    "",
    "worktree /run/wt/owner__repo/issue-9",
    "HEAD 000aaa",
    "detached",
    "",
  ].join("\n");

  it("takes every `worktree <path>` line", () => {
    expect(parseWorktreePorcelain(porcelain)).toEqual([
      "/clone/owner/repo",
      "/run/wt/owner__repo/issue-3",
      "/run/wt/owner__repo/issue-9",
    ]);
  });

  it("empty output → no paths", () => {
    expect(parseWorktreePorcelain("")).toEqual([]);
  });

  it("keeps only paths under <runRoot>/wt/ — the main checkout drops out", () => {
    const all = parseWorktreePorcelain(porcelain);
    expect(underRunRoot(all, "/run")).toEqual(["/run/wt/owner__repo/issue-3", "/run/wt/owner__repo/issue-9"]);
  });
});

describe("path → repo recovery — the sweep holds only a path", () => {
  it("maps <owner>__<name> back to that repo's clone root", () => {
    expect(repoRootForPath("/run/wt/owner__repo/issue-3", cfg)).toBe("/clone/owner/repo");
  });

  it("throws on a path whose repo segment matches no configured repo (never force-remove a foreign tree)", () => {
    expect(() => repoRootForPath("/run/wt/someone__else/issue-1", cfg)).toThrow();
  });
});
