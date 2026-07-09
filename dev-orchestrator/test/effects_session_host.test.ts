// Spec: the session-host builders (§2, §9.7.1). `spawnSession` dispatches on the host kind, but
// every kind reduces to a pure command/doc builder + one `exec` (the shell, verified by running).
// Only *Open* is required (the §2 capability table), so the whole surface is a template fill.

import { describe, expect, it } from "bun:test";
import { sessionHostArgv, vscodeWorkspaceDoc } from "../src/effects/session_host";
import { fakeConfig } from "./support/config";

const card = { repo: "owner/repo", issue_number: 5, worktree_path: "/run/wt/owner__repo/issue-5" };

describe("sessionHostArgv — kind='command' fills {cwd}{resume}{sid}", () => {
  const cfg = fakeConfig({
    sessionHost: { kind: "command", command: "wezterm start --cwd {cwd} -- claude {resume} --session-id {sid}" },
  });

  it("collapses an absent {resume} to nothing", () => {
    expect(sessionHostArgv(cfg, card, { sid: "s1" })).toEqual([
      "wezterm",
      "start",
      "--cwd",
      "/run/wt/owner__repo/issue-5",
      "--",
      "claude",
      "--session-id",
      "s1",
    ]);
  });

  it("expands {resume} to --resume <S> when resuming", () => {
    expect(sessionHostArgv(cfg, card, { sid: "s1", resume: "r9" })).toEqual([
      "wezterm",
      "start",
      "--cwd",
      "/run/wt/owner__repo/issue-5",
      "--",
      "claude",
      "--resume",
      "r9",
      "--session-id",
      "s1",
    ]);
  });

  it("a card with no worktree opens at the repo's clone root (§6.6 discuss)", () => {
    const rootless = { repo: "owner/repo", issue_number: 5, worktree_path: null };
    expect(sessionHostArgv(cfg, rootless, { sid: "s1" })).toContain("/clone/owner/repo");
  });
});

describe("vscodeWorkspaceDoc — a folderOpen task, carried OUTSIDE the repo (§2)", () => {
  const cfg = fakeConfig(); // default kind: vscode

  it("opens the worktree folder and auto-runs claude with the session id on open", () => {
    const doc = vscodeWorkspaceDoc(cfg, card, { sid: "s1" });
    expect(doc.folders[0].path).toBe("/run/wt/owner__repo/issue-5");
    const task = doc.tasks.tasks[0];
    expect(task.runOptions.runOn).toBe("folderOpen");
    expect(task.command).toContain("--session-id");
    expect(task.command).toContain("s1");
  });

  it("carries --resume into the task when resuming", () => {
    const doc = vscodeWorkspaceDoc(cfg, card, { sid: "s1", resume: "r9" });
    expect(doc.tasks.tasks[0].command).toContain("--resume");
    expect(doc.tasks.tasks[0].command).toContain("r9");
  });
});

describe("discuss tuning — the interactive session honors stages.discuss (§9.9)", () => {
  const tuned = fakeConfig({ stages: { discuss: { model: "opus", effort: "xhigh" } } });

  it("vscode: appends discuss's --model/--effort to the folderOpen claude task", () => {
    const doc = vscodeWorkspaceDoc(tuned, card, { sid: "s1" });
    expect(doc.tasks.tasks[0].command).toContain("--model opus");
    expect(doc.tasks.tasks[0].command).toContain("--effort xhigh");
  });

  it("command/tmux: expands {tuning} into the argv", () => {
    const cfg = fakeConfig({
      sessionHost: { kind: "command", command: "claude --session-id {sid} {tuning}" },
      stages: { discuss: { model: "opus", effort: "xhigh" } },
    });
    expect(sessionHostArgv(cfg, card, { sid: "s1" })).toEqual(["claude", "--session-id", "s1", "--model", "opus", "--effort", "xhigh"]);
  });

  it("leaves the interactive command untouched when no discuss tuning resolves", () => {
    const doc = vscodeWorkspaceDoc(fakeConfig(), card, { sid: "s1" });
    expect(doc.tasks.tasks[0].command).not.toContain("--model");
    expect(doc.tasks.tasks[0].command).not.toContain("--effort");
  });

  it("a {tuning} placeholder collapses to nothing when no discuss tuning resolves", () => {
    const cfg = fakeConfig({ sessionHost: { kind: "command", command: "claude --session-id {sid} {tuning}" } });
    expect(sessionHostArgv(cfg, card, { sid: "s1" })).toEqual(["claude", "--session-id", "s1"]);
  });
});
