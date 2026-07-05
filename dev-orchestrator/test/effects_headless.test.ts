// Spec: the headless `claude -p` effect (§9.7.1). The argv + the stage prompt + the RunResult
// parse are pure and pinned here; the `Bun.spawn` under `setsid` (process group) + the pidfile are
// verified by running (§10). session_id is CONFIRMATORY — it was assigned + persisted before the
// spawn (§9.7), so parseRunResult only surfaces what the run reported, never a second source.

import { describe, expect, it } from "bun:test";
import { headlessArgv, headlessPrompt, parseRunResult } from "../src/effects/claude";
import { fakeConfig } from "./support/config";

const card = { repo: "owner/repo", issue_number: 5, worktree_path: "/run/wt/owner__repo/issue-5" };

describe("headlessPrompt — one skill per stage, cold from the issue (§7.5, §1.8)", () => {
  it("names the issue the stage cold-starts from", () => {
    for (const stage of ["write_tests", "write_code", "review"] as const) {
      const p = headlessPrompt({ stage }, card);
      expect(p).toContain("#5");
      expect(p).toContain("owner/repo");
    }
  });

  it("dispatches each stage to its own skill", () => {
    expect(headlessPrompt({ stage: "write_tests" }, card)).toContain("write-tests");
    expect(headlessPrompt({ stage: "write_code" }, card)).toContain("write-code-from-spec");
    expect(headlessPrompt({ stage: "review" }, card)).toContain("code-review");
  });

  it("the three stage prompts are distinct (a stage never runs another stage's skill)", () => {
    const t = headlessPrompt({ stage: "write_tests" }, card);
    const c = headlessPrompt({ stage: "write_code" }, card);
    const r = headlessPrompt({ stage: "review" }, card);
    expect(new Set([t, c, r]).size).toBe(3);
  });
});

describe("headlessArgv — setsid claude -p … --session-id … --output-format json", () => {
  const run = { stage: "write_tests" as const };

  it("builds the full argv, rooting the run at the card's worktree via --add-dir", () => {
    expect(headlessArgv(run, card, "sid-1", fakeConfig())).toEqual([
      "setsid",
      "claude",
      "-p",
      headlessPrompt(run, card),
      "--session-id",
      "sid-1",
      "--output-format",
      "json",
      "--permission-mode",
      "acceptEdits",
      "--add-dir",
      "/run/wt/owner__repo/issue-5",
    ]);
  });

  it("appends --model only when configured", () => {
    const argv = headlessArgv(run, card, "sid-1", fakeConfig({ model: "opus" }));
    expect(argv.slice(-2)).toEqual(["--model", "opus"]);
  });
});

describe("parseRunResult — ok = exit 0 AND is_error === false", () => {
  it("clean exit + is_error:false → ok, surfacing the reported session_id", () => {
    expect(parseRunResult(0, '{"is_error":false,"session_id":"s9"}')).toEqual({
      ok: true,
      session_id: "s9",
      pr_number: undefined,
    });
  });

  it("threads through the discovered pr_number", () => {
    expect(parseRunResult(0, '{"is_error":false,"session_id":"s9"}', 441)).toMatchObject({ ok: true, pr_number: 441 });
  });

  it("is_error:true → failed even on a 0 exit", () => {
    expect(parseRunResult(0, '{"is_error":true,"session_id":"s9"}').ok).toBe(false);
  });

  it("non-zero exit → failed", () => {
    expect(parseRunResult(1, '{"is_error":false}').ok).toBe(false);
  });

  it("unparseable stdout → failed (can't confirm is_error, so don't claim success)", () => {
    const r = parseRunResult(0, "claude crashed before emitting json");
    expect(r.ok).toBe(false);
    expect(r.session_id).toBeUndefined();
  });
});
