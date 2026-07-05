// Spec: the gh effect parsers (§9.7.1). Each real effect is `gh <argv>` + a pure parser; only the
// parser is pinned here (the `gh` call is verified by running, §10). Grounded against the installed
// CLI: `gh issue create` has NO --json (it prints the URL), and `gh pr view --json state` already
// distinguishes MERGED from CLOSED — so no mergedAt is read.

import { describe, expect, it } from "bun:test";
import { parseIssueList, parseIssueNumberFromUrl, parsePrState } from "../src/effects/gh";

describe("parseIssueNumberFromUrl — gh issue create prints a URL, not json", () => {
  it("takes the trailing /issues/<n>", () => {
    expect(parseIssueNumberFromUrl("https://github.com/owner/repo/issues/123")).toBe(123);
  });

  it("tolerates trailing whitespace / newline from stdout", () => {
    expect(parseIssueNumberFromUrl("https://github.com/owner/repo/issues/7\n")).toBe(7);
  });

  it("throws on output with no issue number (surface the failure, never invent a card)", () => {
    expect(() => parseIssueNumberFromUrl("error: could not create issue")).toThrow();
  });
});

describe("parseIssueList — gh issue list --json number,title → IssueRef[]", () => {
  it("stamps each row with the repo it was listed from", () => {
    const json = JSON.stringify([
      { number: 7, title: "first" },
      { number: 9, title: "second" },
    ]);
    expect(parseIssueList(json, "owner/repo")).toEqual([
      { repo: "owner/repo", issue_number: 7, title: "first" },
      { repo: "owner/repo", issue_number: 9, title: "second" },
    ]);
  });

  it("empty list → no refs", () => {
    expect(parseIssueList("[]", "owner/repo")).toEqual([]);
  });
});

describe("parsePrState — gh pr view --json state", () => {
  it("maps the three PR states verbatim", () => {
    expect(parsePrState('{"state":"MERGED"}')).toBe("merged");
    expect(parsePrState('{"state":"CLOSED"}')).toBe("closed");
    expect(parsePrState('{"state":"OPEN"}')).toBe("open");
  });

  it("throws on an unrecognized state (never silently treat unknown as open drift)", () => {
    expect(() => parsePrState('{"state":"DRAFT"}')).toThrow();
  });
});
