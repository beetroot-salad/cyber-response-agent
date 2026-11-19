// B1's decision, over every input of Am-5's table: 2 sources x 4 takes of the attempt record x 2 ways of arriving.
import { describe, expect, it } from "vitest";
import { decideUnauthorized, type Decision, type FailedReason, type Source, type Taken } from "./decision";

const NONE: Taken = { status: "none" };
const FOUND_FIRST: Taken = { status: "found", again: false };
const FOUND_AGAIN: Taken = { status: "found", again: true };
const UNAVAILABLE: Taken = { status: "unavailable" };

const SIGN_IN_FIRST: Decision = { kind: "sign-in", again: false };
const SIGN_IN_AGAIN: Decision = { kind: "sign-in", again: true };
const failed = (reason: FailedReason): Decision => ({
  kind: "failed",
  reason,
});

interface Case {
  readonly source: Source;
  readonly label: string;
  readonly taken: Taken;
  readonly byHistory: boolean;
  readonly expected: Decision;
}
/** One case: source, the record's label, the record, byHistory, and the decision expected. */
type Row = readonly [Source, string, Taken, boolean, Decision];

const ROWS: readonly Row[] = [
  ["me", "none", NONE, false, SIGN_IN_FIRST],
  ["me", "none", NONE, true, SIGN_IN_FIRST],
  ["me", "found", FOUND_FIRST, false, failed("session-lost")],
  ["me", "found", FOUND_FIRST, true, failed("sign-in-left")],
  ["me", "found again", FOUND_AGAIN, false, failed("session-lost")],
  ["me", "found again", FOUND_AGAIN, true, failed("sign-in-left")],
  ["me", "unavailable", UNAVAILABLE, false, failed("storage-unavailable")],
  ["me", "unavailable", UNAVAILABLE, true, failed("storage-unavailable")],
  ["later", "none", NONE, false, SIGN_IN_FIRST],
  ["later", "none", NONE, true, SIGN_IN_FIRST],
  ["later", "found", FOUND_FIRST, false, SIGN_IN_AGAIN],
  ["later", "found", FOUND_FIRST, true, SIGN_IN_AGAIN],
  ["later", "found again", FOUND_AGAIN, false, failed("session-refused")],
  ["later", "found again", FOUND_AGAIN, true, failed("session-refused")],
  ["later", "unavailable", UNAVAILABLE, false, failed("storage-unavailable")],
  ["later", "unavailable", UNAVAILABLE, true, failed("storage-unavailable")],
];
const TABLE: readonly Case[] = ROWS.map(([source, label, taken, byHistory, expected]) => ({
  source,
  label,
  taken,
  byHistory,
  expected,
}));

describe("decideUnauthorized", () => {
  it("is tested over all 16 combinations of source, taken and byHistory", () => {
    expect(new Set(TABLE.map((c) => `${c.source}/${c.label}/${c.byHistory}`)).size).toBe(16);
  });

  it.each(TABLE)("$source, record $label, byHistory=$byHistory", ({ source, taken, byHistory, expected }) => {
    expect(decideUnauthorized({ source, taken, byHistory })).toEqual(expected);
  });
});
