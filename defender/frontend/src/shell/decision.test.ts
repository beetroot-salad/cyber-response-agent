// B1's decision, over every input of Am-5's table: 2 sources x 4 takes of the attempt record x 2 ways of arriving.
import { describe, expect, it } from "vitest";
import { decideUnauthorized, type Decision, type Taken } from "./decision";

const NONE: Taken = { status: "none" };
const FOUND_FIRST: Taken = { status: "found", again: false };
const FOUND_AGAIN: Taken = { status: "found", again: true };
const UNAVAILABLE: Taken = { status: "unavailable" };

const SIGN_IN_FIRST: Decision = { kind: "sign-in", again: false };
const SIGN_IN_AGAIN: Decision = { kind: "sign-in", again: true };
const failed = (reason: "session-lost" | "sign-in-left" | "storage-unavailable" | "session-refused"): Decision => ({
  kind: "failed",
  reason,
});

type Source = "me" | "later";
interface Case {
  readonly source: Source;
  readonly label: string;
  readonly taken: Taken;
  readonly byHistory: boolean;
  readonly expected: Decision;
}
const row = (source: Source, label: string, taken: Taken, byHistory: boolean, expected: Decision): Case => ({
  source,
  label,
  taken,
  byHistory,
  expected,
});

const TABLE: readonly Case[] = [
  row("me", "none", NONE, false, SIGN_IN_FIRST),
  row("me", "none", NONE, true, SIGN_IN_FIRST),
  row("me", "found", FOUND_FIRST, false, failed("session-lost")),
  row("me", "found", FOUND_FIRST, true, failed("sign-in-left")),
  row("me", "found again", FOUND_AGAIN, false, failed("session-lost")),
  row("me", "found again", FOUND_AGAIN, true, failed("sign-in-left")),
  row("me", "unavailable", UNAVAILABLE, false, failed("storage-unavailable")),
  row("me", "unavailable", UNAVAILABLE, true, failed("storage-unavailable")),
  row("later", "none", NONE, false, SIGN_IN_FIRST),
  row("later", "none", NONE, true, SIGN_IN_FIRST),
  row("later", "found", FOUND_FIRST, false, SIGN_IN_AGAIN),
  row("later", "found", FOUND_FIRST, true, SIGN_IN_AGAIN),
  row("later", "found again", FOUND_AGAIN, false, failed("session-refused")),
  row("later", "found again", FOUND_AGAIN, true, failed("session-refused")),
  row("later", "unavailable", UNAVAILABLE, false, failed("storage-unavailable")),
  row("later", "unavailable", UNAVAILABLE, true, failed("storage-unavailable")),
];

describe("decideUnauthorized", () => {
  it("is tested over all 16 combinations of source, taken and byHistory", () => {
    expect(new Set(TABLE.map((c) => `${c.source}/${c.label}/${c.byHistory}`)).size).toBe(16);
  });

  it.each(TABLE)("$source, record $label, byHistory=$byHistory", ({ source, taken, byHistory, expected }) => {
    expect(decideUnauthorized({ source, taken, byHistory })).toEqual(expected);
  });
});
