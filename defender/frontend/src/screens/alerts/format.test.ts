// The alert list's pure pieces (O5, O7): the fired time as the row shows it, and the address query read into the list
// read's query. Both take the zone and (for the time) the moment "now" explicitly, so the cases do not depend on the
// machine's zone or clock; the screen passes the browser's.
// FORCED CHOICES: the module (`screens/alerts/format`), the names and signatures (`firedLabel`, `readFilters`), and the
// result shapes are not in the design. The date line for a day before yesterday is not either: the design says "the
// date"; the case below writes ISO `YYYY-MM-DD`, one candidate of several ("30 Oct", "Oct 30", the locale's).
import { describe, expect, it } from "vitest";
import { firedLabel, readFilters } from "./format";

const PARIS = "Europe/Paris"; // UTC+1 in November
const NOW = new Date("2026-11-01T15:00:00Z"); // 16:00 in Paris

describe("firedLabel", () => {
  it("writes the local HH:MM over Today, Yesterday or the date", () => {
    expect(firedLabel("2026-11-01T12:00:00Z", { now: NOW, timeZone: PARIS })).toEqual({ time: "13:00", day: "Today" });
    // 23:30 on 31 October in Paris, though 22:30 UTC: the day is the zone's, not UTC's.
    expect(firedLabel("2026-10-31T22:30:00Z", { now: NOW, timeZone: PARIS })).toEqual({
      time: "23:30",
      day: "Yesterday",
    });
    expect(firedLabel("2026-10-30T08:05:00Z", { now: NOW, timeZone: PARIS })).toEqual({
      time: "09:05",
      day: "2026-10-30",
    });
  });
});

describe("readFilters", () => {
  it("treats empty fields as unset and converts local date-times to instants in the zone", () => {
    const read = readFilters("?outcome=malicious&fired_after=2026-11-12T00:00&fired_before=", PARIS);
    expect(read.kind).toBe("valid");
    if (read.kind !== "valid") return;
    expect(read.filtered).toBe(true);
    expect(read.query.outcome).toBe("malicious");
    expect(new Date(read.query.fired_after ?? "").toISOString()).toBe("2026-11-11T23:00:00.000Z");
    expect(read.query.fired_before).toBeUndefined();
  });

  it("reads an all-empty submit as no filter", () => {
    expect(readFilters("?outcome=&fired_after=&fired_before=", PARIS)).toEqual({
      kind: "valid",
      filtered: false,
      query: {},
    });
  });

  it("refuses an outcome outside the six values and a time not YYYY-MM-DDTHH:MM", () => {
    expect(readFilters("?outcome=evil", PARIS)).toEqual({ kind: "invalid" });
    expect(readFilters("?fired_after=2026-11-12", PARIS)).toEqual({ kind: "invalid" });
  });
});
