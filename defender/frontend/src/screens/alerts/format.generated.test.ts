// The alert list's calendar arithmetic over every instant, zone and clock the design promises, not over hand-picked
// ones (#1581 repair, families G4 and G5): O5's fired label and O7's wall times and their reading back.
//
// Each oracle is independent of format.ts. A filter time is valid when JS's own date arithmetic round-trips its fields
// (proleptic Gregorian). A wall time is what the `sv-SE` locale writes (`YYYY-MM-DD HH:MM:SS`, Latin digits, no zone
// words) for the instant in the zone. A day label is the difference of the zone's two calendar dates by that same
// writing. Each part states a premise with a minimum count, so a generator that stops reaching the cases a wrong
// formula differs on fails loudly instead of passing.
//
// The same parts run again under a default locale that differs from en-US in calendar (Buddhist), numbering system
// (Thai digits) and month names (Thai), because O5 promises English months "whatever the browser's language" and O7's
// reading depends on Latin digits in the Gregorian calendar. The runtime's own default stays en-US here, so the Thai
// default is stood in for at the one place format.ts could read it: a locale left undefined.
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { AddressQuery } from "../../shell/provider";
import { firedLabel, readFilters, wallTime } from "./format";

const DAY_MS = 86_400_000;
const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
/** Each part walks thousands of instants and zones: a test timeout that allows for it. */
const SLOW = 120_000;
const THAI = "th-TH-u-ca-buddhist-nu-thai";

// --- the oracles ---------------------------------------------------------------------------------------------------

/** A calendar date and a time of day, with no zone. */
interface Fields {
  readonly year: number;
  readonly month: number;
  readonly day: number;
  readonly hour: number;
  readonly minute: number;
  readonly second: number;
}

const midnight = (year: number, month: number, day: number): Fields => ({
  year,
  month,
  day,
  hour: 0,
  minute: 0,
  second: 0,
});

const writers = new Map<string, Intl.DateTimeFormat>();

/** The zone's wall time at the instant `ms`, as `sv-SE` writes it. */
function wallOf(zone: string, ms: number): Fields {
  let writer = writers.get(zone);
  if (writer === undefined) {
    writer = new Intl.DateTimeFormat("sv-SE", {
      timeZone: zone,
      hourCycle: "h23",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
    writers.set(zone, writer);
  }
  const found = /^(\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+)$/.exec(writer.format(ms));
  if (found === null) throw new Error(`premise: sv-SE wrote an unexpected form for ${zone}`);
  const [year = NaN, month = NaN, day = NaN, hour = NaN, minute = NaN, second = NaN] = found.slice(1).map(Number);
  return { year, month, day, hour, minute, second };
}

/** The fields as an instant, were they UTC (proleptic Gregorian, any year, 0 to 99 included). */
function utcMs(fields: Fields): number {
  const date = new Date(0);
  date.setUTCFullYear(fields.year, fields.month - 1, fields.day);
  date.setUTCHours(fields.hour, fields.minute, fields.second, 0);
  return date.getTime();
}

const pad = (value: number, width = 2): string => String(value).padStart(width, "0");

/** The zone's offset from UTC at the instant `ms`, in ms. */
function offsetOf(zone: string, ms: number): number {
  return utcMs(wallOf(zone, ms)) - Math.floor(ms / 1000) * 1000;
}

/** `YYYY-MM-DDTHH:MM` of the fields: the one form a filter time takes in the address. */
function formText(f: Fields): string {
  return `${pad(f.year, 4)}-${pad(f.month)}-${pad(f.day)}T${pad(f.hour)}:${pad(f.minute)}`;
}

/** Whether the fields are a real date and time: JS's date arithmetic gives the same fields back. */
function isReal(f: Fields): boolean {
  const date = new Date(utcMs(f));
  return (
    date.getUTCFullYear() === f.year &&
    date.getUTCMonth() === f.month - 1 &&
    date.getUTCDate() === f.day &&
    date.getUTCHours() === f.hour &&
    date.getUTCMinutes() === f.minute
  );
}

function address(...pairs: readonly (readonly [string, string])[]): AddressQuery {
  return {
    get: (name) => pairs.find(([key]) => key === name)?.[1] ?? null,
    getAll: (name) => pairs.filter(([key]) => key === name).map(([, value]) => value),
  };
}

/** The instant (ms) a `fired_after` reads as in `zone`, or "invalid". */
function readAfter(text: string, zone: string): number | "invalid" {
  const result = readFilters(address(["fired_after", text], ["tz", zone]), "UTC");
  if (result.kind === "invalid") return "invalid";
  if (result.after === null) throw new Error("a set time read as unset");
  return Date.parse(result.after);
}

// --- how much each run covers --------------------------------------------------------------------------------------

interface Scale {
  /** Every nth zone of the browser's list is walked. */
  readonly zoneStride: number;
  /** Years whose 29 February is tried: every one, or the ones a leap rule can differ on. */
  readonly allYears: boolean;
  /** Clock changes tried of each kind. */
  readonly changes: number;
}
const FULL: Scale = { zoneStride: 1, allYears: true, changes: 20 };
const SAMPLE: Scale = { zoneStride: 12, allYears: false, changes: 4 };

const ZONES = Intl.supportedValuesOf("timeZone");

// --- validity (O7): which field strings are a real date and time -----------------------------------------------------

function leapYears(scale: Scale): number[] {
  const every = Array.from({ length: 10_000 }, (_, year) => year);
  if (scale.allYears) return every;
  return every.filter((year) => year % 100 === 0 || year < 12 || year > 9990 || year % 997 === 0);
}

/** Every month 0 to 13 and day 0 to 32 of `year`, at times that are and are not of a day. */
function gridOf(year: number): Fields[] {
  const times = [
    [0, 0],
    [23, 59],
    [24, 0],
    [12, 60],
  ] as const;
  return Array.from({ length: 14 * 33 * times.length }, (_, index) => {
    const [hour, minute] = times[index % times.length] ?? [0, 0];
    const cell = Math.floor(index / times.length);
    return { year, month: Math.floor(cell / 33), day: cell % 33, hour, minute, second: 0 };
  });
}

function validityCases(scale: Scale): Fields[] {
  const years = scale.allYears ? [0, 4, 100, 1900, 2000, 2024, 2100, 9999] : [1900, 2000, 2024];
  return [
    ...leapYears(scale).map((year) => ({ ...midnight(year, 2, 29), hour: 12 })),
    ...years.flatMap((year) => gridOf(year)),
  ];
}

function checkValidity(scale: Scale): void {
  const seen = { century: 0, fourHundred: 0, valid: 0, invalid: 0 };
  const wrong: string[] = [];
  for (const fields of validityCases(scale)) {
    const text = formText(fields);
    const expected = isReal(fields) ? utcMs(fields) : "invalid";
    if (readAfter(text, "UTC") !== expected) wrong.push(text);
    seen[expected === "invalid" ? "invalid" : "valid"]++;
    if (fields.month === 2 && fields.day === 29 && fields.year % 100 === 0)
      seen[fields.year % 400 === 0 ? "fourHundred" : "century"]++;
  }
  expect(wrong.slice(0, 10), `${wrong.length} field strings read differently from a real date`).toEqual([]);
  // premise: the strings that tell a leap rule apart (century years that are not leap, those divisible by 400) and
  // both answers are reached
  expect(seen.century).toBeGreaterThanOrEqual(scale.allYears ? 70 : 8);
  expect(seen.fourHundred).toBeGreaterThanOrEqual(scale.allYears ? 25 : 3);
  expect(seen.valid).toBeGreaterThan(1000);
  expect(seen.invalid).toBeGreaterThan(1000);
}

// --- refill (O7): an instant written for the form reads back as itself -----------------------------------------------

function refillInstants(zoneIndex: number): number[] {
  return Array.from({ length: 36 }, (_, k) =>
    utcMs({
      year: 2000 + ((k * 7 + zoneIndex) % 90),
      month: 1 + ((k + zoneIndex) % 12),
      day: 1 + ((k * 5 + zoneIndex) % 28),
      hour: (k + zoneIndex * 5) % 24,
      minute: (13 * k) % 60,
      second: 0,
    }),
  );
}

/** Every month of years that stress the calendar, at every hour, in UTC. */
function denseInstants(): number[] {
  const years = [1000, 1583, 1900, 2000, 2100, 9000];
  return years.flatMap((year) =>
    Array.from({ length: 12 * 24 }, (_, index) =>
      utcMs({ year, month: 1 + Math.floor(index / 24), day: 15, hour: index % 24, minute: 7, second: 0 }),
    ),
  );
}

interface Refill {
  readonly wrong: string[];
  readonly months: Map<number, number>;
  readonly hours: Map<number, number>;
  exact: number;
  total: number;
}

function refillOne(zone: string, ms: number, into: Refill): void {
  const written = wallTime(new Date(ms).toISOString(), zone);
  const wall = wallOf(zone, ms);
  const expected = formText(wall);
  into.total++;
  into.months.set(wall.month, (into.months.get(wall.month) ?? 0) + 1);
  into.hours.set(wall.hour, (into.hours.get(wall.hour) ?? 0) + 1);
  if (written !== expected) into.wrong.push(`${zone} ${new Date(ms).toISOString()} wrote ${written}, not ${expected}`);
  const back = readAfter(written, zone);
  const minute = Math.floor(ms / MINUTE_MS) * MINUTE_MS;
  if (back === minute) into.exact++;
  // the second of a repeated hour reads back as the first (the accepted cost): an earlier instant, same wall time
  else if (back === "invalid" || back > minute || formText(wallOf(zone, back)) !== expected)
    into.wrong.push(`${zone} ${written} read back as ${String(back)}, not ${new Date(minute).toISOString()}`);
}

function checkRefill(scale: Scale): void {
  const into: Refill = { wrong: [], months: new Map(), hours: new Map(), exact: 0, total: 0 };
  const zones = ZONES.map((zone, index) => [zone, index] as const).filter(
    ([, index]) => index % scale.zoneStride === 0,
  );
  for (const [zone, index] of zones) refillInstants(index).forEach((ms) => refillOne(zone, ms, into));
  denseInstants().forEach((ms) => refillOne("UTC", ms, into));
  expect(into.wrong.slice(0, 10), `${into.wrong.length} instants did not refill`).toEqual([]);
  // premises: every month and every hour of the day is written, the single-digit ones included, and nearly every
  // instant reads back exactly (the repeated hour is the only exception)
  for (let month = 1; month <= 12; month++) expect(into.months.get(month) ?? 0, `month ${month}`).toBeGreaterThan(19);
  for (let hour = 0; hour < 24; hour++) expect(into.hours.get(hour) ?? 0, `hour ${hour}`).toBeGreaterThan(19);
  expect(into.exact / into.total).toBeGreaterThan(0.99);
}

// --- the day label (O5), around the days of 23 and 25 hours ----------------------------------------------------------

interface Change {
  readonly zone: string;
  /** The first instant (ms, to the minute) on the new offset. */
  readonly at: number;
  /** The change of offset in ms: positive when the clocks went forward (a short day). */
  readonly delta: number;
}

/** Narrow `(low, high]` to the minute at which the zone's offset stops being `before`. */
function changeBetween(zone: string, before: number, low: number, high: number): number {
  if (high - low <= MINUTE_MS) return high;
  const middle = Math.floor((low + high) / 2 / MINUTE_MS) * MINUTE_MS;
  return offsetOf(zone, middle) === before
    ? changeBetween(zone, before, middle, high)
    : changeBetween(zone, before, low, middle);
}

/** The zone's clock changes in `year`, found by comparing its offset at each noon UTC and narrowing to the minute. */
function changesIn(zone: string, year: number): Change[] {
  const start = utcMs({ ...midnight(year, 1, 1), hour: 12 });
  const offsets = Array.from({ length: 367 }, (_, day) => offsetOf(zone, start + day * DAY_MS));
  return offsets.flatMap((after, day) => {
    const before = offsets[day - 1];
    if (before === undefined || after === before) return [];
    const at = changeBetween(zone, before, start + (day - 1) * DAY_MS, start + day * DAY_MS);
    return [{ zone, at, delta: after - before }];
  });
}

const NAMED = ["Europe/Paris", "America/New_York", "Australia/Lord_Howe", "America/Havana", "Europe/London"];

/** Up to `count` changes of the given kind, the named zones first and the rest spread over the browser's list. */
function changesOfKind(forward: boolean, count: number): Change[] {
  const wanted = (change: Change): boolean => change.delta > 0 === forward;
  const named = NAMED.flatMap((zone) => changesIn(zone, 2025).filter(wanted));
  const rest = ZONES.filter((zone) => !NAMED.includes(zone)).flatMap((zone) => changesIn(zone, 2025).filter(wanted));
  const stride = Math.max(1, Math.floor(rest.length / Math.max(1, count - named.length)));
  return [...named, ...rest.filter((_, index) => index % stride === 0)].slice(0, count);
}

/** The local midnights (the first quarter hour of a new calendar date) from 30 hours before `at` to 36 hours after. */
function midnightsAround(zone: string, at: number): number[] {
  const quarter = 15 * MINUTE_MS;
  const start = Math.floor((at - 30 * HOUR_MS) / quarter) * quarter;
  const steps = Array.from({ length: Math.ceil((66 * HOUR_MS) / quarter) }, (_, index) => start + index * quarter);
  return steps.filter((ms) => wallOf(zone, ms).day !== wallOf(zone, ms - quarter).day);
}

/** The label a row shows: the difference of the zone's calendar dates, from the sv-SE writing. */
function expectedLabel(zone: string, fired: number, now: number): { time: string; day: string; daysAgo: number } {
  const f = wallOf(zone, fired);
  const n = wallOf(zone, now);
  const daysAgo = (utcMs(midnight(n.year, n.month, n.day)) - utcMs(midnight(f.year, f.month, f.day))) / DAY_MS;
  const time = `${pad(f.hour)}:${pad(f.minute)}`;
  const date = `${f.day} ${MONTHS[f.month - 1] ?? ""}`;
  const day = daysAgo === 0 ? "Today" : daysAgo === 1 ? "Yesterday" : f.year === n.year ? date : `${date} ${f.year}`;
  return { time, day, daysAgo };
}

/** The day count a clock would give that took "yesterday" as now less 24 hours (0, 1, or 2 for more). */
function dayShortcut(zone: string, fired: number, now: number): number {
  const dateOf = (ms: number): number => {
    const w = wallOf(zone, ms);
    return utcMs(midnight(w.year, w.month, w.day));
  };
  if (dateOf(fired) === dateOf(now)) return 0;
  return dateOf(fired) === dateOf(now - DAY_MS) ? 1 : 2;
}

interface Labels {
  readonly wrong: string[];
  traps: number;
}

/** One row's label at `now`, against the oracle's. */
function labelOne(zone: string, fired: number, now: number, into: Labels): void {
  const want = expectedLabel(zone, fired, now);
  const got = firedLabel(new Date(fired).toISOString(), { now: new Date(now), timeZone: zone });
  if (Math.min(want.daysAgo, 2) !== dayShortcut(zone, fired, now)) into.traps++;
  if (got.time !== want.time || got.day !== want.day)
    into.wrong.push(
      `${zone} fired ${new Date(fired).toISOString()} now ${new Date(now).toISOString()}: ` +
        `${got.time} ${got.day}, not ${want.time} ${want.day}`,
    );
}

/** Every label from `now` back four days in half hours, for the nows an hour either side of each local midnight. */
function labelsAround({ zone, at }: Change, into: Labels): void {
  const nows = midnightsAround(zone, at).flatMap((m) => [m, m + 30 * MINUTE_MS, m - 30 * MINUTE_MS]);
  for (const now of nows)
    for (let back = 0; back <= 100; back++) labelOne(zone, now - back * 30 * MINUTE_MS, now, into);
}

function checkLabels(scale: Scale): void {
  for (const forward of [true, false]) {
    const changes = changesOfKind(forward, scale.changes);
    const into: Labels = { wrong: [], traps: 0 };
    for (const change of changes) labelsAround(change, into);
    const kind = forward ? "23-hour (clocks forward)" : "25-hour (clocks back)";
    expect(into.wrong.slice(0, 10), `${into.wrong.length} labels wrong around ${kind} days`).toEqual([]);
    // premises: enough clock changes of this kind, and enough labels where "now less 24 hours" is the wrong "yesterday"
    expect(changes.length, `${kind} changes reached`).toBeGreaterThanOrEqual(Math.min(scale.changes, 4));
    expect(into.traps, `${kind}: labels a 24-hour shortcut gets wrong`).toBeGreaterThanOrEqual(scale.changes);
  }
}

// --- both runs -------------------------------------------------------------------------------------------------------

describe("the calendar arithmetic, over every instant, zone and clock", () => {
  it(
    "reads a field string as a time exactly when it is a real date (every year's 29 February among them)",
    () => {
      checkValidity(FULL);
    },
    SLOW,
  );
  it(
    "writes every instant as the form's wall time and reads it back, in every zone, month and hour",
    () => {
      checkRefill(FULL);
    },
    SLOW,
  );
  it(
    "labels the day by the zone's calendar around every kind of 23- and 25-hour day",
    () => {
      checkLabels(FULL);
    },
    SLOW,
  );
});

/** What a `Date` writes with no options of its own, per method (the default fields ECMA-402 gives each). */
const METHODS = ["toLocaleString", "toLocaleDateString", "toLocaleTimeString"] as const;
const DEFAULT_FIELDS: Record<(typeof METHODS)[number], Intl.DateTimeFormatOptions> = {
  toLocaleString: {
    year: "numeric",
    month: "numeric",
    day: "numeric",
    hour: "numeric",
    minute: "numeric",
    second: "numeric",
  },
  toLocaleDateString: { year: "numeric", month: "numeric", day: "numeric" },
  toLocaleTimeString: { hour: "numeric", minute: "numeric", second: "numeric" },
};

/** The browser's default locale made Thai, where format.ts could read it: a formatter or a date given no locale. */
function useThaiDefault(): void {
  const Real = Intl.DateTimeFormat;
  vi.spyOn(Intl, "DateTimeFormat").mockImplementation(function (locales, options) {
    return new Real(locales ?? THAI, options);
  });
  for (const method of METHODS) {
    vi.spyOn(Date.prototype, method).mockImplementation(function (this: Date, locales, options) {
      return new Real(locales ?? THAI, options ?? DEFAULT_FIELDS[method]).format(this);
    });
  }
}

describe("the same arithmetic when the browser's default locale is not en-US", () => {
  beforeAll(useThaiDefault);
  afterAll(() => {
    vi.restoreAllMocks();
  });

  it("is a default that differs from en-US in calendar, numbering system and month names (premise)", () => {
    const options = new Intl.DateTimeFormat().resolvedOptions();
    expect([options.calendar, options.numberingSystem]).toEqual(["buddhist", "thai"]);
    expect(new Date(0).toLocaleString(undefined, { month: "short", timeZone: "UTC" })).not.toBe("Jan");
    expect(new Date(0).toLocaleString(undefined, { year: "numeric", timeZone: "UTC" })).not.toBe("1970");
  });

  it(
    "reads a field string as a time exactly when it is a real date",
    () => {
      checkValidity(SAMPLE);
    },
    SLOW,
  );
  it(
    "writes every instant as the form's wall time and reads it back",
    () => {
      checkRefill(SAMPLE);
    },
    SLOW,
  );
  it(
    "labels the day by the zone's calendar, with English months",
    () => {
      checkLabels(SAMPLE);
    },
    SLOW,
  );
});
