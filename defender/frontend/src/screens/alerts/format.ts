// The alert list's pure pieces (alert list design O5, O7): the fired time as a row shows it, the address's query read
// once into the filters, and an instant written back as a wall time for the filter form. Each takes its zone (and
// `firedLabel` the moment "now") from its caller; nothing here reads the browser's clock or zone.
import type { AddressQuery } from "../../shell/provider";
import { outcomeFilterOf, type OutcomeFilter } from "./outcomes";

/** The filters an address asks for: `after` and `before` are UTC instants (ISO strings), each null when unset. */
export interface Filters {
  readonly kind: "filters";
  readonly outcome: OutcomeFilter | null;
  readonly after: string | null;
  readonly before: string | null;
}

/** An address the screen cannot read (O7): it shows only that, and sends no read. */
export interface Invalid {
  readonly kind: "invalid";
}

const INVALID: Invalid = { kind: "invalid" };

/** The fixed English month names a date label uses, whatever the browser's language. */
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"] as const;

const DAY_MS = 86_400_000;

/** A wall-clock date and time, with no zone. `month` is 1 to 12. */
interface Wall {
  readonly year: number;
  readonly month: number;
  readonly day: number;
  readonly hour: number;
  readonly minute: number;
  readonly second: number;
}

/** The formatter that writes an instant's wall time in `timeZone`; throws `RangeError` for a zone the browser does not
 * know. Every field numeric and the hour 0 to 23, so the parts read back as numbers. */
function wallFormat(timeZone: string): Intl.DateTimeFormat {
  return new Intl.DateTimeFormat("en-US", {
    timeZone,
    calendar: "gregory",
    numberingSystem: "latn",
    era: "short",
    year: "numeric",
    month: "numeric",
    day: "numeric",
    hour: "numeric",
    minute: "numeric",
    second: "numeric",
    hourCycle: "h23",
  });
}

/** The wall time of the instant `ms` as `format` writes it. */
function wallAt(format: Intl.DateTimeFormat, ms: number): Wall {
  const parts = new Map(format.formatToParts(ms).map((part) => [part.type, part.value]));
  const number = (type: Intl.DateTimeFormatPartTypes): number => {
    const value = Number(parts.get(type));
    if (!Number.isInteger(value)) throw new Error(`the zone's ${type} did not read as a number`);
    return value;
  };
  const year = parts.get("era") === "BC" ? 1 - number("year") : number("year");
  return {
    year,
    month: number("month"),
    day: number("day"),
    hour: number("hour"),
    minute: number("minute"),
    second: number("second"),
  };
}

/** The wall time read as if it were UTC, in ms: the arithmetic below compares wall times by it. */
function asUtc(wall: Wall): number {
  const date = new Date(0);
  date.setUTCFullYear(wall.year, wall.month - 1, wall.day); // unlike Date.UTC, not shifted for years 0 to 99
  date.setUTCHours(wall.hour, wall.minute, wall.second, 0);
  return date.getTime();
}

/** The zone's offset from UTC at the instant `ms`, in ms (to the second). */
function offsetAt(format: Intl.DateTimeFormat, ms: number): number {
  const whole = Math.floor(ms / 1000) * 1000;
  return asUtc(wallAt(format, whole)) - whole;
}

/** The instant a wall time (`local`, as `asUtc` gives it) means in the zone, as Temporal's `compatible` resolves it: a
 * wall time the zone has once is that instant; one it has twice (the clocks went back) is the earlier; one it skipped
 * (the clocks went forward) takes the offset from before the change, so it lands after it. Offsets are probed a day
 * either side, which spans every change a zone has made (Apia skipped a whole day). */
function instantOf(format: Intl.DateTimeFormat, local: number): number {
  const before = offsetAt(format, local - DAY_MS);
  const after = offsetAt(format, local + DAY_MS);
  const found = [...new Set([before, after])]
    .map((offset) => local - offset)
    .filter((instant) => offsetAt(format, instant) === local - instant)
    .sort((a, b) => a - b);
  return found[0] ?? local - before;
}

/** True for a year that has a 29 February. */
function leap(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] as const;

/** `YYYY-MM-DDTHH:MM`, the one form a time takes in the address (a `datetime-local` field's value). */
const WALL_TIME = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})$/;

/** `text` as a wall time, or null when it is not in the address's form or not a real calendar date and time. */
function wallOf(text: string): Wall | null {
  const found = WALL_TIME.exec(text);
  if (found === null) return null;
  const [year, month, day, hour, minute] = found.slice(1).map(Number);
  if (year === undefined || month === undefined || day === undefined || hour === undefined || minute === undefined)
    return null;
  if (month < 1 || month > 12 || hour > 23 || minute > 59) return null;
  const last = month === 2 && leap(year) ? 29 : (DAYS_IN_MONTH[month - 1] ?? 0);
  if (day < 1 || day > last) return null;
  return { year, month, day, hour, minute, second: 0 };
}

/** The single value the address gives `name`: "" when it gives none, null when it gives it more than once. */
function single(query: AddressQuery, name: string): string | null {
  const values = query.getAll(name);
  if (values.length > 1) return null;
  return values[0] ?? "";
}

/**
 * The address's filters (O7), read once: `outcome`, `fired_after` and `fired_before`, with the times read as wall
 * times in the zone `tz` names, or in `viewerZone` when `tz` is absent or empty. An empty value is unset. Invalid: an
 * outcome not one of the six, a time not `YYYY-MM-DDTHH:MM` or not a real date and time, a zone the browser does not
 * know, or any of the four keys given twice. Other keys are ignored.
 */
export function readFilters(query: AddressQuery, viewerZone: string): Filters | Invalid {
  const outcomeText = single(query, "outcome");
  const afterText = single(query, "fired_after");
  const beforeText = single(query, "fired_before");
  const tz = single(query, "tz");
  if (outcomeText === null || afterText === null || beforeText === null || tz === null) return INVALID;
  const outcome = outcomeText === "" ? null : outcomeFilterOf(outcomeText);
  if (outcomeText !== "" && outcome === null) return INVALID;
  let format: Intl.DateTimeFormat;
  try {
    format = wallFormat(tz === "" ? viewerZone : tz);
  } catch (error) {
    if (error instanceof RangeError) return INVALID;
    throw error;
  }
  /** The instant a time means, null when it is unset, undefined when it can't be read. */
  const instant = (text: string): string | null | undefined => {
    if (text === "") return null;
    const wall = wallOf(text);
    return wall === null ? undefined : new Date(instantOf(format, asUtc(wall))).toISOString();
  };
  const after = instant(afterText);
  const before = instant(beforeText);
  if (after === undefined || before === undefined) return INVALID;
  return { kind: "filters", outcome, after, before };
}

/** Whether any filter is set: the outcome or a time (`tz` alone never is). */
export function anySet(filters: Filters): boolean {
  return filters.outcome !== null || filters.after !== null || filters.before !== null;
}

const two = (value: number): string => String(value).padStart(2, "0");

/** The instant `iso` as the filter form writes it (`YYYY-MM-DDTHH:MM`) in `timeZone`. */
export function wallTime(iso: string, timeZone: string): string {
  const wall = wallAt(wallFormat(timeZone), Date.parse(iso));
  return `${String(wall.year).padStart(4, "0")}-${two(wall.month)}-${two(wall.day)}T${two(wall.hour)}:${two(wall.minute)}`;
}

/** The fired time as a row shows it (O5): `HH:MM` in `timeZone`, over "Today", "Yesterday" or the date ("5 Sep", with
 * the year when it is not the current one: "20 Dec 2025"), each day and year the zone's. */
export function firedLabel(
  iso: string,
  { now, timeZone }: { readonly now: Date; readonly timeZone: string },
): { readonly time: string; readonly day: string } {
  const format = wallFormat(timeZone);
  const fired = wallAt(format, Date.parse(iso));
  const today = wallAt(format, now.getTime());
  const dayOf = (wall: Wall): number => asUtc({ ...wall, hour: 0, minute: 0, second: 0 }) / DAY_MS;
  const daysAgo = dayOf(today) - dayOf(fired);
  const time = `${two(fired.hour)}:${two(fired.minute)}`;
  if (daysAgo === 0) return { time, day: "Today" };
  if (daysAgo === 1) return { time, day: "Yesterday" };
  const date = `${fired.day} ${MONTHS[fired.month - 1] ?? ""}`;
  return { time, day: fired.year === today.year ? date : `${date} ${fired.year}` };
}
