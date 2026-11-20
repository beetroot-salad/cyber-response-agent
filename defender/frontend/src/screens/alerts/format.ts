// The alert list's pure pieces (alert list design O5, O7): the fired time as a row shows it, the address's query read
// once into the filters, and an instant written back as a wall time for the filter form. Each takes its zone (and
// `firedLabel` the moment "now") from its caller; nothing here reads the browser's clock or zone.
import { Temporal } from "temporal-polyfill";
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

/** `YYYY-MM-DDTHH:MM`, the one form a time takes in the address (a `datetime-local` field's value). Checked before
 * Temporal reads it, which would also take seconds, an offset or an annotation. */
const WALL_TIME = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})$/;

/** The instant `iso` in `timeZone`; throws `RangeError` for a zone Temporal does not know. */
function zoned(iso: string, timeZone: string): Temporal.ZonedDateTime {
  return Temporal.Instant.fromEpochMilliseconds(Date.parse(iso)).toZonedDateTimeISO(timeZone);
}

/** `text` as a wall time, or null when it is not in the address's form or not a real calendar date and time. */
function wallOf(text: string): Temporal.PlainDateTime | null {
  const found = WALL_TIME.exec(text);
  if (found === null) return null;
  const [year, month, day, hour, minute] = found.slice(1).map(Number);
  if (year === undefined || month === undefined || day === undefined || hour === undefined || minute === undefined)
    return null;
  try {
    return Temporal.PlainDateTime.from({ year, month, day, hour, minute }, { overflow: "reject" });
  } catch (error) {
    if (error instanceof RangeError) return null;
    throw error;
  }
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
  const zone = tz === "" ? viewerZone : tz;
  try {
    // Both must know it: Temporal also reads an ISO date-time (`2026-01-01T00:00Z`) as its zone, which is not a zone.
    new Intl.DateTimeFormat("en-US", { timeZone: zone });
    Temporal.Instant.fromEpochMilliseconds(0).toZonedDateTimeISO(zone);
  } catch (error) {
    if (error instanceof RangeError) return INVALID;
    throw error;
  }
  /** The instant a time means (a wall time the zone skipped or has twice, as `compatible` resolves it), null when it
   * is unset, undefined when it can't be read. Written as `toISOString` writes it. */
  const instant = (text: string): string | null | undefined => {
    if (text === "") return null;
    const wall = wallOf(text);
    if (wall === null) return undefined;
    return new Date(wall.toZonedDateTime(zone, { disambiguation: "compatible" }).epochMilliseconds).toISOString();
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
  const wall = zoned(iso, timeZone);
  return `${String(wall.year).padStart(4, "0")}-${two(wall.month)}-${two(wall.day)}T${two(wall.hour)}:${two(wall.minute)}`;
}

/** The fired time as a row shows it (O5): `HH:MM` in `timeZone`, over "Today", "Yesterday" or the date ("5 Sep", with
 * the year when it is not the current one: "20 Dec 2025"), each day and year the zone's. */
export function firedLabel(
  iso: string,
  { now, timeZone }: { readonly now: Date; readonly timeZone: string },
): { readonly time: string; readonly day: string } {
  const fired = zoned(iso, timeZone);
  const today = zoned(now.toISOString(), timeZone);
  const daysAgo = fired.toPlainDate().until(today.toPlainDate(), { largestUnit: "days" }).days;
  const time = `${two(fired.hour)}:${two(fired.minute)}`;
  if (daysAgo === 0) return { time, day: "Today" };
  if (daysAgo === 1) return { time, day: "Yesterday" };
  const date = `${fired.day} ${MONTHS[fired.month - 1] ?? ""}`;
  return { time, day: fired.year === today.year ? date : `${date} ${fired.year}` };
}
