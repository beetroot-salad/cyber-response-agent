// The alert list's pure pieces (alert list design O5, O7, AP4): the fired time as a row shows it, and the address
// query read once into the filters. Both take the zone (and `firedLabel` the moment "now") explicitly, so no case
// depends on the machine's zone or clock; the screen passes the browser's.
// FORCED CHOICES (the design names neither): the module (`screens/alerts/format`), `firedLabel(iso, {now, timeZone})`
// answering `{time, day}`, and how Invalid and the instants are spelled. A valid read is an object holding `outcome`,
// `after` and `before`; any other answer is Invalid, and an instant may be a `Date`, an ISO string or epoch ms.
// Expected instants come from Python's `zoneinfo` (fold=0, which PEP 495 defines as Temporal's `compatible`), not from
// this module's own arithmetic.
import { describe, expect, it } from "vitest";
import type { AddressQuery } from "../../shell/provider";
import { firedLabel, readFilters } from "./format";

/** An address query with the given pairs, in order (`get` the first of a name, as the browser's is). */
function address(...pairs: readonly (readonly [string, string])[]): AddressQuery {
  return {
    get: (name) => pairs.find(([key]) => key === name)?.[1] ?? null,
    getAll: (name) => pairs.filter(([key]) => key === name).map(([, value]) => value),
  };
}

type Pair = readonly [string, string];
type Read = { readonly outcome: unknown; readonly after: unknown; readonly before: unknown } | "invalid";

function read(zone: string, ...pairs: Pair[]): Read {
  const result: unknown = readFilters(address(...pairs), zone);
  if (typeof result === "object" && result !== null && "outcome" in result && "after" in result && "before" in result)
    return { outcome: result.outcome, after: result.after, before: result.before };
  expect(result, "an Invalid read is a defined answer").toBeDefined();
  return "invalid";
}

/** An instant as epoch ms, whichever way the module spells it; null stays null. */
function ms(instant: unknown): number | null {
  if (instant === null) return null;
  if (typeof instant === "string" || typeof instant === "number" || instant instanceof Date)
    return new Date(instant).getTime();
  throw new Error("not an instant");
}

function valid(result: Read) {
  if (result === "invalid") throw new Error("the read was Invalid");
  return { outcome: result.outcome, after: ms(result.after), before: ms(result.before) };
}

const at = (iso: string): number => new Date(iso).getTime();

/** Each `zone wall-time instant`: a wall time in `zone` and the instant it means (fold 0). The transitions are every
 * 15 minutes across each change of Paris, New York, Lord Howe (30 minutes), Havana (at midnight) and Apia (a whole day
 * skipped, 2011); the ordinary times are away from any change. */
const TRANSITIONS: readonly string[] = [
  "Europe/Paris 2026-03-29T01:00 2026-03-29T00:00Z",
  "Europe/Paris 2026-03-29T01:15 2026-03-29T00:15Z",
  "Europe/Paris 2026-03-29T01:30 2026-03-29T00:30Z",
  "Europe/Paris 2026-03-29T01:45 2026-03-29T00:45Z",
  "Europe/Paris 2026-03-29T02:00 2026-03-29T01:00Z",
  "Europe/Paris 2026-03-29T02:15 2026-03-29T01:15Z",
  "Europe/Paris 2026-03-29T02:30 2026-03-29T01:30Z",
  "Europe/Paris 2026-03-29T02:45 2026-03-29T01:45Z",
  "Europe/Paris 2026-03-29T03:00 2026-03-29T01:00Z",
  "Europe/Paris 2026-03-29T03:15 2026-03-29T01:15Z",
  "Europe/Paris 2026-03-29T03:30 2026-03-29T01:30Z",
  "Europe/Paris 2026-03-29T03:45 2026-03-29T01:45Z",
  "Europe/Paris 2026-03-29T04:00 2026-03-29T02:00Z",
  "Europe/Paris 2026-10-25T01:00 2026-10-24T23:00Z",
  "Europe/Paris 2026-10-25T01:15 2026-10-24T23:15Z",
  "Europe/Paris 2026-10-25T01:30 2026-10-24T23:30Z",
  "Europe/Paris 2026-10-25T01:45 2026-10-24T23:45Z",
  "Europe/Paris 2026-10-25T02:00 2026-10-25T00:00Z",
  "Europe/Paris 2026-10-25T02:15 2026-10-25T00:15Z",
  "Europe/Paris 2026-10-25T02:30 2026-10-25T00:30Z",
  "Europe/Paris 2026-10-25T02:45 2026-10-25T00:45Z",
  "Europe/Paris 2026-10-25T03:00 2026-10-25T02:00Z",
  "Europe/Paris 2026-10-25T03:15 2026-10-25T02:15Z",
  "Europe/Paris 2026-10-25T03:30 2026-10-25T02:30Z",
  "Europe/Paris 2026-10-25T03:45 2026-10-25T02:45Z",
  "Europe/Paris 2026-10-25T04:00 2026-10-25T03:00Z",
  "America/New_York 2026-03-08T01:00 2026-03-08T06:00Z",
  "America/New_York 2026-03-08T01:15 2026-03-08T06:15Z",
  "America/New_York 2026-03-08T01:30 2026-03-08T06:30Z",
  "America/New_York 2026-03-08T01:45 2026-03-08T06:45Z",
  "America/New_York 2026-03-08T02:00 2026-03-08T07:00Z",
  "America/New_York 2026-03-08T02:15 2026-03-08T07:15Z",
  "America/New_York 2026-03-08T02:30 2026-03-08T07:30Z",
  "America/New_York 2026-03-08T02:45 2026-03-08T07:45Z",
  "America/New_York 2026-03-08T03:00 2026-03-08T07:00Z",
  "America/New_York 2026-03-08T03:15 2026-03-08T07:15Z",
  "America/New_York 2026-03-08T03:30 2026-03-08T07:30Z",
  "America/New_York 2026-03-08T03:45 2026-03-08T07:45Z",
  "America/New_York 2026-03-08T04:00 2026-03-08T08:00Z",
  "America/New_York 2026-11-01T00:00 2026-11-01T04:00Z",
  "America/New_York 2026-11-01T00:15 2026-11-01T04:15Z",
  "America/New_York 2026-11-01T00:30 2026-11-01T04:30Z",
  "America/New_York 2026-11-01T00:45 2026-11-01T04:45Z",
  "America/New_York 2026-11-01T01:00 2026-11-01T05:00Z",
  "America/New_York 2026-11-01T01:15 2026-11-01T05:15Z",
  "America/New_York 2026-11-01T01:30 2026-11-01T05:30Z",
  "America/New_York 2026-11-01T01:45 2026-11-01T05:45Z",
  "America/New_York 2026-11-01T02:00 2026-11-01T07:00Z",
  "America/New_York 2026-11-01T02:15 2026-11-01T07:15Z",
  "America/New_York 2026-11-01T02:30 2026-11-01T07:30Z",
  "America/New_York 2026-11-01T02:45 2026-11-01T07:45Z",
  "America/New_York 2026-11-01T03:00 2026-11-01T08:00Z",
  "Australia/Lord_Howe 2026-10-04T01:00 2026-10-03T14:30Z",
  "Australia/Lord_Howe 2026-10-04T01:15 2026-10-03T14:45Z",
  "Australia/Lord_Howe 2026-10-04T01:30 2026-10-03T15:00Z",
  "Australia/Lord_Howe 2026-10-04T01:45 2026-10-03T15:15Z",
  "Australia/Lord_Howe 2026-10-04T02:00 2026-10-03T15:30Z",
  "Australia/Lord_Howe 2026-10-04T02:15 2026-10-03T15:45Z",
  "Australia/Lord_Howe 2026-10-04T02:30 2026-10-03T15:30Z",
  "Australia/Lord_Howe 2026-10-04T02:45 2026-10-03T15:45Z",
  "Australia/Lord_Howe 2026-10-04T03:00 2026-10-03T16:00Z",
  "Australia/Lord_Howe 2026-10-04T03:15 2026-10-03T16:15Z",
  "Australia/Lord_Howe 2026-10-04T03:30 2026-10-03T16:30Z",
  "Australia/Lord_Howe 2026-04-05T00:30 2026-04-04T13:30Z",
  "Australia/Lord_Howe 2026-04-05T00:45 2026-04-04T13:45Z",
  "Australia/Lord_Howe 2026-04-05T01:00 2026-04-04T14:00Z",
  "Australia/Lord_Howe 2026-04-05T01:15 2026-04-04T14:15Z",
  "Australia/Lord_Howe 2026-04-05T01:30 2026-04-04T14:30Z",
  "Australia/Lord_Howe 2026-04-05T01:45 2026-04-04T14:45Z",
  "Australia/Lord_Howe 2026-04-05T02:00 2026-04-04T15:30Z",
  "Australia/Lord_Howe 2026-04-05T02:15 2026-04-04T15:45Z",
  "Australia/Lord_Howe 2026-04-05T02:30 2026-04-04T16:00Z",
  "Australia/Lord_Howe 2026-04-05T02:45 2026-04-04T16:15Z",
  "Australia/Lord_Howe 2026-04-05T03:00 2026-04-04T16:30Z",
  "America/Havana 2026-03-08T00:00 2026-03-08T05:00Z",
  "America/Havana 2026-03-08T00:15 2026-03-08T05:15Z",
  "America/Havana 2026-03-08T00:30 2026-03-08T05:30Z",
  "America/Havana 2026-03-08T00:45 2026-03-08T05:45Z",
  "America/Havana 2026-03-08T01:00 2026-03-08T05:00Z",
  "America/Havana 2026-03-08T01:15 2026-03-08T05:15Z",
  "America/Havana 2026-03-08T01:30 2026-03-08T05:30Z",
  "America/Havana 2026-03-08T01:45 2026-03-08T05:45Z",
  "America/Havana 2026-03-08T02:00 2026-03-08T06:00Z",
  "America/Havana 2026-11-01T00:00 2026-11-01T04:00Z",
  "America/Havana 2026-11-01T00:15 2026-11-01T04:15Z",
  "America/Havana 2026-11-01T00:30 2026-11-01T04:30Z",
  "America/Havana 2026-11-01T00:45 2026-11-01T04:45Z",
  "America/Havana 2026-11-01T01:00 2026-11-01T06:00Z",
  "America/Havana 2026-11-01T01:15 2026-11-01T06:15Z",
  "America/Havana 2026-11-01T01:30 2026-11-01T06:30Z",
  "America/Havana 2026-11-01T01:45 2026-11-01T06:45Z",
  "America/Havana 2026-11-01T02:00 2026-11-01T07:00Z",
  "Pacific/Apia 2011-12-29T22:00 2011-12-30T08:00Z",
  "Pacific/Apia 2011-12-29T22:15 2011-12-30T08:15Z",
  "Pacific/Apia 2011-12-29T22:30 2011-12-30T08:30Z",
  "Pacific/Apia 2011-12-29T22:45 2011-12-30T08:45Z",
  "Pacific/Apia 2011-12-29T23:00 2011-12-30T09:00Z",
  "Pacific/Apia 2011-12-29T23:15 2011-12-30T09:15Z",
  "Pacific/Apia 2011-12-29T23:30 2011-12-30T09:30Z",
  "Pacific/Apia 2011-12-29T23:45 2011-12-30T09:45Z",
  "Pacific/Apia 2011-12-30T00:00 2011-12-30T10:00Z",
  "Pacific/Apia 2011-12-30T00:00 2011-12-30T10:00Z",
  "Pacific/Apia 2011-12-30T00:15 2011-12-30T10:15Z",
  "Pacific/Apia 2011-12-30T00:30 2011-12-30T10:30Z",
  "Pacific/Apia 2011-12-30T00:45 2011-12-30T10:45Z",
  "Pacific/Apia 2011-12-30T01:00 2011-12-30T11:00Z",
  "Pacific/Apia 2011-12-30T01:15 2011-12-30T11:15Z",
  "Pacific/Apia 2011-12-30T01:30 2011-12-30T11:30Z",
  "Pacific/Apia 2011-12-30T01:45 2011-12-30T11:45Z",
  "Pacific/Apia 2011-12-30T02:00 2011-12-30T12:00Z",
  "Pacific/Apia 2011-12-30T02:15 2011-12-30T12:15Z",
  "Pacific/Apia 2011-12-30T02:30 2011-12-30T12:30Z",
  "Pacific/Apia 2011-12-30T02:45 2011-12-30T12:45Z",
  "Pacific/Apia 2011-12-30T03:00 2011-12-30T13:00Z",
  "Pacific/Apia 2011-12-30T03:15 2011-12-30T13:15Z",
  "Pacific/Apia 2011-12-30T03:30 2011-12-30T13:30Z",
  "Pacific/Apia 2011-12-30T03:45 2011-12-30T13:45Z",
  "Pacific/Apia 2011-12-30T04:00 2011-12-30T14:00Z",
  "Pacific/Apia 2011-12-30T04:15 2011-12-30T14:15Z",
  "Pacific/Apia 2011-12-30T04:30 2011-12-30T14:30Z",
  "Pacific/Apia 2011-12-30T04:45 2011-12-30T14:45Z",
  "Pacific/Apia 2011-12-30T05:00 2011-12-30T15:00Z",
  "Pacific/Apia 2011-12-30T05:15 2011-12-30T15:15Z",
  "Pacific/Apia 2011-12-30T05:30 2011-12-30T15:30Z",
  "Pacific/Apia 2011-12-30T05:45 2011-12-30T15:45Z",
  "Pacific/Apia 2011-12-30T06:00 2011-12-30T16:00Z",
  "Pacific/Apia 2011-12-30T06:15 2011-12-30T16:15Z",
  "Pacific/Apia 2011-12-30T06:30 2011-12-30T16:30Z",
  "Pacific/Apia 2011-12-30T06:45 2011-12-30T16:45Z",
  "Pacific/Apia 2011-12-30T07:00 2011-12-30T17:00Z",
  "Pacific/Apia 2011-12-30T07:15 2011-12-30T17:15Z",
  "Pacific/Apia 2011-12-30T07:30 2011-12-30T17:30Z",
  "Pacific/Apia 2011-12-30T07:45 2011-12-30T17:45Z",
  "Pacific/Apia 2011-12-30T08:00 2011-12-30T18:00Z",
  "Pacific/Apia 2011-12-30T08:15 2011-12-30T18:15Z",
  "Pacific/Apia 2011-12-30T08:30 2011-12-30T18:30Z",
  "Pacific/Apia 2011-12-30T08:45 2011-12-30T18:45Z",
  "Pacific/Apia 2011-12-30T09:00 2011-12-30T19:00Z",
  "Pacific/Apia 2011-12-30T09:15 2011-12-30T19:15Z",
  "Pacific/Apia 2011-12-30T09:30 2011-12-30T19:30Z",
  "Pacific/Apia 2011-12-30T09:45 2011-12-30T19:45Z",
  "Pacific/Apia 2011-12-30T10:00 2011-12-30T20:00Z",
  "Pacific/Apia 2011-12-30T10:15 2011-12-30T20:15Z",
  "Pacific/Apia 2011-12-30T10:30 2011-12-30T20:30Z",
  "Pacific/Apia 2011-12-30T10:45 2011-12-30T20:45Z",
  "Pacific/Apia 2011-12-30T11:00 2011-12-30T21:00Z",
  "Pacific/Apia 2011-12-30T11:15 2011-12-30T21:15Z",
  "Pacific/Apia 2011-12-30T11:30 2011-12-30T21:30Z",
  "Pacific/Apia 2011-12-30T11:45 2011-12-30T21:45Z",
  "Pacific/Apia 2011-12-30T12:00 2011-12-30T22:00Z",
  "Pacific/Apia 2011-12-30T12:15 2011-12-30T22:15Z",
  "Pacific/Apia 2011-12-30T12:30 2011-12-30T22:30Z",
  "Pacific/Apia 2011-12-30T12:45 2011-12-30T22:45Z",
  "Pacific/Apia 2011-12-30T13:00 2011-12-30T23:00Z",
  "Pacific/Apia 2011-12-30T13:15 2011-12-30T23:15Z",
  "Pacific/Apia 2011-12-30T13:30 2011-12-30T23:30Z",
  "Pacific/Apia 2011-12-30T13:45 2011-12-30T23:45Z",
  "Pacific/Apia 2011-12-30T14:00 2011-12-31T00:00Z",
  "Pacific/Apia 2011-12-30T14:15 2011-12-31T00:15Z",
  "Pacific/Apia 2011-12-30T14:30 2011-12-31T00:30Z",
  "Pacific/Apia 2011-12-30T14:45 2011-12-31T00:45Z",
  "Pacific/Apia 2011-12-30T15:00 2011-12-31T01:00Z",
  "Pacific/Apia 2011-12-30T15:15 2011-12-31T01:15Z",
  "Pacific/Apia 2011-12-30T15:30 2011-12-31T01:30Z",
  "Pacific/Apia 2011-12-30T15:45 2011-12-31T01:45Z",
  "Pacific/Apia 2011-12-30T16:00 2011-12-31T02:00Z",
  "Pacific/Apia 2011-12-30T16:15 2011-12-31T02:15Z",
  "Pacific/Apia 2011-12-30T16:30 2011-12-31T02:30Z",
  "Pacific/Apia 2011-12-30T16:45 2011-12-31T02:45Z",
  "Pacific/Apia 2011-12-30T17:00 2011-12-31T03:00Z",
  "Pacific/Apia 2011-12-30T17:15 2011-12-31T03:15Z",
  "Pacific/Apia 2011-12-30T17:30 2011-12-31T03:30Z",
  "Pacific/Apia 2011-12-30T17:45 2011-12-31T03:45Z",
  "Pacific/Apia 2011-12-30T18:00 2011-12-31T04:00Z",
  "Pacific/Apia 2011-12-30T18:15 2011-12-31T04:15Z",
  "Pacific/Apia 2011-12-30T18:30 2011-12-31T04:30Z",
  "Pacific/Apia 2011-12-30T18:45 2011-12-31T04:45Z",
  "Pacific/Apia 2011-12-30T19:00 2011-12-31T05:00Z",
  "Pacific/Apia 2011-12-30T19:15 2011-12-31T05:15Z",
  "Pacific/Apia 2011-12-30T19:30 2011-12-31T05:30Z",
  "Pacific/Apia 2011-12-30T19:45 2011-12-31T05:45Z",
  "Pacific/Apia 2011-12-30T20:00 2011-12-31T06:00Z",
  "Pacific/Apia 2011-12-30T20:15 2011-12-31T06:15Z",
  "Pacific/Apia 2011-12-30T20:30 2011-12-31T06:30Z",
  "Pacific/Apia 2011-12-30T20:45 2011-12-31T06:45Z",
  "Pacific/Apia 2011-12-30T21:00 2011-12-31T07:00Z",
  "Pacific/Apia 2011-12-30T21:15 2011-12-31T07:15Z",
  "Pacific/Apia 2011-12-30T21:30 2011-12-31T07:30Z",
  "Pacific/Apia 2011-12-30T21:45 2011-12-31T07:45Z",
  "Pacific/Apia 2011-12-30T22:00 2011-12-31T08:00Z",
  "Pacific/Apia 2011-12-30T22:15 2011-12-31T08:15Z",
  "Pacific/Apia 2011-12-30T22:30 2011-12-31T08:30Z",
  "Pacific/Apia 2011-12-30T22:45 2011-12-31T08:45Z",
  "Pacific/Apia 2011-12-30T23:00 2011-12-31T09:00Z",
  "Pacific/Apia 2011-12-30T23:15 2011-12-31T09:15Z",
  "Pacific/Apia 2011-12-30T23:30 2011-12-31T09:30Z",
  "Pacific/Apia 2011-12-30T23:45 2011-12-31T09:45Z",
  "Pacific/Apia 2011-12-31T00:00 2011-12-30T10:00Z",
  "Pacific/Apia 2011-12-31T00:00 2011-12-30T10:00Z",
  "Pacific/Apia 2011-12-31T00:15 2011-12-30T10:15Z",
  "Pacific/Apia 2011-12-31T00:30 2011-12-30T10:30Z",
  "Pacific/Apia 2011-12-31T00:45 2011-12-30T10:45Z",
  "Pacific/Apia 2011-12-31T01:00 2011-12-30T11:00Z",
];

const ORDINARY: readonly string[] = [
  "UTC 2026-01-15T00:00 2026-01-15T00:00Z",
  "UTC 2026-06-30T23:59 2026-06-30T23:59Z",
  "UTC 2026-07-04T12:30 2026-07-04T12:30Z",
  "UTC 2026-12-31T23:45 2026-12-31T23:45Z",
  "UTC 2024-02-29T06:05 2024-02-29T06:05Z",
  "Europe/Paris 2026-01-15T00:00 2026-01-14T23:00Z",
  "Europe/Paris 2026-06-30T23:59 2026-06-30T21:59Z",
  "Europe/Paris 2026-07-04T12:30 2026-07-04T10:30Z",
  "Europe/Paris 2026-12-31T23:45 2026-12-31T22:45Z",
  "Europe/Paris 2024-02-29T06:05 2024-02-29T05:05Z",
  "America/New_York 2026-01-15T00:00 2026-01-15T05:00Z",
  "America/New_York 2026-06-30T23:59 2026-07-01T03:59Z",
  "America/New_York 2026-07-04T12:30 2026-07-04T16:30Z",
  "America/New_York 2026-12-31T23:45 2027-01-01T04:45Z",
  "America/New_York 2024-02-29T06:05 2024-02-29T11:05Z",
  "Asia/Tokyo 2026-01-15T00:00 2026-01-14T15:00Z",
  "Asia/Tokyo 2026-06-30T23:59 2026-06-30T14:59Z",
  "Asia/Tokyo 2026-07-04T12:30 2026-07-04T03:30Z",
  "Asia/Tokyo 2026-12-31T23:45 2026-12-31T14:45Z",
  "Asia/Tokyo 2024-02-29T06:05 2024-02-28T21:05Z",
  "Asia/Kolkata 2026-01-15T00:00 2026-01-14T18:30Z",
  "Asia/Kolkata 2026-06-30T23:59 2026-06-30T18:29Z",
  "Asia/Kolkata 2026-07-04T12:30 2026-07-04T07:00Z",
  "Asia/Kolkata 2026-12-31T23:45 2026-12-31T18:15Z",
  "Asia/Kolkata 2024-02-29T06:05 2024-02-29T00:35Z",
  "Asia/Kathmandu 2026-01-15T00:00 2026-01-14T18:15Z",
  "Asia/Kathmandu 2026-06-30T23:59 2026-06-30T18:14Z",
  "Asia/Kathmandu 2026-07-04T12:30 2026-07-04T06:45Z",
  "Asia/Kathmandu 2026-12-31T23:45 2026-12-31T18:00Z",
  "Asia/Kathmandu 2024-02-29T06:05 2024-02-29T00:20Z",
  "Australia/Lord_Howe 2026-01-15T00:00 2026-01-14T13:00Z",
  "Australia/Lord_Howe 2026-06-30T23:59 2026-06-30T13:29Z",
  "Australia/Lord_Howe 2026-07-04T12:30 2026-07-04T02:00Z",
  "Australia/Lord_Howe 2026-12-31T23:45 2026-12-31T12:45Z",
  "Australia/Lord_Howe 2024-02-29T06:05 2024-02-28T19:05Z",
  "Pacific/Auckland 2026-01-15T00:00 2026-01-14T11:00Z",
  "Pacific/Auckland 2026-06-30T23:59 2026-06-30T11:59Z",
  "Pacific/Auckland 2026-07-04T12:30 2026-07-04T00:30Z",
  "Pacific/Auckland 2026-12-31T23:45 2026-12-31T10:45Z",
  "Pacific/Auckland 2024-02-29T06:05 2024-02-28T17:05Z",
  "America/Los_Angeles 2026-01-15T00:00 2026-01-15T08:00Z",
  "America/Los_Angeles 2026-06-30T23:59 2026-07-01T06:59Z",
  "America/Los_Angeles 2026-07-04T12:30 2026-07-04T19:30Z",
  "America/Los_Angeles 2026-12-31T23:45 2027-01-01T07:45Z",
  "America/Los_Angeles 2024-02-29T06:05 2024-02-29T14:05Z",
  "Pacific/Kiritimati 2026-01-15T00:00 2026-01-14T10:00Z",
  "Pacific/Kiritimati 2026-06-30T23:59 2026-06-30T09:59Z",
  "Pacific/Kiritimati 2026-07-04T12:30 2026-07-03T22:30Z",
  "Pacific/Kiritimati 2026-12-31T23:45 2026-12-31T09:45Z",
  "Pacific/Kiritimati 2024-02-29T06:05 2024-02-28T16:05Z",
  "America/St_Johns 2026-01-15T00:00 2026-01-15T03:30Z",
  "America/St_Johns 2026-06-30T23:59 2026-07-01T02:29Z",
  "America/St_Johns 2026-07-04T12:30 2026-07-04T15:00Z",
  "America/St_Johns 2026-12-31T23:45 2027-01-01T03:15Z",
  "America/St_Johns 2024-02-29T06:05 2024-02-29T09:35Z",
];

const PARIS = "Europe/Paris"; // UTC+1 in November
const NEW_YORK = "America/New_York";
const NOW = new Date("2026-11-01T15:00:00Z"); // 16:00 in Paris

describe("firedLabel (O5)", () => {
  it("writes the zone's HH:MM over Today, Yesterday or the date, the day being the zone's", () => {
    expect(firedLabel("2026-11-01T12:00:00Z", { now: NOW, timeZone: PARIS })).toEqual({ time: "13:00", day: "Today" });
    // 23:30 on 31 October in Paris, though 22:30 UTC: the day is the zone's, not UTC's.
    expect(firedLabel("2026-10-31T22:30:00Z", { now: NOW, timeZone: PARIS })).toEqual({
      time: "23:30",
      day: "Yesterday",
    });
    // 00:30 on 1 November in Paris (23:30Z): Today, and an hour written 00, not 24.
    expect(firedLabel("2026-10-31T23:30:00Z", { now: NOW, timeZone: PARIS })).toEqual({ time: "00:30", day: "Today" });
    expect(firedLabel("2026-10-30T08:05:00Z", { now: NOW, timeZone: PARIS })).toEqual({ time: "09:05", day: "30 Oct" });
  });

  it.each([
    ["2026-01-15T12:00:00Z", /^15 Jan$/],
    ["2026-02-15T12:00:00Z", /^15 Feb$/],
    ["2026-03-15T12:00:00Z", /^15 Mar$/],
    ["2026-04-15T12:00:00Z", /^15 Apr$/],
    ["2026-05-15T12:00:00Z", /^15 May$/],
    ["2026-06-15T12:00:00Z", /^15 Jun$/],
    ["2026-07-15T12:00:00Z", /^15 Jul$/],
    ["2026-08-15T12:00:00Z", /^15 Aug$/],
    ["2026-09-15T12:00:00Z", /^15 Sept?$/],
    ["2026-10-15T12:00:00Z", /^15 Oct$/],
  ])("writes %s, a day of this year, as day and month with no year", (fired, expected) => {
    expect(firedLabel(fired, { now: NOW, timeZone: PARIS }).day).toMatch(expected);
  });

  it("adds the year when it is not the current year, the current year being the zone's", () => {
    expect(firedLabel("2025-12-20T12:00:00Z", { now: NOW, timeZone: PARIS }).day).toMatch(/^20 Dec,? 2025$/);
    // 31 December 23:30Z is already 2027 in Paris: there, 20 December 2026 is last year though UTC says it is not.
    const newYear = new Date("2026-12-31T23:30:00Z");
    expect(firedLabel("2026-12-20T12:00:00Z", { now: newYear, timeZone: PARIS }).day).toMatch(/^20 Dec,? 2026$/);
    expect(firedLabel("2026-12-20T12:00:00Z", { now: newYear, timeZone: "UTC" }).day).toBe("20 Dec");
  });

  it("states the same instant in each viewer's zone, with Today the viewer's own", () => {
    const fired = "2026-11-01T12:00:00Z";
    // `NOW` is already 2 November in Tokyo.
    expect(firedLabel(fired, { now: NOW, timeZone: "Asia/Tokyo" })).toEqual({ time: "21:00", day: "Yesterday" });
    expect(firedLabel(fired, { now: NOW, timeZone: NEW_YORK })).toEqual({ time: "07:00", day: "Today" });
  });
});

describe("readFilters, what is set (O7)", () => {
  it("reads no key, and empty values, as no filter, whatever tz holds", () => {
    const none = { outcome: null, after: null, before: null };
    expect(valid(read(PARIS))).toEqual(none);
    expect(valid(read(PARIS, ["outcome", ""], ["fired_after", ""], ["fired_before", ""], ["tz", ""]))).toEqual(none);
    // `tz` alone is never a filter: the read has all three unset, whether it names a zone or the zone is empty.
    expect(valid(read(PARIS, ["tz", "Asia/Tokyo"]))).toEqual(none);
  });

  it.each(["benign", "false-positive", "inconclusive", "malicious", "unresolved", "none"])(
    "accepts the outcome %s",
    (outcome) => {
      expect(valid(read(PARIS, ["outcome", outcome])).outcome).toBe(outcome);
    },
  );

  it.each([
    "evil",
    "Malicious",
    "MALICIOUS",
    " malicious",
    "malicious ",
    "All",
    "No outcome yet",
    "unsanctioned-benign",
    "null",
    "0",
  ])("refuses the outcome %j, however the six values are spelled", (outcome) => {
    expect(read(PARIS, ["outcome", outcome])).toBe("invalid");
    expect(read(PARIS, ["outcome", outcome], ["fired_after", "2026-11-12T00:00"])).toBe("invalid");
  });
});

describe("readFilters, the times (O7)", () => {
  it.each([
    "2026-11-12",
    "2026-11-12T00",
    "2026-11-12T00:00:00",
    "2026-11-12T00:00:00Z",
    "2026-11-12T00:00Z",
    "2026-11-12T00:00+01:00",
    "2026-11-12 00:00",
    "26-11-12T00:00",
    "2026-1-2T00:00",
    "12/11/2026 00:00",
    "yesterday",
    " 2026-11-12T00:00",
    "2026-11-12T00:00 ",
  ])("refuses the time %j, which is not YYYY-MM-DDTHH:MM", (text) => {
    expect(read(PARIS, ["fired_after", text])).toBe("invalid");
    expect(read(PARIS, ["fired_before", text])).toBe("invalid");
    expect(
      valid(read(PARIS, ["fired_after", "2026-11-12T00:00"])).after,
      "positive control: the format itself reads",
    ).toBe(at("2026-11-11T23:00:00Z"));
  });

  it("reads each time in the zone tz names, and in the viewer's zone when tz is absent or empty", () => {
    const wall: Pair = ["fired_after", "2026-11-12T00:00"];
    expect(valid(read(PARIS, wall)).after).toBe(at("2026-11-11T23:00:00Z"));
    expect(valid(read(PARIS, wall, ["tz", ""])).after).toBe(at("2026-11-11T23:00:00Z"));
    expect(valid(read(NEW_YORK, wall)).after).toBe(at("2026-11-12T05:00:00Z"));
    // tz wins over the viewer's zone, whichever way round.
    expect(valid(read(NEW_YORK, wall, ["tz", PARIS])).after).toBe(at("2026-11-11T23:00:00Z"));
    expect(valid(read(PARIS, wall, ["tz", NEW_YORK])).after).toBe(at("2026-11-12T05:00:00Z"));
  });

  it("gives a link the same instants for whoever opens it, and only the viewer's zone moves a link with no tz", () => {
    const link: Pair[] = [
      ["fired_after", "2026-06-30T23:59"],
      ["fired_before", "2026-07-01T08:15"],
      ["tz", "Asia/Kolkata"],
    ];
    const expected = { outcome: null, after: at("2026-06-30T18:29:00Z"), before: at("2026-07-01T02:45:00Z") };
    for (const viewer of ["UTC", PARIS, NEW_YORK, "Pacific/Kiritimati", "Australia/Lord_Howe"])
      expect(valid(read(viewer, ...link)), viewer).toEqual(expected);
    expect(valid(read("UTC", ...link.slice(0, 2))).after).not.toBe(valid(read(PARIS, ...link.slice(0, 2))).after);
  });

  it("reads the outcome, after and before together, each on its own", () => {
    expect(valid(read(PARIS, ["outcome", "none"], ["fired_before", "2026-11-12T08:00"]))).toEqual({
      outcome: "none",
      after: null,
      before: at("2026-11-12T07:00:00Z"),
    });
  });
});

describe("readFilters, wall times near a clock change (O7)", () => {
  it("resolves a wall time a clock change skipped to the offset before the change, and a repeated one to its first", () => {
    const wall = (zone: string, time: string) => valid(read(zone, ["fired_after", time], ["tz", zone])).after;
    expect(wall(PARIS, "2026-03-29T02:30")).toBe(at("2026-03-29T01:30:00Z")); // skipped: +01:00, lands at 03:30
    expect(wall(PARIS, "2026-10-25T02:30")).toBe(at("2026-10-25T00:30:00Z")); // repeated: the +02:00 one
    expect(wall(NEW_YORK, "2026-03-08T02:30")).toBe(at("2026-03-08T07:30:00Z"));
    expect(wall(NEW_YORK, "2026-11-01T01:30")).toBe(at("2026-11-01T05:30:00Z"));
    expect(wall("Australia/Lord_Howe", "2026-10-04T02:15")).toBe(at("2026-10-03T15:45:00Z")); // a 30-minute change
    expect(wall("Australia/Lord_Howe", "2026-04-05T01:45")).toBe(at("2026-04-04T14:45:00Z"));
    expect(wall("Pacific/Apia", "2011-12-30T12:00")).toBe(at("2011-12-30T22:00:00Z")); // a whole day skipped
  });

  it.each(TRANSITIONS)("resolves %s the way `compatible` does, and never calls a wall time invalid", (row) => {
    const [zone, time, instant] = row.split(" ") as [string, string, string];
    expect(valid(read(PARIS, ["fired_before", time], ["tz", zone])).before).toBe(at(instant));
  });

  it.each(ORDINARY)("reads %s", (row) => {
    const [zone, time, instant] = row.split(" ") as [string, string, string];
    expect(valid(read("UTC", ["fired_after", time], ["tz", zone])).after).toBe(at(instant));
  });
});

describe("readFilters, the addresses it refuses (O7)", () => {
  it.each([["Mars/Phobos"], ["Nowhere"], ["Europe/Nowhere"], ["UTC+1x"]])(
    "refuses the zone %s the browser does not know, with times set or not",
    (zone) => {
      expect(read(PARIS, ["tz", zone])).toBe("invalid");
      expect(read(PARIS, ["tz", zone], ["outcome", "malicious"])).toBe("invalid");
      expect(read(PARIS, ["tz", zone], ["fired_after", "2026-11-12T00:00"])).toBe("invalid");
    },
  );

  it("refuses any of the four keys given twice, even with the same value or an empty one", () => {
    const given: Record<string, string> = {
      outcome: "malicious",
      fired_after: "2026-11-12T00:00",
      fired_before: "2026-11-13T00:00",
      tz: NEW_YORK,
    };
    for (const [key, value] of Object.entries(given)) {
      expect(read(PARIS, [key, value], [key, value]), `${key} twice`).toBe("invalid");
      expect(read(PARIS, [key, ""], [key, value]), `${key}, empty then set`).toBe("invalid");
      expect(read(PARIS, [key, value], [key, ""]), `${key}, set then empty`).toBe("invalid");
      expect(read(PARIS, [key, ""], [key, ""]), `${key}, both empty`).toBe("invalid");
    }
    // Positive control: a key the screen does not read may repeat.
    expect(valid(read(PARIS, ["x", "1"], ["x", "2"], ["outcome", "benign"])).outcome).toBe("benign");
  });
});
