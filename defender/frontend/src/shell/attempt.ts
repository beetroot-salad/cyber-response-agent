// The tab's sign-in attempt record (#1161 B1): the only thing the app keeps in sessionStorage. It holds the target a
// sign-in was started for (a matched returnable pathname, or none). Written when the shell or the failed screen's
// retry sends the browser to sign in; read and deleted on every load. `again` marks an attempt started by a screen's
// own 401 on a load that had itself come back from sign-in: a second such 401 stops instead of signing in again.
import type { Taken } from "./decision";

const KEY = "defender.attempt";

/** What the decision takes (`Taken`), with the target a found record names. */
export type Read =
  | Exclude<Taken, { readonly status: "found" }>
  | (Extract<Taken, { readonly status: "found" }> & { readonly target: string | null });

/** Read and delete this tab's record. `unavailable` when the storage cannot be used. */
export function take(): Read {
  let raw: string | null;
  try {
    const storage = window.sessionStorage;
    raw = storage.getItem(KEY);
    if (raw !== null) storage.removeItem(KEY);
  } catch {
    return { status: "unavailable" };
  }
  return raw === null ? { status: "none" } : { status: "found", ...contentOf(raw) };
}

/** A record's target and `again`. A record that cannot be read is still a record: no target, not again. */
function contentOf(raw: string): { readonly target: string | null; readonly again: boolean } {
  const parsed = parsedJson(raw);
  if (typeof parsed !== "object" || parsed === null) return { target: null, again: false };
  return {
    target: "target" in parsed && typeof parsed.target === "string" ? parsed.target : null,
    again: "again" in parsed && parsed.again === true,
  };
}

/** `raw` read as JSON, or null when it is not JSON. */
function parsedJson(raw: string): unknown {
  try {
    const value: unknown = JSON.parse(raw);
    return value;
  } catch {
    return null;
  }
}

/** Record an attempt for `target`; false when the storage cannot be used. */
export function record(target: string | null, again: boolean): boolean {
  try {
    window.sessionStorage.setItem(KEY, JSON.stringify({ target, again }));
    return true;
  } catch {
    return false;
  }
}
