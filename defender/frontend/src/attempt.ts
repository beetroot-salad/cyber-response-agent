// The tab's sign-in attempt record (#1161 B1): the only thing the app keeps in sessionStorage. It holds the target a
// sign-in was started for (a matched returnable pathname, or none). Written when the shell or the failed screen's
// retry sends the browser to sign in; read and deleted on every load.
const KEY = "defender.attempt";

export type Read =
  | { readonly status: "none" }
  | { readonly status: "found"; readonly target: string | null }
  | { readonly status: "unavailable" };

/** Read and delete this tab's record. `unavailable` when the storage cannot be used. */
export function take(): Read {
  try {
    const storage = window.sessionStorage;
    const raw = storage.getItem(KEY);
    if (raw === null) return { status: "none" };
    storage.removeItem(KEY);
    let target: string | null = null;
    try {
      const parsed: unknown = JSON.parse(raw);
      const value = (parsed as { target?: unknown } | null)?.target;
      if (typeof value === "string") target = value;
    } catch {
      // a record that cannot be read is still a record
    }
    return { status: "found", target };
  } catch {
    return { status: "unavailable" };
  }
}

/** Record an attempt for `target`; false when the storage cannot be used. */
export function record(target: string | null): boolean {
  try {
    window.sessionStorage.setItem(KEY, JSON.stringify({ target }));
    return true;
  } catch {
    return false;
  }
}
