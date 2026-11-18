// B1's decision (#1161 B1, #1540 Am-5): what a 401 means, as a pure function. It takes no target and does no effect; the
// load carries the decision out.

/** What reading this load's attempt record found. */
export type Taken =
  | { readonly status: "none" }
  | { readonly status: "found"; readonly again: boolean }
  | { readonly status: "unavailable" };

/** The reasons the API's sign-in callback sends a person to the failed screen with (the API's identity service). Not in
 * the OpenAPI document: the callback answers with a redirect. */
export type CallbackReason =
  | "prelogin-missing"
  | "login-attempt-invalid"
  | "unknown-account"
  | "otp-required"
  | "unavailable"
  | "bad-request"
  | "error";

/** Why the shell sends a load to the failed screen. */
export type FailedReason = "session-lost" | "sign-in-left" | "storage-unavailable" | "session-refused";

/** Which call of the load was answered 401: its own `/api/me`, or a later one. */
export type Source = "me" | "later";

export type Decision = { readonly kind: "sign-in"; readonly again: boolean } | { readonly kind: "failed"; readonly reason: FailedReason };

export function decideUnauthorized(input: {
  readonly taken: Taken;
  /** Reached by Back/Forward, or restored from the back-forward cache. */
  readonly byHistory: boolean;
  readonly source: Source;
}): Decision {
  const { taken, byHistory, source } = input;
  // A load that could not read its record starts no sign-in, whichever call was answered 401 (B1.3).
  if (taken.status === "unavailable") return { kind: "failed", reason: "storage-unavailable" };
  if (source === "me") {
    if (taken.status === "none") return { kind: "sign-in", again: false };
    // Back (or Forward) to a page that sent itself to sign in means the person left the provider before finishing; any
    // other return with a record means sign-in finished but its session did not arrive.
    return { kind: "failed", reason: byHistory ? "sign-in-left" : "session-lost" };
  }
  // A later call: `/api/me` accepted the session but this one is refused. After a sign-in that a call's own 401 started,
  // a second such 401 stops instead of signing in forever.
  if (taken.status === "found") {
    return taken.again ? { kind: "failed", reason: "session-refused" } : { kind: "sign-in", again: true };
  }
  return { kind: "sign-in", again: false };
}
