// The sign-in-failed screen (B1, B4): shows why sign-in did not complete, and a retry. It makes no authenticated
// call at load. `return` is only ever passed on to `/api/auth/login`, which judges it.
import { record } from "../attempt";
import { element, type Screen } from "../screen";

export const REASONS = [
  "prelogin-missing",
  "login-attempt-invalid",
  "unknown-account",
  "otp-required",
  "unavailable",
  "bad-request",
  "error",
  "session-lost",
  "storage-unavailable",
] as const;
export type Reason = (typeof REASONS)[number];

const MESSAGES: Record<Reason, string> = {
  "prelogin-missing": "This sign-in attempt was not found. It may have expired or been opened in another browser.",
  "login-attempt-invalid": "The identity provider did not accept this sign-in attempt.",
  "unknown-account": "Your account is not known here.",
  "otp-required": "A second factor is required for this account.",
  unavailable: "Sign-in is temporarily unavailable.",
  "bad-request": "The sign-in request was not valid.",
  error: "Sign-in failed.",
  "session-lost": "You were signed in, but the session did not arrive.",
  "storage-unavailable": "This browser does not let the app keep a sign-in attempt, so it cannot sign you in automatically.",
};

function reasonOf(value: string | null): Reason {
  return REASONS.find((reason) => reason === value) ?? "error";
}

export const signInFailed: Screen = {
  needsSession: false,
  render(context) {
    const params = new URLSearchParams(window.location.search);
    const reason = reasonOf(params.get("reason"));

    // Settle the consumed record's target into the address, unless the address has a return already or the target
    // was the one refused.
    if (!params.has("return") && reason !== "bad-request" && context.attempt.status === "found" && context.attempt.target !== null) {
      params.set("return", context.attempt.target);
      window.history.replaceState(window.history.state, "", `${window.location.pathname}?${params.toString()}`);
    }

    const main = element("main", { "data-screen": "sign-in-failed" });
    const retry = element("button", { type: "button", "data-action": "retry" }, "Try again");
    retry.addEventListener("click", () => {
      // The address as it is now (the settle above may have added its `return`).
      const returns = new URLSearchParams(window.location.search).getAll("return");
      record(returns[0] ?? null);
      const query = returns.map((value) => `return=${encodeURIComponent(value)}`).join("&");
      window.location.assign(`/api/auth/login${query === "" ? "" : `?${query}`}`);
    });
    main.append(
      element("h1", {}, "Sign-in failed"),
      element("p", { "data-reason": reason }, MESSAGES[reason]),
      retry,
    );
    context.mount(main);
  },
};
