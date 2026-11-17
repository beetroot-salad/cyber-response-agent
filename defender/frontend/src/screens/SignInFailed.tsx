// The sign-in-failed screen (B1, B4): shows why sign-in did not complete, and a retry. It makes no authenticated call at
// load; the shell has settled its `return` into the address, and `retry` passes it on to the shell's sign-in, which the API judges.
import { useActions, useAddress } from "../shell/provider";

export const REASONS = [
  "prelogin-missing",
  "login-attempt-invalid",
  "unknown-account",
  "otp-required",
  "unavailable",
  "bad-request",
  "error",
  "session-lost",
  "sign-in-left",
  "session-refused",
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
  // Also shown when the person left the provider by a bookmark or a typed address: the shell sees only a fresh load.
  "session-lost": "You signed in, but this browser did not keep the session. It may be blocking cookies for this site.",
  "sign-in-left": "Sign-in did not finish, so you are not signed in.",
  // `/api/me` accepted the session, but this page's own request was refused twice: signing in again cannot help.
  "session-refused": "You are signed in, but the server refused this page. If trying again does not help, tell your administrator.",
  "storage-unavailable": "This browser does not let the app keep a sign-in attempt, so it cannot sign you in automatically.",
};

function reasonOf(value: string | null): Reason {
  return REASONS.find((reason) => reason === value) ?? "error";
}

export function SignInFailed() {
  const { query } = useAddress();
  const actions = useActions();
  const reason = reasonOf(query.get("reason"));
  return (
    <main data-screen="sign-in-failed">
      <h1>Sign-in failed</h1>
      <p data-reason={reason}>{MESSAGES[reason]}</p>
      <button type="button" data-action="retry" onClick={() => actions.retry()}>
        Try again
      </button>
    </main>
  );
}
