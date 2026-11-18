// The sign-in-failed screen (B1, B4): shows why sign-in did not complete, and a retry. It makes no authenticated call
// at load; the shell has settled its `return` into the address, and `retry` passes it on to the shell's sign-in, which
// the API judges.
import { useActions, useQueryOfAddress, type CallbackReason, type FailedReason } from "../shell/provider";

/** Every reason the failed screen is sent with: the API's callback's and the shell's own. A reason without a message
 * here does not compile. */
type Reason = CallbackReason | FailedReason;

const MESSAGES: Readonly<Record<Reason, string>> = {
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
  "session-refused":
    "You are signed in, but the server refused this page. If trying again does not help, tell your administrator.",
  "storage-unavailable":
    "This browser does not let the app keep a sign-in attempt, so it cannot sign you in automatically.",
};
/** Each reason's code and message, by the code the address may hold. */
const BY_CODE: ReadonlyMap<string, { readonly reason: string; readonly text: string }> = new Map(
  Object.entries(MESSAGES).map(([reason, text]) => [reason, { reason, text }]),
);
/** The address is anyone's to type: a reason this screen does not know is shown as the general failure. */
const GENERAL = { reason: "error", text: MESSAGES.error };

export function SignInFailed() {
  const asked = useQueryOfAddress().get("reason");
  const actions = useActions();
  const { reason, text } = (asked === null ? undefined : BY_CODE.get(asked)) ?? GENERAL;
  return (
    <main data-screen="sign-in-failed">
      <h1>Sign-in failed</h1>
      <p data-reason={reason}>{text}</p>
      <button type="button" data-action="retry" onClick={() => actions.retry()}>
        Try again
      </button>
    </main>
  );
}
