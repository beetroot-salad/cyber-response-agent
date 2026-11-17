// The public landing page (F4): the same signed out or in, and it asks nothing of the API. "Sign in" is a plain link, a
// full page load that runs the shell's B1 at `/home`.
import illustration from "../../look/illustration.svg";
import { literalAddress } from "../addresses";

export function Root() {
  return (
    <main data-screen="root">
      <img src={illustration} alt="" width="160" height="160" />
      <h1>Defender</h1>
      <p>An agent that investigates what your systems raise, so people see the answer first.</p>
      <a href={literalAddress("home")} data-action="sign-in">
        Sign in
      </a>
    </main>
  );
}
