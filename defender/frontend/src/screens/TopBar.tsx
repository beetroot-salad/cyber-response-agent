// The top bar of every signed-in screen: the product's name, a link home; who is signed in; and sign-out. Only a screen
// the shell asked `/api/me` for draws it.
import { literalAddress } from "../addresses";
import { useActions, useMe } from "../shell/provider";

export function TopBar() {
  const me = useMe();
  const actions = useActions();
  return (
    <header data-bar="top">
      <a href={literalAddress("home")} data-action="home">
        Sluice
      </a>
      <span data-field="email">{me.user.email}</span>
      <button type="button" data-action="sign-out" onClick={() => actions.signOut()}>
        Sign out
      </button>
    </header>
  );
}
