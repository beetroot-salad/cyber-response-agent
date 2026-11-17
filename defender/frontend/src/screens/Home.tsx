// The signed-in home (F4): who is signed in, and a sign-out.
import { useActions, useMe } from "../shell/provider";

export function Home() {
  const me = useMe();
  const actions = useActions();
  return (
    <main data-screen="home">
      <h1>Home</h1>
      <p>
        Signed in as <span data-field="email">{me.user.email}</span>
      </p>
      <button type="button" data-action="sign-out" onClick={() => actions.signOut()}>
        Sign out
      </button>
    </main>
  );
}
