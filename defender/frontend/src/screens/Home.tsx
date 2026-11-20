// The signed-in home (F4; alert list design O8, O11): who is signed in, a link to each of their tenants' alerts, each
// open invitation with Accept, and with neither, that Sluice is invite-only. A sign-out.
import { useState } from "react";
import { addressOf } from "../addresses";
import { useActions, useMe, type AcceptResult, type Person } from "../shell/provider";

export function Home() {
  const me = useMe();
  const actions = useActions();
  const lone = me.tenants.length === 1;
  return (
    <main data-screen="home">
      <h1>Home</h1>
      <p>
        Signed in as <span data-field="email">{me.user.email}</span>
      </p>
      {me.tenants.length > 0 ? (
        <ul data-list="tenants">
          {me.tenants.map(({ tenant_id }) => (
            <li key={tenant_id}>
              <a href={addressOf("alerts", [tenant_id])}>{lone ? "Alerts" : `Alerts — ${tenant_id}`}</a>
            </li>
          ))}
        </ul>
      ) : null}
      {me.invitations.length > 0 ? (
        <ul data-list="invitations">
          {me.invitations.map((invitation) => (
            <Invitation key={invitation.id} id={invitation.id} />
          ))}
        </ul>
      ) : null}
      {me.tenants.length === 0 && me.invitations.length === 0 ? <InviteOnly me={me} /> : null}
      <button type="button" data-action="sign-out" onClick={() => actions.signOut()}>
        Sign out
      </button>
    </main>
  );
}

function InviteOnly({ me }: { readonly me: Person }) {
  return (
    <p>
      You haven't been added to a team yet. Sluice is invite-only. Ask your administrator to invite {me.user.email}.
    </p>
  );
}

/** An invitation's own state: not yet accepted, its request in flight, or what the request came to. */
type Accepting = { readonly kind: "open" } | { readonly kind: "sending" } | AcceptResult;

/** What each answer that is not a success says, under the invitation. */
const SAID: Readonly<Partial<Record<Accepting["kind"], string>>> = {
  "not-open": "This invitation is no longer open.",
  refused: "You can't accept this invitation.",
  error: "Couldn't accept the invitation. Reload the page to try again.",
};

/** One open invitation and its Accept. Accept is disabled while its request is in flight; once answered without
 * leaving, the button goes and what happened is said instead (no retry in place). */
function Invitation({ id }: { readonly id: string }) {
  const actions = useActions();
  const [state, setState] = useState<Accepting>({ kind: "open" });
  const accept = (): void => {
    setState({ kind: "sending" });
    void actions.acceptInvitation(id).then(setState);
  };
  const said = SAID[state.kind];
  // While open or in flight, and once the shell has left or the load is gone (the page is going away), the button
  // stays as it is: only an answer the person must read takes it away.
  return (
    <li data-invitation={id}>
      <span>You've been invited to a team.</span>{" "}
      {said === undefined ? (
        <button type="button" disabled={state.kind !== "open"} onClick={accept}>
          Accept
        </button>
      ) : (
        <p data-said={state.kind}>{said}</p>
      )}
    </li>
  );
}
