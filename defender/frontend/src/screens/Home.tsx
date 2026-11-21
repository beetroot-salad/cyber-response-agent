// The signed-in home (F4; alert list design O8, O11, amended by the home redesign): for each of the person's tenants,
// a card that opens its alerts and a card that opens its knowledge repository (through the app's `/t/<tenant>/repo`,
// which sends the person on to the forge); each open invitation with Accept; and with neither, that Sluice is
// invite-only. With several tenants, each tenant's cards sit under its id. Who is signed in, and sign-out, are in the
// top bar.
import { useState } from "react";
import { addressOf } from "../addresses";
import { useActions, useMe, type AcceptResult, type Person } from "../shell/provider";
import { TopBar } from "./TopBar";

export function Home() {
  const me = useMe();
  const lone = me.tenants.length === 1;
  return (
    <>
      <TopBar current="home" />
      <main data-screen="home">
        <h1>Home</h1>
        {me.tenants.length > 0 ? (
          <ul data-list="tenants">
            {me.tenants.map(({ tenant_id }) => (
              <Tenant key={tenant_id} tenant={tenant_id} lone={lone} />
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
      </main>
    </>
  );
}

/** One tenant's cards: its alerts, and its knowledge repository. Under the tenant's id when the person has several. */
function Tenant({ tenant, lone }: { readonly tenant: string; readonly lone: boolean }) {
  return (
    <li data-tenant={tenant}>
      {lone ? null : <h2 data-field="tenant">{tenant}</h2>}
      <div data-cards="tenant">
        <section data-card="alerts">
          <h3>Alerts</h3>
          <p>Every alert pulled from your ticket system, with what Sluice concluded.</p>
          <a href={addressOf("alerts", [tenant])} data-action="open-alerts">
            Open alerts
          </a>
        </section>
        <section data-card="repo">
          <h3>Knowledge repo</h3>
          <p>
            What Sluice has learned about your environment, kept as files. A change takes effect once someone on your
            team merges it, and Sluice asks for feedback there as issues you answer in a comment.
          </p>
          <a href={addressOf("repo", [tenant])} data-action="open-repo">
            Open repo <span aria-hidden="true">↗</span>
          </a>
        </section>
      </div>
    </li>
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
