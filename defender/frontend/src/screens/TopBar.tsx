// The top bar of every signed-in screen: the product's name, a link home; the screens of the tenant in view (Home,
// its Alerts, its knowledge repository on the forge); who is signed in; and sign-out. Only a screen the shell asked
// `/api/me` for draws it.
//
// The tenant in view is the one the address names, else the person's only tenant. The tenant links show only for a
// tenant the person is in, and the repository's only when the shell checked its page; with several tenants and none
// named (Home), only Home shows. Configuration joins the bar when its screen exists.
import { addressOf, literalAddress, repoLink } from "../addresses";
import { useActions, useMe, useRepoAddress } from "../shell/provider";

/** The screen the bar is drawn on, for the link that says so (`aria-current`). */
type Current = "home" | "alerts" | null;

export function TopBar({ tenant, current = null }: { readonly tenant?: string; readonly current?: Current }) {
  const me = useMe();
  const actions = useActions();
  const named = tenant ?? (me.tenants.length === 1 ? me.tenants[0]?.tenant_id : undefined);
  const inView = me.tenants.find(({ tenant_id }) => tenant_id === named)?.tenant_id ?? null;
  const repo = useRepoAddress(inView);
  const here = (screen: Current) => (current === screen ? "page" : undefined);
  return (
    <header data-bar="top">
      <a href={literalAddress("home")} data-action="home">
        Sluice
      </a>
      <nav aria-label="Main">
        <a href={literalAddress("home")} data-nav="home" aria-current={here("home")}>
          Home
        </a>
        {inView === null ? null : (
          <a href={addressOf("alerts", [inView])} data-nav="alerts" aria-current={here("alerts")}>
            Alerts
          </a>
        )}
        {repo === null ? null : (
          <a href={repoLink(repo)} data-nav="repo">
            Knowledge repo <span aria-hidden="true">↗</span>
          </a>
        )}
      </nav>
      <span data-field="email">{me.user.email}</span>
      <button type="button" data-action="sign-out" onClick={() => actions.signOut()}>
        Sign out
      </button>
    </header>
  );
}
