// The tenant's knowledge repository (`/t/{uuid}/repo`; home redesign): an app address Home and the top bar link to, so
// no screen links off the app. It reads where the repository is and the shell sends the person there, replacing this
// page (Back returns to where they came from). With nothing recorded, or an address the shell will not send a browser
// to, it says so.
import { useEffect, useMemo, type ReactNode } from "react";
import { stateOf, useActions, usePlaceholders, useRead, type ScreenRead } from "../shell/provider";
import { TopBar } from "./TopBar";

const READ = "/api/tenants/{tenant_id}/repository";

export function Repo() {
  const [tenant_id] = usePlaceholders("repo");
  const result = useRead(READ, { path: { tenant_id } });
  const actions = useActions();
  const served = result.kind === "ok" ? result.body.repo_url : null;
  const leave = useMemo(() => (served === null ? null : actions.outbound(served)), [served, actions]);
  useEffect(() => {
    leave?.();
  }, [leave]);
  return (
    <>
      <TopBar tenant={tenant_id} current="repo" />
      <main data-screen="repo" data-state={stateOf(result)}>
        <h1>Knowledge repo</h1>
        {content(result.kind, leave !== null)}
      </main>
    </>
  );
}

function content(kind: ScreenRead<typeof READ>["kind"], leaving: boolean): ReactNode {
  if (kind === "not-available") return <p>There is nothing at this address.</p>;
  if (kind === "error")
    return <p data-said="error">Couldn't find this tenant's repository. Reload the page to try again.</p>;
  if (kind !== "ok") return <p>Finding the repository…</p>;
  if (!leaving) return <p data-said="none">This tenant has no repository Sluice can link to.</p>;
  return <p>Opening the repository…</p>;
}
