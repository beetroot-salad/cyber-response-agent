// The tenant's knowledge repository (`/t/{uuid}/repo`; home redesign): an app address Home and the top bar link to, so
// no screen links off the app. It reads where the repository is and the shell sends the person there, replacing this
// page (Back returns to where they came from). With nothing recorded, or an address the shell will not send a browser
// to, it says so.
import { useEffect, type ReactNode } from "react";
import { stateOf, useActions, usePlaceholders, useRead } from "../shell/provider";
import { TopBar } from "./TopBar";

const READ = "/api/tenants/{tenant_id}/repository";

export function Repo() {
  const [tenant_id] = usePlaceholders("repo");
  const result = useRead(READ, { path: { tenant_id } });
  const actions = useActions();
  const served = result.kind === "ok" ? result.body.repo_url : null;
  const address = served !== null && actions.mayOpenRepository(served) ? served : null;
  useEffect(() => {
    if (address !== null) actions.openRepository(address);
  }, [address, actions]);
  return (
    <>
      <TopBar tenant={tenant_id} />
      <main data-screen="repo" data-state={stateOf(result)}>
        <h1>Knowledge repo</h1>
        {content(result.kind, address)}
      </main>
    </>
  );
}

function content(kind: string, address: string | null): ReactNode {
  if (kind === "not-available") return <p>There is nothing at this address.</p>;
  if (kind === "error")
    return <p data-said="error">Couldn't find this tenant's repository. Reload the page to try again.</p>;
  if (kind !== "ok") return <p>Opening the repository…</p>;
  if (address === null) return <p data-said="none">This tenant has no repository Sluice can link to.</p>;
  return <p>Opening the repository…</p>;
}
