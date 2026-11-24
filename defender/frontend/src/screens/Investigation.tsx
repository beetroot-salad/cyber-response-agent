// The minimal investigation screen (B7): the status and outcome of the investigation read, as their raw codes.
import type { ReactNode } from "react";
import { stateOf, usePlaceholders, useRead, type ScreenRead } from "../shell/provider";
import { TopBar } from "./TopBar";

const READ = "/api/tenants/{tenant_id}/investigations/{investigation_id}";

export function Investigation() {
  const [tenant_id, investigation_id] = usePlaceholders("investigation");
  const result = useRead(READ, { path: { tenant_id, investigation_id } });
  return (
    <>
      <TopBar tenant={tenant_id} />
      <main data-screen="investigation" data-state={stateOf(result)}>
        <h1>Investigation</h1>
        {content(result)}
      </main>
    </>
  );
}

function content(result: ScreenRead<typeof READ>): ReactNode {
  switch (result.kind) {
    case "loading":
      return null;
    case "not-available":
      return <p>This investigation is not available.</p>;
    case "error":
      return <p>The investigation could not be loaded.</p>;
    case "ok":
      return (
        <dl>
          <dt>Status</dt>
          <dd data-field="status">{result.body.status}</dd>
          <dt>Outcome</dt>
          <dd data-field="outcome">{result.body.disposition ?? "none"}</dd>
        </dl>
      );
  }
}
