// The minimal investigation screen (B7): the status and outcome of the investigation read, as their raw codes.
import { useAddress, useRead } from "../shell/provider";

export function Investigation() {
  const { segments } = useAddress();
  const [, tenant, , id] = segments;
  const result = useRead("/api/tenants/{tenant_id}/investigations/{investigation_id}", {
    path: { tenant_id: tenant ?? "", investigation_id: id ?? "" },
  });
  if (result.kind === "loading" || result.kind === "gone") {
    return (
      <main data-screen="investigation" data-state="loading">
        <h1>Investigation</h1>
      </main>
    );
  }
  if (result.kind === "not-available") {
    return (
      <main data-screen="investigation" data-state="not-available">
        <h1>Investigation</h1>
        <p>This investigation is not available.</p>
      </main>
    );
  }
  if (result.kind === "error") {
    return (
      <main data-screen="investigation" data-state="error">
        <h1>Investigation</h1>
        <p>The investigation could not be loaded.</p>
      </main>
    );
  }
  return (
    <main data-screen="investigation" data-state="ready">
      <h1>Investigation</h1>
      <dl>
        <dt>Status</dt>
        <dd data-field="status">{result.body.status}</dd>
        <dt>Outcome</dt>
        <dd data-field="outcome">{result.body.disposition ?? "none"}</dd>
      </dl>
    </main>
  );
}
