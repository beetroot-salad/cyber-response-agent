// The minimal investigation screen (B7): the status and outcome of the investigation read, as their raw codes.
import { element, type Screen } from "../screen";

function text(body: unknown, field: string): string | null {
  const value = (body as Record<string, unknown> | null)?.[field];
  return typeof value === "string" ? value : null;
}

export const investigation: Screen = {
  needsSession: true,
  async render(context) {
    const [, tenant, , id] = context.segments;
    const main = element("main", { "data-screen": "investigation", "data-state": "loading" });
    main.append(element("h1", {}, "Investigation"));
    context.mount(main);
    const result = await context.read(
      `/api/tenants/${encodeURIComponent(tenant ?? "")}/investigations/${encodeURIComponent(id ?? "")}`,
    );
    if (result.kind === "gone") return;
    if (result.kind === "not-available") {
      main.setAttribute("data-state", "not-available");
      main.append(element("p", {}, "This investigation is not available."));
      return;
    }
    if (result.kind === "error") {
      main.setAttribute("data-state", "error");
      main.append(element("p", {}, "The investigation could not be loaded."));
      return;
    }
    main.setAttribute("data-state", "ready");
    const list = element("dl");
    list.append(
      element("dt", {}, "Status"),
      element("dd", { "data-field": "status" }, text(result.body, "status") ?? "unknown"),
      element("dt", {}, "Outcome"),
      element("dd", { "data-field": "outcome" }, text(result.body, "disposition") ?? "none"),
    );
    main.append(list);
  },
};
