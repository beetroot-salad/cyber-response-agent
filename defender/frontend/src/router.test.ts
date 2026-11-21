// The router's handling of the alerts address (alert list design O4): a returnable shape, so the shell asks `/api/me`
// first and sign-in returns to its path, not its query (`route` is given the pathname alone).
import { describe, expect, it } from "vitest";
import { route } from "./router";

const TENANT = "0b6f1c1e-3c55-4a4e-9a51-1083000000aa";
const INVESTIGATION = "7c1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f";

describe("route, for the alerts address", () => {
  it("is the alerts shape, needs the session, and is the target sign-in returns to", () => {
    const path = `/t/${TENANT}/alerts`;
    const found = route(path);
    expect(found.shape).toBe("alerts");
    expect(found.needsSession).toBe(true);
    expect(found.target).toBe(path);
  });

  it("has a screen of its own, neither the investigation's, the home's nor the not-found one", () => {
    const alerts = route(`/t/${TENANT}/alerts`).Screen;
    expect(alerts).not.toBe(route(`/t/${TENANT}/investigations/${INVESTIGATION}`).Screen);
    expect(alerts).not.toBe(route("/home").Screen);
    expect(alerts).not.toBe(route(`/t/${TENANT}/alerts/`).Screen);
  });

  it("does not take a near miss of the path for the alerts shape", () => {
    for (const path of [`/t/${TENANT}/alerts/`, `/t/${TENANT}/Alerts`, `/t/${TENANT}`]) {
      const found = route(path);
      expect(found.shape, path).toBeNull();
      expect(found.target, path).toBeNull();
    }
  });
});
