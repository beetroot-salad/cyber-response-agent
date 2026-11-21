// Home and the top bar (home redesign), drawn in jsdom over a shell built as the real one builds `repos`: each tenant's
// cards, the bar's links for the tenant in view, and the repository link only for a page the shell's check kept. Run
// by `bun run test:dom`.
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Home } from "../screens/Home";
import { onceQueryClient } from "./load";
import { ShellProvider, type Shell } from "./provider";
import { repoAddress } from "./repo";
import type { Person } from "./types";

const A = "0b6f1c1e-3c55-4a4e-9a51-1083000000aa";
const B = "0b6f1c1e-3c55-4a4e-9a51-1083000000bb";
const APP = "http://localhost:3000";

afterEach(cleanup);

function person(tenants: Person["tenants"]): Person {
  return {
    kind: "person",
    user: { id: "u", email: "ann@a.example", display_name: "Ann" },
    tenants,
    administrator: false,
    invitations: [],
  };
}

/** Home drawn for `me`, its repository pages checked against the app's origin as the shell checks them. */
function home(me: Person) {
  const repos = new Map(
    me.tenants.flatMap(({ tenant_id, repo_url }) => {
      const checked = repoAddress(repo_url, APP);
      return checked === null ? [] : [[tenant_id, checked] as const];
    }),
  );
  const shell: Shell = {
    read: () => Promise.reject(new Error("Home reads nothing")),
    queryClient: onceQueryClient(),
    me,
    repos,
    pathname: "/home",
    shape: "home",
    query: { get: () => null, getAll: () => [] },
    actions: { retry: () => undefined, signOut: () => undefined, acceptInvitation: () => Promise.reject(new Error()) },
  };
  render(
    <ShellProvider shell={shell}>
      <Home />
    </ShellProvider>,
  );
}

/** The top bar's links: text, href, aria-current. */
function nav() {
  return within(screen.getByRole("navigation", { name: "Main" }))
    .getAllByRole("link")
    .map((link) => [
      link.textContent.replace("↗", "").trim(),
      link.getAttribute("href"),
      link.getAttribute("aria-current"),
    ]);
}

describe("Home with one tenant", () => {
  it("links the tenant's alerts and its repository, in the bar and on the cards", () => {
    home(person([{ tenant_id: A, repo_url: "http://forge.test/tenants/a" }]));
    expect(nav()).toEqual([
      ["Home", "/home", "page"],
      ["Alerts", `/t/${A}/alerts`, null],
      ["Knowledge repo", "http://forge.test/tenants/a", null],
    ]);
    const main = within(screen.getByRole("main"));
    expect(main.getByRole("link", { name: "Open alerts" }).getAttribute("href")).toBe(`/t/${A}/alerts`);
    expect(main.getByRole("link", { name: /Open repo/ }).getAttribute("href")).toBe("http://forge.test/tenants/a");
    expect(main.queryByRole("heading", { level: 2 })).toBeNull();
  });

  it.each([
    ["no wiring", null],
    ["a page on the app's own origin", `${APP}/api/me`],
  ])("with %s, says there is no repository and links none", (_, repo_url) => {
    home(person([{ tenant_id: A, repo_url }]));
    expect(nav().map(([text]) => text)).toEqual(["Home", "Alerts"]);
    expect(screen.queryByRole("link", { name: /Open repo/ })).toBeNull();
    expect(screen.getByText("This tenant has no knowledge repository yet.")).toBeTruthy();
  });
});

describe("Home with several tenants", () => {
  it("puts each tenant's cards under its id, and the bar has only Home", () => {
    home(
      person([
        { tenant_id: A, repo_url: "http://forge.test/tenants/a" },
        { tenant_id: B, repo_url: null },
      ]),
    );
    expect(nav()).toEqual([["Home", "/home", "page"]]);
    const headings = screen.getAllByRole("heading", { level: 2 }).map((heading) => heading.textContent);
    expect(headings).toEqual([A, B]);
    const alerts = screen.getAllByRole("link", { name: "Open alerts" }).map((link) => link.getAttribute("href"));
    expect(alerts).toEqual([`/t/${A}/alerts`, `/t/${B}/alerts`]);
    expect(screen.getAllByRole("link", { name: /Open repo/ })).toHaveLength(1);
  });
});
