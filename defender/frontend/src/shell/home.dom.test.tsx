// Home, the top bar and the repository screen (home redesign), drawn in jsdom over a fake shell: each tenant's cards,
// the bar's links for the tenant in view, and the repository address handing the served page to the shell, or saying
// there is none. Run by `bun run test:dom`.
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it } from "vitest";
import { Home } from "../screens/Home";
import { Repo } from "../screens/Repo";
import { onceQueryClient } from "./load";
import { ShellProvider, type Shell } from "./provider";
import type { Person, ReadKey, ReadResult } from "./types";

const A = "0b6f1c1e-3c55-4a4e-9a51-1083000000aa";
const B = "0b6f1c1e-3c55-4a4e-9a51-1083000000bb";

afterEach(cleanup);

function person(tenants: readonly string[]): Person {
  return {
    kind: "person",
    user: { id: "u", email: "ann@a.example", display_name: "Ann" },
    tenants: tenants.map((tenant_id) => ({ tenant_id })),
    administrator: false,
    invitations: [],
  };
}

/** `node` drawn at `pathname` over a shell whose one read answers `answer`; the repository addresses it was asked to
 * open, and what it answers them. */
function drawn(
  node: ReactNode,
  { me, pathname, answer, allows = true }: { me: Person; pathname: string; answer?: unknown; allows?: boolean },
) {
  const opened: string[] = [];
  const shell: Shell = {
    // trust: the one read these screens send is the repository read, and `answer` is its result
    read: <K extends ReadKey>() => Promise.resolve(answer as ReadResult<K>),
    queryClient: onceQueryClient(),
    me,
    pathname,
    shape: pathname === "/home" ? "home" : "repo",
    query: { get: () => null, getAll: () => [] },
    actions: {
      retry: () => undefined,
      signOut: () => undefined,
      acceptInvitation: () => Promise.reject(new Error()),
      mayOpenRepository: () => allows,
      openRepository: (address) => {
        opened.push(address);
      },
    },
  };
  render(<ShellProvider shell={shell}>{node}</ShellProvider>);
  return opened;
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

describe("Home", () => {
  it("with one tenant, links its alerts and its repository address, in the bar and on the cards", () => {
    drawn(<Home />, { me: person([A]), pathname: "/home" });
    expect(nav()).toEqual([
      ["Home", "/home", "page"],
      ["Alerts", `/t/${A}/alerts`, null],
      ["Knowledge repo", `/t/${A}/repo`, null],
    ]);
    const main = within(screen.getByRole("main"));
    expect(main.getByRole("link", { name: "Open alerts" }).getAttribute("href")).toBe(`/t/${A}/alerts`);
    expect(main.getByRole("link", { name: /Open repo/ }).getAttribute("href")).toBe(`/t/${A}/repo`);
    expect(main.queryByRole("heading", { level: 2 })).toBeNull();
  });

  it("with several tenants, puts each tenant's cards under its id, and the bar has only Home", () => {
    drawn(<Home />, { me: person([A, B]), pathname: "/home" });
    expect(nav()).toEqual([["Home", "/home", "page"]]);
    expect(screen.getAllByRole("heading", { level: 2 }).map((heading) => heading.textContent)).toEqual([A, B]);
    const repos = screen.getAllByRole("link", { name: /Open repo/ }).map((link) => link.getAttribute("href"));
    expect(repos).toEqual([`/t/${A}/repo`, `/t/${B}/repo`]);
  });
});

describe("the repository address", () => {
  const repo = `/t/${A}/repo`;

  it("hands the served page to the shell to open, once, and says it is opening", async () => {
    const opened = drawn(<Repo />, {
      me: person([A]),
      pathname: repo,
      answer: { kind: "ok", body: { repo_url: "https://forge.example/tenants/a" } },
    });
    await waitFor(() => {
      expect(opened).toEqual(["https://forge.example/tenants/a"]);
    });
    expect(screen.getByText("Opening the repository…")).toBeTruthy();
  });

  it.each([
    ["none is recorded", { kind: "ok", body: { repo_url: null } }, true],
    ["the shell refuses the page", { kind: "ok", body: { repo_url: "ssh://forge.example/a" } }, false],
  ])("when %s, says there is no repository to link to", async (_, answer, allows) => {
    const opened = drawn(<Repo />, { me: person([A]), pathname: repo, answer, allows });
    await screen.findByText("This tenant has no repository Sluice can link to.");
    expect(opened).toEqual([]);
  });

  it("a read the person may not make is not available, and opens nothing", async () => {
    const opened = drawn(<Repo />, { me: person([B]), pathname: repo, answer: { kind: "not-available" } });
    await screen.findByText("There is nothing at this address.");
    expect(opened).toEqual([]);
  });
});
