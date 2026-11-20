// @vitest-environment jsdom
// The paged read's cursors belong to the key and params they were read under (#1598): when either changes, the pages
// loaded under the old ones are dropped, and the new read starts again at its page 1. The fake server's cursors name
// the read they were minted for and it refuses a cursor sent with another read's filters, as the API does (422).
import { QueryClient } from "@tanstack/react-query";
import { act, cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ShellProvider, usePagedRead, type PagedKey, type PagedRead, type Shell } from "./provider";
import type { ReadKey, ReadParams, ReadResult } from "./types";

const ALERTS = "/api/tenants/{tenant_id}/alerts";
const LESSONS = "/api/tenants/{tenant_id}/lessons";
type Outcome = "malicious" | "benign";

/** The alert list's params under `outcome`. */
const alerts = (outcome: Outcome): ReadParams<typeof ALERTS> => ({ path: { tenant_id: "t" }, query: { outcome } });
/** Every alert, and every lesson: the same params under two keys. */
const everything = { path: { tenant_id: "t" } };

/** One alert of the fake server's, titled `name`. */
function alert(name: string) {
  const at = "2026-01-01T00:00:00Z";
  return {
    alert_id: "00000000-0000-4000-8000-000000000000",
    changed_at: at,
    description: null,
    fired_at: at,
    latest_status: null,
    outcome: null,
    received_at: at,
    title: name,
    vendor: "v",
    vendor_ticket_id: name,
  };
}

interface Sent {
  readonly key: string;
  readonly what: string;
  readonly cursor: string | null;
}

/** A server whose every read has two pages, `<what>-1` and `<what>-2`, page 1 giving the cursor `<key> <what>`. */
function server() {
  const sent: Sent[] = [];
  const read = <K extends ReadKey>(key: K, params: ReadParams<K>): Promise<ReadResult<K>> => {
    // trust: the fake answers only the two reads this file sends, and its bodies are their pages
    const query = (params as { query?: { outcome?: string; cursor?: string } }).query ?? {};
    const what = query.outcome ?? "all";
    const cursor = query.cursor ?? null;
    sent.push({ key, what, cursor });
    if (cursor !== null && cursor !== `${key} ${what}`) return Promise.resolve({ kind: "error" }); // the filters changed
    const body =
      cursor === null
        ? { items: [alert(`${what}-1`)], next_cursor: `${key} ${what}` }
        : { items: [alert(`${what}-2`)], next_cursor: null };
    // trust: the body is a page of the read's items (an alert's, which page 1 of the lessons read is never checked for)
    return Promise.resolve({ kind: "ok", body } as ReadResult<K>);
  };
  const shell: Shell = {
    read,
    queryClient: new QueryClient({ defaultOptions: { queries: { retry: false } } }),
    me: null,
    pathname: "/",
    shape: null,
    query: { get: () => null, getAll: () => [] },
    actions: { retry: () => undefined, signOut: () => undefined, acceptInvitation: () => Promise.reject(new Error()) },
  };
  return { sent, shell };
}

type Read =
  | { readonly key: typeof ALERTS; readonly params: ReadParams<typeof ALERTS> }
  | {
      readonly key: typeof LESSONS;
      readonly params: ReadParams<typeof LESSONS>;
    };

/** Draws the hook for `of` and hands what it answers to `seen`. */
function Probe({ of, seen }: { readonly of: Read; readonly seen: (read: PagedRead<PagedKey>) => void }) {
  seen(usePagedRead<PagedKey>(of.key, of.params));
  return null;
}

/** The hook drawn for `start`, and a way to draw it again for another read. */
function drawn(start: Read) {
  const { sent, shell } = server();
  let last: PagedRead<PagedKey> | null = null;
  const seen = (read: PagedRead<PagedKey>) => {
    last = read;
  };
  const view = render(
    <ShellProvider shell={shell}>
      <Probe of={start} seen={seen} />
    </ShellProvider>,
  );
  const now = () => {
    if (last === null) throw new Error("the probe was not drawn");
    return last;
  };
  // trust: every item this server answers is an alert, titled with its page's name
  const ids = () => now().items.map((item) => (item as { title: string }).title);
  const redraw = (of: Read) => {
    view.rerender(
      <ShellProvider shell={shell}>
        <Probe of={of} seen={seen} />
      </ShellProvider>,
    );
  };
  const more = async () => {
    const press = now().more;
    if (press === null) throw new Error("no Load more");
    act(press);
    await waitFor(() => {
      expect(now().later).toBeNull();
    });
  };
  return { sent, now, ids, redraw, more };
}

/** Drawn for the malicious alerts, with their two pages loaded by one Load more. */
async function twoPagesLoaded(params: ReadParams<typeof ALERTS> = alerts("malicious")) {
  const probe = drawn({ key: ALERTS, params });
  const what = params.query?.outcome ?? "all";
  await waitFor(() => {
    expect(probe.ids()).toEqual([`${what}-1`]);
  });
  await probe.more();
  expect(probe.ids()).toEqual([`${what}-1`, `${what}-2`]);
  return probe;
}

afterEach(cleanup);

describe("usePagedRead drops the pages of the read it was drawn for before", () => {
  it("new params after one Load more read their own page 1, with no old cursor, and page on by their own", async () => {
    const probe = await twoPagesLoaded();
    const mark = probe.sent.length;
    probe.redraw({ key: ALERTS, params: alerts("benign") });
    await waitFor(() => {
      expect(probe.ids()).toEqual(["benign-1"]);
    });
    expect(probe.sent.slice(mark)).toEqual([{ key: ALERTS, what: "benign", cursor: null }]);
    expect(probe.now().later).toBeNull();
    await probe.more();
    expect(probe.ids()).toEqual(["benign-1", "benign-2"]);
    expect(probe.sent.slice(mark)).toEqual([
      { key: ALERTS, what: "benign", cursor: null },
      { key: ALERTS, what: "benign", cursor: `${ALERTS} benign` },
    ]);
  });

  it("returning to the first params shows only their page 1 again", async () => {
    const probe = await twoPagesLoaded();
    probe.redraw({ key: ALERTS, params: alerts("benign") });
    await waitFor(() => {
      expect(probe.ids()).toEqual(["benign-1"]);
    });
    probe.redraw({ key: ALERTS, params: alerts("malicious") });
    await waitFor(() => {
      expect(probe.ids()).toEqual(["malicious-1"]);
    });
    expect(probe.now().later).toBeNull();
    expect(probe.now().more).not.toBeNull();
  });

  it("a new key with the same params after one Load more reads its own page 1, with no old cursor", async () => {
    const probe = await twoPagesLoaded(everything);
    const mark = probe.sent.length;
    probe.redraw({ key: LESSONS, params: everything });
    await waitFor(() => {
      expect(probe.sent.slice(mark)).toEqual([{ key: LESSONS, what: "all", cursor: null }]);
    });
    await waitFor(() => {
      expect(probe.ids()).toEqual(["all-1"]);
    });
    expect(probe.now().later).toBeNull();
  });
});

describe("usePagedRead keeps pages only for the read it is drawn for", () => {
  it("a Load more drawn for the old params and pressed after the change sends nothing", async () => {
    const probe = drawn({ key: ALERTS, params: alerts("malicious") });
    await waitFor(() => {
      expect(probe.now().more).not.toBeNull();
    });
    const stale = probe.now().more;
    probe.redraw({ key: ALERTS, params: alerts("benign") });
    await waitFor(() => {
      expect(probe.ids()).toEqual(["benign-1"]);
    });
    const mark = probe.sent.length;
    if (stale === null) throw new Error("no Load more under the old params");
    act(stale);
    await new Promise((settled) => setTimeout(settled, 50));
    expect(probe.sent.slice(mark)).toEqual([]);
    expect(probe.ids()).toEqual(["benign-1"]);
    expect(probe.now().later).toBeNull();
  });

  it("the same params in a new object keep the pages loaded", async () => {
    const probe = await twoPagesLoaded();
    const mark = probe.sent.length;
    probe.redraw({ key: ALERTS, params: alerts("malicious") });
    expect(probe.ids()).toEqual(["malicious-1", "malicious-2"]);
    expect(probe.sent.slice(mark)).toEqual([]);
  });
});
