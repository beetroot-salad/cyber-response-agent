// The paged read's cursors belong to the key and params they were read under (#1598): each read keeps its own, a
// cursor is only ever sent with the read it was minted for, and a read returned to shows the pages it had, from the
// load's cache. The fake server's cursors name the read they were minted for and it refuses a cursor sent with another
// read's filters, as the API does (422). Run by `bun run test:dom`, in jsdom: see vite.config.mjs.
import { act, cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { onceQueryClient } from "./load";
import { ShellProvider, usePagedRead, type PagedKey, type PagedRead, type Shell } from "./provider";
import type { ReadKey, ReadParams, ReadResult } from "./types";

const ALERTS = "/api/tenants/{tenant_id}/alerts";
const LESSONS = "/api/tenants/{tenant_id}/lessons";
type Outcome = "malicious" | "benign" | "inconclusive" | "unresolved";

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

/** A server whose every read has three pages, `<what>-1` to `<what>-3`, the cursor of page n being `<key> <what> n`;
 * page 2 of the inconclusive alerts is a fault (the read throws), and of the unresolved ones an error answer. */
function server() {
  const sent: Sent[] = [];
  const read = <K extends ReadKey>(key: K, params: ReadParams<K>): Promise<ReadResult<K>> => {
    // trust: the fake answers only the two reads this file sends, and its bodies are their pages
    const query = (params as { query?: { outcome?: string; cursor?: string } }).query ?? {};
    const what = query.outcome ?? "all";
    const cursor = query.cursor ?? null;
    sent.push({ key, what, cursor });
    if (cursor !== null && !cursor.startsWith(`${key} ${what} `)) return Promise.resolve({ kind: "error" }); // 422
    const n = cursor === null ? 1 : Number(cursor.split(" ").at(-1));
    if (what === "inconclusive" && n === 2) return Promise.reject(new Error("a fault"));
    if (what === "unresolved" && n === 2) return Promise.resolve({ kind: "error" });
    const body = { items: [alert(`${what}-${n}`)], next_cursor: n < 3 ? `${key} ${what} ${n + 1}` : null };
    // trust: the body is a page of the read's items (an alert's, which page 1 of the lessons read is never checked for)
    return Promise.resolve({ kind: "ok", body } as ReadResult<K>);
  };
  const shell: Shell = {
    read,
    queryClient: onceQueryClient(),
    me: null,
    pathname: "/",
    shape: null,
    query: { get: () => null, getAll: () => [] },
    actions: { retry: () => undefined, signOut: () => undefined, acceptInvitation: () => Promise.reject(new Error()) },
  };
  return { sent, shell };
}

/** The cursors of the entries in `shell`'s query cache that were minted for another read than the entry's own. */
function strayCursors(shell: Shell): string[] {
  return shell.queryClient
    .getQueryCache()
    .getAll()
    .flatMap((query) => {
      // trust: every entry is a read's `[key, params]`, as the hook keys them
      const [key, params] = query.queryKey as [string, { query?: { outcome?: string; cursor?: string } }];
      const cursor = params.query?.cursor;
      return cursor === undefined || cursor.startsWith(`${key} ${params.query?.outcome ?? "all"} `) ? [] : [cursor];
    });
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
  return { sent, shell, now, ids, redraw, more };
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

/** Draw `of` again and wait for its rows to be `rows`. */
async function shown(probe: ReturnType<typeof drawn>, of: Read, rows: string[]) {
  probe.redraw(of);
  await waitFor(() => {
    expect(probe.ids()).toEqual(rows);
  });
}

/** Press `press` (drawn earlier) and let anything it sends be answered. */
async function pressed(press: (() => void) | null) {
  if (press === null) throw new Error("no Load more to press");
  act(press);
  await new Promise((settled) => setTimeout(settled, 50));
}

describe("usePagedRead keeps each read's cursors to that read", () => {
  it("new params after one Load more read their own page 1, with no old cursor, and page on by their own", async () => {
    const probe = await twoPagesLoaded();
    const mark = probe.sent.length;
    await shown(probe, { key: ALERTS, params: alerts("benign") }, ["benign-1"]);
    expect(probe.sent.slice(mark)).toEqual([{ key: ALERTS, what: "benign", cursor: null }]);
    expect(probe.now().later).toBeNull();
    await probe.more();
    expect(probe.ids()).toEqual(["benign-1", "benign-2"]);
    expect(probe.sent.slice(mark)).toEqual([
      { key: ALERTS, what: "benign", cursor: null },
      { key: ALERTS, what: "benign", cursor: `${ALERTS} benign 2` },
    ]);
    expect(strayCursors(probe.shell)).toEqual([]);
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

  it("returning to the first params shows the pages they had and sends nothing", async () => {
    const probe = await twoPagesLoaded();
    await shown(probe, { key: ALERTS, params: alerts("benign") }, ["benign-1"]);
    const mark = probe.sent.length;
    await shown(probe, { key: ALERTS, params: alerts("malicious") }, ["malicious-1", "malicious-2"]);
    await new Promise((settled) => setTimeout(settled, 50)); // whatever the return would send
    expect(probe.sent.slice(mark)).toEqual([]);
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

describe("usePagedRead's Load more reads the next page of the read it is pressed in", () => {
  it("a Load more drawn before leaving a read, pressed after returning, reads that read's next page", async () => {
    const probe = await twoPagesLoaded();
    const stale = probe.now().more; // holds the cursor of malicious page 3
    await shown(probe, { key: ALERTS, params: alerts("benign") }, ["benign-1"]);
    await shown(probe, { key: ALERTS, params: alerts("malicious") }, ["malicious-1", "malicious-2"]);
    const mark = probe.sent.length;
    await pressed(stale);
    await waitFor(() => {
      expect(probe.ids()).toEqual(["malicious-1", "malicious-2", "malicious-3"]);
    });
    expect(probe.sent.slice(mark)).toEqual([{ key: ALERTS, what: "malicious", cursor: `${ALERTS} malicious 3` }]);
  });

  it("a Load more drawn at page 1 and pressed after pages 2 and 3 loaded changes nothing", async () => {
    const probe = drawn({ key: ALERTS, params: alerts("malicious") });
    await waitFor(() => {
      expect(probe.now().more).not.toBeNull();
    });
    const early = probe.now().more;
    await probe.more();
    await probe.more();
    expect(probe.ids()).toEqual(["malicious-1", "malicious-2", "malicious-3"]);
    const mark = probe.sent.length;
    await pressed(early);
    expect(probe.sent.slice(mark)).toEqual([]);
    expect(probe.ids()).toEqual(["malicious-1", "malicious-2", "malicious-3"]);
  });
});

/** The params whose page 2 fails, by how it fails. */
const FAILING = { "a fault": alerts("inconclusive"), "an error answer": alerts("unresolved") };

/** Drawn for `params`, with their page 2 pressed for and failed; the press. */
async function failedAtPage2(params: ReadParams<typeof ALERTS>) {
  const probe = drawn({ key: ALERTS, params });
  await waitFor(() => {
    expect(probe.now().more).not.toBeNull();
  });
  const press = probe.now().more;
  await pressed(press);
  await waitFor(() => {
    expect(probe.now().later).toBe("failed");
  });
  return { probe, press };
}

// #1581 "Shell, paged read": a failed later page stays failed for the load (no retry, #1540's once-per-load rule).
describe.each(Object.entries(FAILING))(
  "usePagedRead keeps a later page failed by %s failed for the load",
  (_, params) => {
    it("a Load more drawn before the page failed and pressed after does not read anything", async () => {
      const { probe, press } = await failedAtPage2(params);
      const mark = probe.sent.length;
      await pressed(press);
      expect(probe.sent.slice(mark)).toEqual([]);
      expect(probe.now().later).toBe("failed");
      expect(probe.now().more).toBeNull();
    });

    it("leaving its read and returning reads nothing and shows the page failed", async () => {
      const { probe } = await failedAtPage2(params);
      const what = params.query?.outcome ?? "";
      await shown(probe, { key: ALERTS, params: alerts("benign") }, ["benign-1"]);
      const mark = probe.sent.length;
      await shown(probe, { key: ALERTS, params }, [`${what}-1`]);
      await new Promise((settled) => setTimeout(settled, 50)); // whatever the return would send
      expect(probe.sent.slice(mark)).toEqual([]);
      expect(probe.now().later).toBe("failed");
      expect(probe.now().more).toBeNull();
    });
  },
);
