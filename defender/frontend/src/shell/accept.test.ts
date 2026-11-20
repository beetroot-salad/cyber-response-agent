// Accepting an invitation, the shell's second write (alert list design O11, Flows "Shell, accept"): success is a full
// load of the accepted tenant's alerts address by `assign` (never `replace`: Back returns to Home), a 401 is the
// shell's sign-in round trip back to /home, and the caller gets the shell's Outcome shape (r3.1, like signOut's
// SignOutResult): `{kind:"left"}` after either navigation, `{kind:"not-open"}` for a 404, `{kind:"refused"}` for
// any other 4xx (r3.3: worded "You can't accept this invitation."), `{kind:"error"}` for a 5xx, no answer or a
// non-JSON success, and `{kind:"gone"}` when the load was superseded. Each case asserts the whole effect log, as
// load.test.ts does.
// FORCED CHOICE: the load-level entry is `load.client.acceptInvitation(id)` beside `signOut`; the design names only the
// action a screen holds (`useActions().acceptInvitation`).
import { describe, expect, it } from "vitest";
import { decideUnauthorized, type Decision, type Taken } from "./decision";
import { makeLoad } from "./load";

const INVITATION = "4f2a8c1e-91b7-4d33-a0c5-6e1f7b2d9a10";
const TENANT = "0b6f1c1e-3c55-4a4e-9a51-1083000000bb";
const ORIGIN = "http://app.test";

interface Accepting {
  readonly acceptInvitation: (id: string) => Promise<unknown>;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function accepting(
  answer: (request: Request) => Promise<Response>,
  start: { readonly taken: Taken; readonly byHistory: boolean } = { taken: { status: "none" }, byHistory: false },
) {
  const log: string[] = [];
  /** Every effect with what it was given, as one line each, in order. */
  const effects: string[] = [];
  const requests: Request[] = [];
  const assigned: string[] = [];
  const load = makeLoad({
    taken: start.taken,
    byHistory: start.byHistory,
    target: "/home",
    origin: ORIGIN,
    effects: {
      fetch: (request) => {
        log.push("fetch");
        effects.push("fetch");
        requests.push(request);
        return answer(request);
      },
      record: (target, again) => {
        log.push("record");
        effects.push(`record ${String(target)} ${String(again)}`);
        return true;
      },
      assign: (url) => {
        log.push("assign");
        effects.push(`assign ${url}`);
        assigned.push(url);
      },
      replace: (url) => {
        log.push("replace");
        effects.push(`replace ${url}`);
      },
    },
  });
  // trust: the test reaches the shell's accept call through the shape it promises, before the types are generated
  const accept = (): Promise<unknown> => (load.client as unknown as Accepting).acceptInvitation(INVITATION);
  /** What the call came to, after every effect it schedules has run: its value, or "pending" when it never resolved. */
  const settled = async (call: Promise<unknown>): Promise<unknown> => {
    const result = await Promise.race([
      call,
      new Promise<string>((resolve) => setTimeout(() => resolve("pending"), 50)),
    ]);
    await new Promise((resolve) => setTimeout(resolve, 0));
    return result;
  };
  return { load, log, effects, requests, assigned, accept, settled };
}

describe("accepting an invitation", () => {
  it("POSTs the invitation's accept route once and, on success, assigns the accepted tenant's alerts address", async () => {
    const { log, requests, assigned, accept, settled } = accepting(() =>
      Promise.resolve(json(200, { tenant_id: TENANT })),
    );
    const result = await settled(accept());
    expect(requests.map((r) => [r.method, r.url])).toEqual([
      ["POST", `${ORIGIN}/api/invitations/${INVITATION}/accept`],
    ]);
    expect(log).toEqual(["fetch", "assign"]);
    expect(assigned.map((url) => new URL(url, ORIGIN).href)).toEqual([`${ORIGIN}/t/${TENANT}/alerts`]);
    expect(result).toEqual({ kind: "left" });
  });

  it("on a 401 makes the shell's one sign-in round trip back to /home, and tells the caller it left", async () => {
    const { log, assigned, accept, settled } = accepting(() => Promise.resolve(json(401, { detail: "no session" })));
    const result = await settled(accept());
    expect(log).toEqual(["fetch", "record", "assign"]);
    const [login] = assigned.map((url) => new URL(url, ORIGIN));
    expect([login?.pathname, login?.searchParams.get("return")]).toEqual(["/api/auth/login", "/home"]);
    expect(result).toEqual({ kind: "left" });
  });

  it("answers not-open for a 404, the invitation no longer open, and navigates nowhere", async () => {
    const { log, accept, settled } = accepting(() => Promise.resolve(json(404, { detail: "no invitation" })));
    expect(await settled(accept())).toEqual({ kind: "not-open" });
    expect(log).toEqual(["fetch"]);
  });

  it.each([400, 403, 409, 422, 429])(
    "answers refused for a %i (r3.3: any 4xx but 401 and 404), and navigates nowhere",
    async (status) => {
      const { log, accept, settled } = accepting(() => Promise.resolve(json(status, { detail: "x" })));
      expect(await settled(accept())).toEqual({ kind: "refused" });
      expect(log).toEqual(["fetch"]);
    },
  );

  it.each([500, 502, 503])("answers error for a %i, and navigates nowhere", async (status) => {
    const { log, accept, settled } = accepting(() => Promise.resolve(json(status, { detail: "x" })));
    expect(await settled(accept())).toEqual({ kind: "error" });
    expect(log).toEqual(["fetch"]);
  });

  it("answers error when no answer comes, or a success is not JSON, and sends nothing a second time", async () => {
    const down = accepting(() => Promise.reject(new TypeError("Failed to fetch")));
    expect(await down.settled(down.accept())).toEqual({ kind: "error" });
    expect(down.log).toEqual(["fetch"]);
    const html = accepting(() => Promise.resolve(new Response("<html>", { status: 200 })));
    expect(await html.settled(html.accept())).toEqual({ kind: "error" });
    expect(html.log).toEqual(["fetch"]);
  });

  it("does nothing once the load is superseded: no navigation of a gone load", async () => {
    const held: ((response: Response) => void)[] = [];
    const { load, log, accept, settled } = accepting(() => new Promise<Response>((resolve) => held.push(resolve)));
    const call = accept();
    load.supersede();
    held.forEach((answer) => answer(json(200, { tenant_id: TENANT })));
    expect(await settled(call)).toEqual({ kind: "gone" });
    expect(log).toEqual(["fetch"]);
  });
});

// Accept's wiring over every state its choices depend on (#1581 repair, G6): which 401 policy it sends through, and
// that it leaves only through the load's one exit. Both are invisible to a fresh load with no attempt record, where
// every wrong choice acts as the right one, so the table crosses the attempt record x how the load was reached x what
// the load has already done.
const TAKENS: readonly (readonly [string, Taken])[] = [
  ["none", { status: "none" }],
  ["found, first", { status: "found", again: false }],
  ["found, again", { status: "found", again: true }],
  ["unavailable", { status: "unavailable" }],
];

/** What the load has already done before Accept is pressed. */
type Before = "fresh" | "accepted" | "signed-out" | "sign-in started by me" | "superseded";
const BEFORES: readonly Before[] = ["fresh", "accepted", "signed-out", "sign-in started by me", "superseded"];

/** The answer for each call the table's loads make: Accept answers from `accepts` in turn, sign-out is a 204, `/api/me`
 * a 401. */
function answers(accepts: Response[]): (request: Request) => Promise<Response> {
  return (request) => {
    const path = new URL(request.url).pathname;
    if (path === "/api/auth/logout") return Promise.resolve(new Response(null, { status: 204 }));
    if (path === "/api/me") return Promise.resolve(json(401, { detail: "no session" }));
    const next = accepts.shift();
    if (next === undefined) throw new Error("premise: Accept was sent more often than the row answers");
    return Promise.resolve(next);
  };
}

interface Row {
  readonly label: string;
  readonly taken: Taken;
  readonly byHistory: boolean;
  readonly before: Before;
}

const ROWS: readonly Row[] = TAKENS.flatMap(([label, taken]) =>
  [false, true].flatMap((byHistory) => BEFORES.map((before) => ({ label, taken, byHistory, before }))),
);

const NO_SESSION = (): Response => json(401, { detail: "no session" });

/** What Accept does on a load in state `before`, and a `later` read does on a twin of the same load (the oracle). */
async function acceptAfter({ taken, byHistory, before }: Row) {
  const first = before === "accepted" ? json(200, { tenant_id: TENANT }) : NO_SESSION();
  const { load, effects, accept, settled } = accepting(answers([first, NO_SESSION()]), { taken, byHistory });
  if (before === "accepted") expect(await settled(accept())).toEqual({ kind: "left" });
  if (before === "signed-out") await settled(load.client.signOut());
  if (before === "sign-in started by me") await settled(load.client.me());
  if (before === "superseded") load.supersede();
  const mark = effects.length;
  const result = await settled(accept());
  const twin = accepting(answers([]), { taken, byHistory });
  await twin.settled(twin.load.client.read("/api/me", {}));
  return { result, sent: effects.slice(mark), twin: twin.effects };
}

describe("accepting over every attempt record, way of arriving and earlier state of the load", () => {
  it("covers every combination, and each 401 decision of the shell", () => {
    expect(new Set(ROWS.map((r) => `${r.label}/${String(r.byHistory)}/${r.before}`)).size).toBe(
      TAKENS.length * 2 * BEFORES.length,
    );
    const decisions = new Set<string>();
    for (const { taken, byHistory } of ROWS) {
      const decision = decideUnauthorized({ taken, byHistory, source: "later" });
      decisions.add(decision.kind === "failed" ? decision.reason : `sign-in ${String(decision.again)}`);
    }
    // premise: the 401 table reaches each outcome the shell has for a later call, so no wrong policy hides
    expect([...decisions].sort()).toEqual(["session-refused", "sign-in false", "sign-in true", "storage-unavailable"]);
  });

  it.each(ROWS.filter((row) => row.before !== "fresh"))(
    "taken $label, byHistory=$byHistory, load already $before: sends nothing and navigates nowhere",
    async (row) => {
      const { result, sent } = await acceptAfter(row);
      expect(sent, "a load that is gone sends nothing and navigates nowhere").toEqual([]);
      // a load that already left answers `left` or `gone` (the design leaves which); a superseded one, `gone`
      if (row.before === "superseded") expect(result).toEqual({ kind: "gone" });
      else expect([{ kind: "left" }, { kind: "gone" }]).toContainEqual(result);
    },
  );

  it.each(ROWS.filter((row) => row.before === "fresh"))(
    "taken $label, byHistory=$byHistory: a 401 is answered as a later call's, by the shell's own decision",
    async (row) => {
      const { result, sent, twin } = await acceptAfter(row);
      expect(result).toEqual({ kind: "left" });
      expect(sent).toEqual(twin);
      const decision: Decision = decideUnauthorized({ taken: row.taken, byHistory: row.byHistory, source: "later" });
      const kinds = sent.map((effect) => effect.split(" ")[0]);
      if (decision.kind === "failed") {
        expect(kinds).toEqual(["fetch", "replace"]);
        expect(new URL(sent[1]?.split(" ")[1] ?? "", ORIGIN).searchParams.get("reason")).toBe(decision.reason);
      } else {
        expect(kinds).toEqual(["fetch", "record", "assign"]);
        expect(sent[1]).toBe(`record /home ${String(decision.again)}`);
      }
    },
  );
});
