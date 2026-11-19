// Accepting an invitation, the shell's second write (alert list design O11, Flows "Shell, accept"): success is a full
// load of the accepted tenant's alerts address by `assign` (never `replace`: Back returns to Home), a 401 is the
// shell's sign-in round trip back to /home, and only a 404 (`gone`) and any other failure (`failed`) come back to the
// caller. Each case asserts the whole effect log, as load.test.ts does.
// FORCED CHOICE: the load-level entry is `load.client.acceptInvitation(id)` beside `signOut`; the design names only the
// action a screen holds (`useActions().acceptInvitation`). Its promise value for success and 401 is unspecified, so
// those cases assert only that it is not `gone` or `failed`.
import { describe, expect, it } from "vitest";
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

function accepting(answer: (request: Request) => Promise<Response>) {
  const log: string[] = [];
  const requests: Request[] = [];
  const assigned: string[] = [];
  const load = makeLoad({
    taken: { status: "none" },
    byHistory: false,
    target: "/home",
    origin: ORIGIN,
    effects: {
      fetch: (request) => {
        log.push("fetch");
        requests.push(request);
        return answer(request);
      },
      record: () => {
        log.push("record");
        return true;
      },
      assign: (url) => {
        log.push("assign");
        assigned.push(url);
      },
      replace: () => {
        log.push("replace");
      },
    },
  });
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
  return { load, log, requests, assigned, accept, settled };
}

const kindOf = (result: unknown): unknown =>
  typeof result === "object" && result !== null && "kind" in result ? result.kind : result;

describe("accepting an invitation", () => {
  it("POSTs the invitation's accept route once and, on success, assigns the accepted tenant's alerts address", async () => {
    const { log, requests, assigned, accept, settled } = accepting(() =>
      Promise.resolve(json(200, { tenant_id: TENANT })),
    );
    const result = await settled(accept());
    expect(requests.map((r) => [r.method, r.url])).toEqual([
      ["POST", `${ORIGIN}/api/auth/invitations/${INVITATION}/accept`],
    ]);
    expect(log).toEqual(["fetch", "assign"]);
    expect(assigned.map((url) => new URL(url, ORIGIN).href)).toEqual([`${ORIGIN}/t/${TENANT}/alerts`]);
    expect([kindOf(result)]).not.toContainEqual("gone");
    expect([kindOf(result)]).not.toContainEqual("failed");
  });

  it("on a 401 makes the shell's one sign-in round trip back to /home, and tells the caller neither gone nor failed", async () => {
    const { log, assigned, accept, settled } = accepting(() => Promise.resolve(json(401, { detail: "no session" })));
    const result = await settled(accept());
    expect(log).toEqual(["fetch", "record", "assign"]);
    const [login] = assigned.map((url) => new URL(url, ORIGIN));
    expect([login?.pathname, login?.searchParams.get("return")]).toEqual(["/api/auth/login", "/home"]);
    expect([kindOf(result)]).not.toContainEqual("gone");
    expect([kindOf(result)]).not.toContainEqual("failed");
  });

  it("answers gone for a 404, the invitation no longer open, and navigates nowhere", async () => {
    const { log, accept, settled } = accepting(() => Promise.resolve(json(404, { detail: "no invitation" })));
    expect(await settled(accept())).toEqual({ kind: "gone" });
    expect(log).toEqual(["fetch"]);
  });

  it.each([400, 403, 409, 422, 429, 500, 502, 503])(
    "answers failed for a %i, and navigates nowhere",
    async (status) => {
      const { log, accept, settled } = accepting(() => Promise.resolve(json(status, { detail: "x" })));
      expect(await settled(accept())).toEqual({ kind: "failed" });
      expect(log).toEqual(["fetch"]);
    },
  );

  it("answers failed when no answer comes, or a success is not JSON, and sends nothing a second time", async () => {
    const down = accepting(() => Promise.reject(new TypeError("Failed to fetch")));
    expect(await down.settled(down.accept())).toEqual({ kind: "failed" });
    expect(down.log).toEqual(["fetch"]);
    const html = accepting(() => Promise.resolve(new Response("<html>", { status: 200 })));
    expect(await html.settled(html.accept())).toEqual({ kind: "failed" });
    expect(html.log).toEqual(["fetch"]);
  });

  it("does nothing once the load is superseded: no navigation of a gone load", async () => {
    const held: ((response: Response) => void)[] = [];
    const { load, log, accept, settled } = accepting(() => new Promise<Response>((resolve) => held.push(resolve)));
    const call = accept();
    load.supersede();
    held.forEach((answer) => answer(json(200, { tenant_id: TENANT })));
    await settled(call);
    expect(log).toEqual(["fetch"]);
  });
});
