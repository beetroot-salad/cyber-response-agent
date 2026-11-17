// The load (B1's owner, Am-5, Am-6): two 401s of one load make one navigation; a 401 to a superseded load does nothing.
// The effects are the load's only way out. Each appends its name to one ordered log, and every case asserts the whole
// log, so an extra `record`, `assign` or `replace` fails any case. Reads go through `load.client.read(key, params)`
// directly (Am-6); a case settles by awaiting the reads' promises or `vi.waitFor`, never by assuming when a call happens.
import { describe, expect, it, vi } from "vitest";
import { makeLoad } from "./load";

/** The investigation read's OpenAPI path key, as the generated types spell it. */
const KEY = "/api/tenants/{tenant_id}/investigations/{investigation_id}";
/** That operation's parameters (`paths[KEY]["get"]["parameters"]`); the reads of a case differ only by the id. */
const params = (investigation_id: string) => ({ path: { tenant_id: "t", investigation_id } });

function unauthorized(): Response {
  return new Response("{}", { status: 401, headers: { "Content-Type": "application/json" } });
}

/** A load whose `fetch` effect holds each answer until the case releases it with a 401. */
function loadWithHeldAnswers() {
  const log: string[] = [];
  const held: Array<(response: Response) => void> = [];
  const effects = {
    fetch: () => {
      log.push("fetch");
      return new Promise<Response>((resolve) => held.push(resolve));
    },
    record: () => {
      log.push("record");
      return true;
    },
    assign: () => {
      log.push("assign");
    },
    replace: () => {
      log.push("replace");
    },
  };
  const load = makeLoad({ taken: { status: "none" }, byHistory: false, target: "/home", effects });
  const answerAll = () => held.forEach((answer) => answer(unauthorized()));
  return { load, log, held, answerAll };
}

describe("a load's reads", () => {
  it("two reads of one load both answered 401 make exactly one record and one sign-in navigation", async () => {
    const { load, log, held, answerAll } = loadWithHeldAnswers();
    const reads = Promise.all([load.client.read(KEY, params("i")), load.client.read(KEY, params("j"))]);
    await vi.waitFor(() => expect(held).toHaveLength(2)); // both answers outstanding, so both are "answered 401"
    answerAll();
    const results = await reads;
    expect(results.map((r) => r.kind)).toEqual(["gone", "gone"]);
    // One record then one navigation (point 2); the second 401 is answered to a leaving load, which is gone whatever
    // the answer (point 4), so B1's policy does not run for it: no second record, no `replace`.
    expect(log).toEqual(["fetch", "fetch", "record", "assign"]);
  });

  it("a 401 answered after the load is superseded makes no record or navigation, and the read is gone", async () => {
    const { load, log, held, answerAll } = loadWithHeldAnswers();
    const pending = load.client.read(KEY, params("i"));
    await vi.waitFor(() => expect(held).toHaveLength(1));
    load.supersede();
    answerAll();
    expect((await pending).kind).toBe("gone");
    expect(log).toEqual(["fetch"]);
  });

  it("a 401 to a read issued after the load is superseded is gone and does nothing", async () => {
    const { load, log, held, answerAll } = loadWithHeldAnswers();
    load.supersede();
    const pending = load.client.read(KEY, params("i"));
    // Whether a superseded load still sends the request is the client's choice (Am-5 point 1 and 4 leave it open);
    // either way it makes no record and no navigation.
    await vi.waitFor(() => expect(held.length <= 1).toBe(true));
    answerAll();
    expect((await pending).kind).toBe("gone");
    expect([[], ["fetch"]]).toContainEqual(log);
  });
});
