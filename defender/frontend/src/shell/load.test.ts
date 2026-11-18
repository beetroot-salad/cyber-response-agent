// The load (B1's owner, Am-5, Am-6): two 401s of one load make one navigation; a 401 to a superseded load does nothing.
// The effects are the load's only way out. Each appends its name to one ordered log, and every case asserts the whole
// log, so an extra `record`, `assign` or `replace` fails any case. Reads go through `load.client.read(key, params)`
// directly (Am-6); one settling discipline (`loadWithHeldAnswers` and `settle`) serves every case, so none assumes when a call happens.
import { describe, expect, it } from "vitest";
import { makeLoad } from "./load";

/** The investigation read's OpenAPI path key, as the generated types spell it. */
const KEY = "/api/tenants/{tenant_id}/investigations/{investigation_id}";
/** That operation's parameters (`paths[KEY]["get"]["parameters"]`); the reads of a case differ only by the id. */
const params = (investigation_id: string) => ({ path: { tenant_id: "t", investigation_id } });

function unauthorized(): Response {
  return new Response("{}", { status: 401, headers: { "Content-Type": "application/json" } });
}

/**
 * The one settling discipline of this file. The injected `fetch` holds each request, and a responder answers whatever is
 * held every millisecond, so a client may send at any time (or never) and no case guesses when. `answerOnce` lets a case
 * decide when the held requests are answered (it is asked whenever some are held, with how many) and what it does at
 * that moment. Every case then ends with `settle`, once, before it asserts the whole log.
 */
function loadWithHeldAnswers(answerOnce: (held: number) => boolean = () => true) {
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
  const load = makeLoad({ taken: { status: "none" }, byHistory: false, target: "/home", origin: "http://app.test", effects });
  const responder = setInterval(() => {
    if (held.length > 0 && answerOnce(held.length)) held.splice(0).forEach((answer) => answer(unauthorized()));
  }, 1);
  /** Await the reads, then let a task pass so an effect scheduled a task late has happened; then stop answering. */
  const settle = async <T>(reads: Promise<T>): Promise<T> => {
    try {
      const result = await reads;
      await new Promise((resolve) => setTimeout(resolve, 0));
      return result;
    } finally {
      clearInterval(responder);
    }
  };
  return { load, log, settle };
}

describe("a load's reads", () => {
  it("two reads of one load both answered 401 make exactly one record and one sign-in navigation", async () => {
    // Both answers outstanding before either is answered, so both are "answered 401".
    const { load, log, settle } = loadWithHeldAnswers((held) => held === 2);
    const results = await settle(Promise.all([load.client.read(KEY, params("i")), load.client.read(KEY, params("j"))]));
    expect(results.map((r) => r.kind)).toEqual(["gone", "gone"]);
    // One record then one navigation (point 2); the second 401 is answered to a leaving load, which is gone whatever
    // the answer (point 4), so B1's policy does not run for it: no second record, no `replace`.
    expect(log).toEqual(["fetch", "fetch", "record", "assign"]);
  });

  it("a 401 answered after the load is superseded makes no record or navigation, and the read is gone", async () => {
    const { load, log, settle } = loadWithHeldAnswers(() => {
      load.supersede(); // the request is in flight: supersede, then answer it
      return true;
    });
    expect((await settle(load.client.read(KEY, params("i")))).kind).toBe("gone");
    expect(log).toEqual(["fetch"]);
  });

  it("a 401 to a read issued after the load is superseded is gone and does nothing", async () => {
    const { load, log, settle } = loadWithHeldAnswers();
    load.supersede();
    // Whether a superseded load still sends the request, or when, is the client's choice (Am-5 points 1 and 4 leave it
    // open); either way it makes no record and no navigation.
    expect((await settle(load.client.read(KEY, params("i")))).kind).toBe("gone");
    expect([[], ["fetch"]]).toContainEqual(log);
  });
});
