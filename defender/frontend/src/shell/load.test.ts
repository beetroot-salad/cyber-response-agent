// The load (B1's owner, Am-5): two 401s of one load make one navigation; a 401 to a superseded load does nothing.
// The effects are the load's only way out, so each is a spy and nothing else is stubbed.
import { describe, expect, it, vi } from "vitest";
import { makeLoad } from "./load";

/** The one place that names how a read is issued through the load's client. The design says the client owns every
 *  read and returns gone / ok / not-available / error (Am-5 point 4) but not the call's shape: `load.client.read(path)`
 *  is assumed, and only this adapter has to follow the real one. */
interface Reading {
  readonly client: { read(path: string): Promise<{ readonly kind: string }> };
}
const read = (load: unknown, path: string) => (load as Reading).client.read(path);

const READ = "/api/tenants/t/investigations/i";

function unauthorized(): Response {
  return new Response("{}", { status: 401, headers: { "Content-Type": "application/json" } });
}

function loadWith(fetch: () => Promise<Response>) {
  const effects = { fetch: vi.fn(fetch), record: vi.fn(() => true), assign: vi.fn(), replace: vi.fn() };
  const load = makeLoad({ taken: { status: "none" }, byHistory: false, target: "/home", effects });
  return { load, effects };
}

describe("a load's reads", () => {
  it("two reads of one load both answered 401 make exactly one sign-in navigation", async () => {
    const { load, effects } = loadWith(async () => unauthorized());
    const results = await Promise.all([read(load, READ), read(load, `${READ}?again=1`)]);
    expect(effects.assign).toHaveBeenCalledTimes(1);
    expect(results.map((r) => r.kind)).toEqual(["gone", "gone"]);
  });

  it("a 401 answered after the load is superseded makes no record or navigation, and the read is gone", async () => {
    let answer: (response: Response) => void = () => undefined;
    const { load, effects } = loadWith(() => new Promise<Response>((resolve) => (answer = resolve)));
    const pending = read(load, READ);
    expect(effects.fetch).toHaveBeenCalledTimes(1);
    load.supersede();
    answer(unauthorized());
    expect((await pending).kind).toBe("gone");
    expect(effects.record).not.toHaveBeenCalled();
    expect(effects.assign).not.toHaveBeenCalled();
    expect(effects.replace).not.toHaveBeenCalled();
  });

  it("a 401 to a read issued after the load is superseded is gone and does nothing", async () => {
    const { load, effects } = loadWith(async () => unauthorized());
    load.supersede();
    expect((await read(load, READ)).kind).toBe("gone");
    expect(effects.record).not.toHaveBeenCalled();
    expect(effects.assign).not.toHaveBeenCalled();
    expect(effects.replace).not.toHaveBeenCalled();
  });
});
