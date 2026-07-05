import { expect } from "bun:test";
import type { ApplyResult, CardState } from "../../src/contract";

/** Assert a successful transition and return the new card state. */
export function expectOk(res: ApplyResult | null): CardState {
  expect(res).not.toBeNull();
  expect(res && res.ok).toBe(true);
  if (!res || !res.ok) throw new Error("expected an ok ApplyResult");
  return res.card;
}

/** Assert a routine no-op (stale CAS). */
export function expectStale(res: ApplyResult | null): void {
  expect(res).toEqual({ ok: false, reason: "stale" });
}
