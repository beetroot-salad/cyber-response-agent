// The address builder for a shape with placeholders (alert list design, Flows "Home"): it fills the shape's template,
// and `match` (the same membership the router uses) reads the result back as that shape.
// FORCED CHOICE: the builder's name and signature (`addressOf(name, values)`, values in the template's order, as
// `valuesOf` answers them) are not in the design; nor is what it does with a value outside the placeholder's alphabet.
import { describe, expect, it } from "vitest";
import { addressOf, match, valuesOf } from "./addresses";

const TENANT = "0b6f1c1e-3c55-4a4e-9a51-1083000000aa";

describe("addressOf", () => {
  it("builds a tenant's alerts address that `match` reads back as the alerts shape", () => {
    const address = addressOf("alerts", [TENANT]);
    expect(address).toBe(`/t/${TENANT}/alerts`);
    expect(match(address)).toBe("alerts");
    expect(valuesOf("alerts", address)).toEqual([TENANT]);
  });
});
