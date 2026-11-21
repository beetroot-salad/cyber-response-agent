// The address builder for a shape with placeholders (alert list design, Flows "Home"; O4): it fills the shape's
// template, and `match` (the same membership the router uses) reads the result back as that shape.
// FORCED CHOICE: the builder's name and signature (`addressOf(name, values)`, values in the template's order, as
// `valuesOf` answers them) are not in the design; nor is what it does with a value outside the placeholder's alphabet.
import { describe, expect, it } from "vitest";
import { addressOf, match, RETURNABLE, valuesOf } from "./addresses";

const TENANT = "0b6f1c1e-3c55-4a4e-9a51-1083000000aa";
const INVESTIGATION = "7c1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f";

/** `count` ids spelled by a seeded generator, so a case that fails names its id and fails again. */
function ids(count: number): string[] {
  let state = 0x1161;
  const hex = (): string => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return (state >>> 28).toString(16);
  };
  const group = (n: number): string => Array.from({ length: n }, hex).join("");
  return Array.from({ length: count }, () => [group(8), group(4), group(4), group(4), group(12)].join("-"));
}

describe("addressOf (Home's links)", () => {
  it("builds a tenant's alerts address that `match` reads back as the alerts shape", () => {
    const address = addressOf("alerts", [TENANT]);
    expect(address).toBe(`/t/${TENANT}/alerts`);
    expect(match(address)).toBe("alerts");
    expect(valuesOf("alerts", address)).toEqual([TENANT]);
  });

  it("fills every placeholder of a shape with several, in the template's order", () => {
    const address = addressOf("investigation", [TENANT, INVESTIGATION]);
    expect(address).toBe(`/t/${TENANT}/investigations/${INVESTIGATION}`);
    expect(match(address)).toBe("investigation");
    expect(valuesOf("investigation", address)).toEqual([TENANT, INVESTIGATION]);
  });

  it("builds a member of the shape, and reads back its own values, for any id of the alphabet", () => {
    for (const id of ids(40)) {
      const address = addressOf("alerts", [id]);
      expect(match(address), id).toBe("alerts");
      expect(valuesOf("alerts", address), id).toEqual([id]);
    }
  });
});

describe("the alerts address (O4)", () => {
  it("is returnable, so sign-in brings a person back to it, as it does the home and an investigation", () => {
    expect(RETURNABLE.has("alerts")).toBe(true);
    expect([...RETURNABLE].sort()).toEqual(["alerts", "home", "investigation"]);
  });

  it("is the whole path `/t/<uuid>/alerts`: nothing before it, after it, or in other letters", () => {
    const member = `/t/${TENANT}/alerts`;
    expect(match(member)).toBe("alerts");
    for (const other of [
      `${member}/`,
      `${member}?outcome=malicious`,
      `${member}#x`,
      `/${member}`,
      member.toUpperCase(),
      member.replace("/t/", "/T/"),
      member.replace("alerts", "alert"),
      member.replace("alerts", "Alerts"),
      `/t/${TENANT.slice(1)}/alerts`,
      `/t/${TENANT.toUpperCase()}/alerts`,
      `/t//alerts`,
      `/t/${TENANT}/alerts/${INVESTIGATION}`,
    ])
      expect(match(other), other).toBeNull();
  });
});
