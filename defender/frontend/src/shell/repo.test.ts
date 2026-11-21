// The shell's check of a tenant repository's page (`repoAddress`): what a screen may link to off the app's origin.
import { describe, expect, it } from "vitest";
import { repoAddress } from "./repo";

const APP = "https://app.example";

describe("repoAddress", () => {
  it("keeps an http or https page on another origin, as the browser spells it", () => {
    expect(repoAddress("https://forge.example/tenants/a1", APP)).toBe("https://forge.example/tenants/a1");
    expect(repoAddress("http://forge.example:3000/tenants/a1", APP)).toBe("http://forge.example:3000/tenants/a1");
    expect(repoAddress("HTTPS://Forge.Example/tenants/a1", APP)).toBe("https://forge.example/tenants/a1");
  });

  it.each([
    ["no value", null],
    ["no value (absent)", undefined],
    ["not an address", "tenants/a1"],
    ["a path on the app", "/api/me"],
    ["ssh", "ssh://git@forge.example/tenants/a1.git"],
    ["scp-style", "git@forge.example:tenants/a1.git"],
    ["javascript", "javascript:alert(1)"],
    ["a user part", "https://bot@forge.example/tenants/a1"],
    ["a user and password", "https://bot:secret@forge.example/tenants/a1"],
    ["a query", "https://forge.example/tenants/a1?x=1"],
    ["a fragment", "https://forge.example/tenants/a1#x"],
    ["the app's own origin", "https://app.example/api/tenants"],
    ["the app's own origin, spelled otherwise", "HTTPS://APP.EXAMPLE:443/x"],
  ])("refuses %s", (_, value) => {
    expect(repoAddress(value, APP)).toBeNull();
  });

  it("keeps the app's host on another port or scheme: that is another origin", () => {
    expect(repoAddress("https://app.example:3000/tenants/a1", APP)).toBe("https://app.example:3000/tenants/a1");
    expect(repoAddress("http://app.example/tenants/a1", APP)).toBe("http://app.example/tenants/a1");
  });
});
