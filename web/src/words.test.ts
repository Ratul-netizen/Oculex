import { describe, expect, it } from "vitest";

import { count } from "./words";

describe("count", () => {
  // The case that was wrong in six places, and the one a new install shows first.
  it("says one resource, not one resources", () => {
    expect(count(1, "resource")).toBe("1 resource");
  });

  it("pluralises zero and many", () => {
    expect(count(0, "resource")).toBe("0 resources");
    expect(count(2, "row")).toBe("2 rows");
  });

  it("takes an irregular plural rather than guessing one", () => {
    expect(count(1, "person", "people")).toBe("1 person");
    expect(count(3, "person", "people")).toBe("3 people");
  });

  it("groups large numbers the way every caller already did", () => {
    expect(count(10_000, "row")).toBe((10_000).toLocaleString() + " rows");
  });
});
