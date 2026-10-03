import { describe, expect, it } from "vitest";

import { stamp, toDate, zoneLabel } from "./time";

const DHAKA = 6 * 60; // +06, east of UTC
const ADELAIDE = 9 * 60 + 30; // +09:30
const NEWFOUNDLAND = -(3 * 60 + 30); // -03:30

describe("toDate", () => {
  it("reads a ClickHouse DateTime64 with no zone as UTC, not as local", () => {
    // The six-hour error: `new Date("2026-10-03 08:30:54")` is local in browsers.
    expect(toDate("2026-10-03 08:30:54.133")?.toISOString()).toBe("2026-10-03T08:30:54.133Z");
  });

  it("reads an ISO string with Z, and trims PostgreSQL's microseconds", () => {
    expect(toDate("2026-10-03T08:54:44.400395Z")?.toISOString()).toBe("2026-10-03T08:54:44.400Z");
  });

  it("keeps an explicit offset", () => {
    expect(toDate("2026-10-03T14:30:00+06:00")?.toISOString()).toBe("2026-10-03T08:30:00.000Z");
  });

  it("says null for nonsense rather than Invalid Date", () => {
    expect(toDate("not a time")).toBeNull();
    expect(toDate("")).toBeNull();
  });
});

describe("stamp", () => {
  const at = "2026-10-03 08:30:54.133";

  it("writes local time with the offset, twenty-four hour, year first", () => {
    expect(stamp(at, "local", { zone: true }, DHAKA)).toBe("2026-10-03 14:30:54 +06");
  });

  it("writes UTC as UTC", () => {
    expect(stamp(at, "utc", { zone: true })).toBe("2026-10-03 08:30:54 UTC");
  });

  it("gives milliseconds when the order inside a second matters", () => {
    expect(stamp(at, "utc", { ms: true })).toBe("2026-10-03 08:30:54.133");
  });

  it("can drop the date for a column of times from one day", () => {
    expect(stamp(at, "local", { date: false, seconds: false }, DHAKA)).toBe("14:30");
  });

  it("crosses midnight into the next day when the zone says so", () => {
    expect(stamp("2026-10-03T20:15:00Z", "local", {}, DHAKA)).toBe("2026-10-04 02:15:00");
  });

  it("renders a dash for a missing or unreadable value", () => {
    expect(stamp(null, "utc")).toBe("—");
    expect(stamp(undefined, "utc")).toBe("—");
    expect(stamp("garbage", "utc")).toBe("—");
  });
});

describe("zoneLabel", () => {
  it("writes whole-hour offsets short and half-hours in full", () => {
    expect(zoneLabel("local", new Date(), DHAKA)).toBe("+06");
    expect(zoneLabel("local", new Date(), ADELAIDE)).toBe("+09:30");
    expect(zoneLabel("local", new Date(), NEWFOUNDLAND)).toBe("-03:30");
    expect(zoneLabel("local", new Date(), 0)).toBe("+00");
  });

  it("calls UTC by its name", () => {
    expect(zoneLabel("utc")).toBe("UTC");
  });
});
