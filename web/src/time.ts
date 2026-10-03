/**
 * How this product writes an instant on a screen.
 *
 * One rule, in one place, because there were nine and they disagreed. On a seeded install
 * the resource page said "Everything around 2:26:03 PM" — local, twelve-hour — above log
 * lines reading `08:30:54`, which were UTC with the `Z` stripped off. An operator in Dhaka
 * reads those as six hours apart, during the incident they are investigating, and nothing on
 * the screen said which was which. Elsewhere: raw ISO strings with a trailing `Z`, the
 * browser's locale format, and a range picker that described custom ranges in UTC.
 * Found by screenshotting a seeded install, 2026-10-03.
 *
 * The rule:
 *
 * * **Twenty-four-hour, year first** — `2026-10-03 14:30:54`. It sorts as text, it does not
 *   depend on the browser's locale, and nobody reading an incident timeline has to decide
 *   whether 02:00 meant the afternoon.
 * * **The zone is always visible**, as the offset (`+06`, `+05:30`) or `UTC`. Not per value
 *   necessarily — a column header or a heading can carry it for a whole table — but never
 *   absent from the screen.
 * * **Local by default, UTC on request.** The viewer's own clock is what they will compare
 *   against, and UTC is what they will want when comparing notes with another site. The
 *   choice lives in the URL (`?tz=utc`) beside the time range, for the reason the range
 *   does: a link sent during an incident should open the way it was read. Not in browser
 *   storage, which CI forbids for this app.
 */

export type Zone = "local" | "utc";

export interface StampOptions {
  /** Seconds are shown unless asked otherwise. */
  seconds?: boolean;
  /** Milliseconds, for log lines and spans, where ordering inside a second matters. */
  ms?: boolean;
  /** Append the zone label to this one value. */
  zone?: boolean;
  /** The date part, for a column of times all from one day. */
  date?: boolean;
}

/**
 * Read whatever the API or a query result handed over.
 *
 * Three shapes reach the UI: an ISO string with a `Z` (PostgreSQL via serde), a ClickHouse
 * `DateTime64(3, 'UTC')` rendered as `2026-10-03 08:30:54.133` with **no** zone, and a
 * `Date`. A zoneless string is UTC here, because every telemetry column is declared with
 * `'UTC'`; reading it as local — what `new Date()` does with that shape — would be the
 * six-hour error this module exists to remove. Fractions past milliseconds (PostgreSQL
 * sends microseconds) are trimmed, which JavaScript's parser does not do reliably.
 */
export function toDate(value: string | number | Date): Date | null {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === "number") return new Date(value);
  let s = value.trim();
  if (!s) return null;
  s = s.replace(" ", "T");
  s = s.replace(/(\.\d{3})\d+/, "$1");
  if (!/[zZ]$|[+-]\d{2}:?\d{2}$/.test(s)) s += "Z";
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

function pad(n: number, width = 2): string {
  return String(n).padStart(width, "0");
}

/**
 * The offset for `at`, as a label: `UTC`, `+06`, `+05:30`, `-03:30`.
 *
 * `offsetMinutes` is east of UTC, the opposite sign to `getTimezoneOffset`, and is a
 * parameter so tests do not depend on the zone of the machine running them.
 */
export function zoneLabel(zone: Zone, at: Date = new Date(), offsetMinutes?: number): string {
  if (zone === "utc") return "UTC";
  const east = offsetMinutes ?? -at.getTimezoneOffset();
  const sign = east < 0 ? "-" : "+";
  const abs = Math.abs(east);
  const minutes = abs % 60;
  return `${sign}${pad(Math.floor(abs / 60))}${minutes ? `:${pad(minutes)}` : ""}`;
}

/**
 * An instant, written by the rule above.
 *
 * Returns "—" for a value that is missing or unreadable rather than "Invalid Date", which is
 * what the browser would otherwise put in front of an operator.
 */
export function stamp(
  value: string | number | Date | null | undefined,
  zone: Zone,
  options: StampOptions = {},
  offsetMinutes?: number,
): string {
  if (value === null || value === undefined) return "—";
  const d = toDate(value);
  if (!d) return "—";

  const { seconds = true, ms = false, zone: showZone = false, date = true } = options;
  // Shift into the target zone, then read the UTC fields: that is the same arithmetic for
  // local and UTC, and it lets a test pin the offset.
  const east = zone === "utc" ? 0 : (offsetMinutes ?? -d.getTimezoneOffset());
  const t = new Date(d.getTime() + east * 60_000);

  let out = `${pad(t.getUTCHours())}:${pad(t.getUTCMinutes())}`;
  if (seconds || ms) out += `:${pad(t.getUTCSeconds())}`;
  if (ms) out += `.${pad(t.getUTCMilliseconds(), 3)}`;
  if (date) out = `${t.getUTCFullYear()}-${pad(t.getUTCMonth() + 1)}-${pad(t.getUTCDate())} ${out}`;
  if (showZone) out += ` ${zoneLabel(zone, d, offsetMinutes)}`;
  return out;
}
