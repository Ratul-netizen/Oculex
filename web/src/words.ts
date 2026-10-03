/**
 * Counting things in a sentence.
 *
 * One function, because the same mistake turned up in six places at once: a template
 * literal of the shape `${n} resources`, which reads "1 resources" on exactly the install
 * a new customer sees first — an empty one, holding a single resource that is the
 * installation itself. Found by screenshotting a fresh install on 2026-10-03.
 *
 * `alerting.ts` already had a private `plural` that got this right; it now uses this one,
 * so there is one rule rather than a correct copy and five incorrect ones.
 */

/**
 * `n` and the noun, agreeing.
 *
 * Grouped with the reader's locale, since every caller was already doing that by hand.
 * Irregular plurals are passed explicitly — "person" / "people" — rather than guessed.
 */
export function count(n: number, singular: string, plural = `${singular}s`): string {
  return `${n.toLocaleString()} ${n === 1 ? singular : plural}`;
}
