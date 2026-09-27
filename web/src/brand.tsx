/**
 * The mark, and the one string that is the product's name.
 *
 * # Why this file exists at all
 *
 * SPEC's branding rule: *"the product brand is provisional. No product-facing identifier
 * may be used as a persistence, crate, database, environment-variable, Docker image or
 * encryption identifier until brand clearance is complete. Product-facing surfaces —
 * README, documentation, the UI, marketing — say the product name. Everything in the tree
 * says `uops`."*
 *
 * The UI is a product-facing surface, so it is allowed to say the name — and the name is
 * kept in exactly one constant here so that saying it costs one line to change.
 *
 * **That has now happened twice.** *Aegisora* until 2026-09-16, renamed for eight lines of
 * documentation and no code. *Veyronis* until 2026-09-28, renamed for the reason this file
 * recorded at the time: `veyronis.com` is an active software consultancy and *Varonis* is a
 * registered mark in an adjacent field. Two renames, no code touched either time, which is
 * the whole return on keeping `uops` in the tree.
 *
 * **Oculex** is the third, and is provisional for the same reason the others were. `oculex`
 * is free on npm, PyPI and crates.io — all three 404 as of 2026-09-28, checked rather than
 * taken on trust. The only notable prior use is Oculex Pharmaceuticals, acquired by Allergan
 * in 2003 and defunct, in a different industry entirely. **A free registry is not a clear
 * trademark**: clearance still needs a formal search, and for this owner that is Bangladesh's
 * DPDT alongside USPTO and EUIPO — not India's MCA, which the handoff note that carried this
 * decision suggested and which is both the wrong country and a company registry rather than a
 * trademark one.
 *
 * # Why the mark has no letter in it
 *
 * A monogram is a bet on a name. This one is a geometric figure: separate signals
 * converging on a single node — which is the product's actual thesis, that syslog, SNMP,
 * OTLP, flows and topology all resolve to one `resource_id`. It means the same thing
 * whatever the product ends up being called, and it reads at 16 pixels because it is
 * three strokes and a dot.
 *
 * Drawn in `currentColor` so it themes with everything else and needs no second asset for
 * dark and light.
 */

/**
 * The product's name, on product-facing surfaces only.
 *
 * One constant. See the module docs for why.
 */
export const PRODUCT = "Oculex";

/**
 * The mark: three signals converging on one resource.
 *
 * `size` is a pixel box; the geometry is a 24-unit grid scaled into it. Given
 * `aria-hidden`, because it appears beside the wordmark everywhere it is used and a
 * screen reader announcing "logo" before the product's name is noise.
 */
export function Mark({ size = 20 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
      focusable="false"
    >
      {/* Three signals, arriving at different angles. Rounded caps so they read as
          traces rather than as arrows, and thinned as they converge. */}
      <path
        d="M2 5.5 L10.5 10.2"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        opacity="0.55"
      />
      <path
        d="M2 12 L10.5 12"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        opacity="0.75"
      />
      <path
        d="M2 18.5 L10.5 13.8"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        opacity="0.55"
      />

      {/* The resource they resolve to. A ring rather than a disc: the identity is a
          thing signals attach to, not a full stop. */}
      <circle cx="15.5" cy="12" r="4.5" stroke="currentColor" strokeWidth="2" />
      <circle cx="15.5" cy="12" r="1.4" fill="currentColor" />
    </svg>
  );
}

/** The mark and the name, as they appear in the header. */
export function Wordmark() {
  return (
    <span className="brand">
      <span className="brand-mark">
        <Mark size={20} />
      </span>
      <span className="brand-name">{PRODUCT}</span>
    </span>
  );
}
