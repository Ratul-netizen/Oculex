# Naming decision: this project → **Oculex**

> Handoff note for this project's Claude session, written 2026-09-28 from the sibling
> project's session. The owner (Ratul) has decided on the name below. Treat this as the
> owner's instruction, but verify the availability facts yourself before acting — they were
> true when checked and can change.

## The decision

Rename this project (currently the repo `veyronis`, README title **"uops — Unified
Infrastructure Observability Platform"**) to **Oculex**.

**Why it fits:** the product's whole thesis is *"one resource identity sees and correlates
every signal"* (SNMP, logs, metrics, traces, flows, topology on one `resource_id`). "Oculex"
reads as *oculus* + *-ex* — "the eye," the all-seeing watcher. It matches the observability
theme directly and is short, pronounceable, and brandable.

## Availability as checked on 2026-09-28 (re-verify before committing)

- **Package registries — all FREE:** `oculex` on **npm** (404), **PyPI** (404), **crates.io** (404).
- **Web / company search:** the only notable hit is **Oculex Pharmaceuticals** — an ophthalmic
  drug-delivery company founded 1989, **acquired by Allergan in 2003** (defunct, and a totally
  different industry). No active software company or product called Oculex surfaced.
- **Collision risk:** low, but **registry-free ≠ trademark-clear.** Before committing
  commercially, do a formal trademark search — the owner is **Bangladesh-based**, so start with
  **DPDT** (Department of Patents, Designs and Trademarks, [dpdt.gov.bd](https://dpdt.gov.bd)),
  and add **USPTO** / **EUIPO** if selling in the US/EU — and grab the domain
  (`oculex.io` / `.dev` / `.com`).

## Names that were considered and rejected (so you don't re-suggest them)

- **Nullhawk** — was a candidate for THIS project, but it was assigned to the **sibling
  project** instead (the offensive-security workbench formerly named "Hexora" is being renamed
  **Nullhawk**). Do **not** reuse Nullhawk here.
- **Panoptex** — thematically perfect ("panopticon") but **AVOID**: there's an active Big-Data
  software company *Panoptex Technologies* **with a registered US trademark** (serial 87486930).
- Classic mythic watchers — **Heimdall, Argus, Panoptes, Muninn, Huginn, Yggdrasil, Mimir,
  Aegis** — are all **taken on every registry** (Grafana Mimir is literally a metrics DB, etc.).
- Anime "all-seeing eyes" — **Byakugan, Amaterasu, Tsukuyomi** — partly free but npm-taken and
  carry Naruto/Shueisha IP flavor; risky for a commercial mark.
- **Oculex** won as the cleanest name that still hits the "all-seeing" theme.

## Sibling-project context (for consistency)

The owner runs two products in parallel:

| Project | Old name | New name |
| --- | --- | --- |
| Offensive-security workbench (Rust + Tauri/React) | Hexora | **Nullhawk** |
| **This** — infra observability platform (Rust + Postgres + ClickHouse) | veyronis / uops | **Oculex** |

Keep the two names distinct in any shared copy, docs, or org branding.

## If/when you do the rename, lessons from the sibling's deep rename (Hexora → Nullhawk)

That project did a full, deep rename (all crate names + every reference). What worked:

1. **Do it on a branch** (e.g. `rename/oculex`), keep `main`/any green release intact.
2. **Case-aware scripted replace** across *tracked text files only* (`git ls-files`, excluding
   binaries: png/ico/jpg/gif/wasm/woff*/ttf/exe/pdf…). Replace the three case variants:
   `VEYRONIS→OCULEX`, `Veyronis→Oculex`, `veyronis→oculex` (and likewise for `uops` if that
   string is used internally). Kebab-case crate names (`veyronis-foo`) and snake-case Rust
   module paths (`veyronis_foo`) are substrings, so they're covered automatically.
3. **Check filenames** (`git ls-files | grep -i veyronis`) — rename any files/dirs named after
   the project (the sibling had none; you may differ).
4. **Regenerate `Cargo.lock`** by building; path-dependency crates carry no checksum, so
   renaming their names is safe.
5. **Update the non-obvious identifiers by hand-check:** any build-time env var (the sibling
   had `HEXORA_LICENSE_PUBKEY` → `NULLHAWK_LICENSE_PUBKEY`, which also meant renaming the CI
   repo secret), the app/bundle identifier, the CLI binary name, the on-disk config/data
   directory (`%AppData%\<name>` — note this orphans existing local state, plan a migration or
   accept the reset), and any separate brand tokens that the `name`-replace won't catch (the
   sibling's licence-file extension `.hexlic` was NOT caught by a `hexora→nullhawk` replace —
   look for equivalents here).
6. **Rebuild + test + fmt + clippy + deny** before committing, then re-cut any release
   (new tag/installers) and rename the GitHub repo last (GitHub auto-redirects the old URL).

## Status

Name **chosen** (Oculex). The actual code rename in this repo has **not** been started by the
sibling session — it's left for you/this project's owner to execute when ready (this project
already has a `RENAME_AUDIT.md`, so there's prior art here).
