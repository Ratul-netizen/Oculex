# Rotating the key-encryption key

**Status:** built, 2026-10-03 — every criterion in §5 met. Written before the code, as this repository does,
because the choices below are about how an operator runs a procedure that can lock every
credential out of the product, and those are cheaper to argue about in prose than to fix in a
release.

---

## 1. What exists, and the one thing that does not

The cryptography is done and is good. SPEC §M0 asked for KEK rotation that is *"cheap by
construction — re-wrap DEKs, never touch ciphertext"*, and that is what is built:

* **`LocalVault::rotate_kek`** walks every sealed device credential and re-wraps its data key
  under the active KEK. The write is **conditional** (`replace_wrapping` with the bytes it read),
  so a credential rotated by an operator mid-run is reported as `superseded` rather than
  destroyed. A `RotationReport` counts `rewrapped`, `already_current`, `superseded` and `failed`.
* **`Envelope::rewrap`** does the same for a single `SealedValue` — the shape SSO client secrets
  are stored in.
* **`KekRing`** holds one active key and any number of retired ones, and opening a row looks its
  key up by the `kek_id` the row records.

**What does not exist is any way for an operator to use it.** `docs/unreached-triage.md` §1
found it: `rotate_kek`, `add_retired`, `promote_kek`, `rewrap` and `get_latest` — five
functions, one subsystem — and every caller is a test. Concretely:

1. **Nothing can put a retired key in the ring.** Every process builds its ring with
   `KekRing::from_file` or `from_env`, which take exactly one key. The configuration surface is
   `UOPS_KEK_FILE` *or* `UOPS_KEK_HEX`, plus `UOPS_KEK_ID`.
2. **Nothing triggers a re-wrap.** No route, no subcommand, no job calls `rotate_kek`.
3. **SSO secrets are not covered at all.** `Envelope::rewrap` exists; nothing walks
   `identity_provider` to call it.
4. **Nothing says how far a rotation has got.** There is no count of rows per key, so an
   operator cannot know when the old key is safe to destroy.

So an operator who rotates the way any runbook says — new key file, new `UOPS_KEK_ID`,
restart — gets every credential sealed under the old key failing with `UnknownKek`, polling
stops for every device that has one, and SSO sign-in fails. It is recoverable, by putting the
old key back, which is the only reason this is not a data-loss bug. **It is the top finding of
the unreached triage, and the one a procurement security review asks about by name.**

## 2. Who holds the key

Four processes open sealed values, and each builds its own ring from the same configuration:

| process | opens | through |
|---|---|---|
| `uops-server` | device credentials (API, discovery sweeper), SSO client secrets | `LocalVault`, `Envelope` |
| `uops-poller` | device credentials | `LocalVault` |
| `uops-runner` | device credentials | `LocalVault` |

In the compose stack all three mount the same `kek` volume at `/srv/kek`, and the `migrate`
service generates `/srv/kek/kek.hex` on first start. The collectors open nothing and mount
nothing, and that stays true.

## 3. The decisions

### 3.1 Retired keys come from a directory, beside the active one

**`UOPS_KEK_RETIRED_DIR`**, optional. Every `<id>.hex` file in it is loaded into the ring as a
retired key whose id is the file's name. The active key is still `UOPS_KEK_FILE` and
`UOPS_KEK_ID`, unchanged.

Rejected alternatives:

* **One directory for every key, with `UOPS_KEK_ID` naming the active one.** Neater, and it
  breaks every existing installation: today's key lives at `kek.hex` with the id `default`, and
  a directory loader would read its id as `kek`. Every sealed row in every deployment says
  `default`. Keeping the active key where it is means **an installation that never rotates sees
  no change at all.**
* **A list in an environment variable** (`UOPS_KEK_RETIRED=id1:/path1,id2:/path2`). Parsing
  paths with separators out of an environment variable is a support ticket waiting to happen,
  and the ids would be written in two places — the variable and the files.
* **Retired keys in the database.** The whole design rests on the KEK never being in the same
  store as what it protects; `docs/security-overview.md` says so, and a backup that contained
  its own keys would undo the point of having them.

A file in the retired directory gets the **same permission check** `from_file` applies to the
active key — group- or world-readable is refused, on Unix — and an unreadable or malformed file
**stops the process** rather than being skipped. A retired key that is silently missing is the
failure this whole document exists to remove.

### 3.2 The re-wrap is a subcommand, run by a person

**`uops-server rotate-kek`**: loads the configuration, builds the ring with its retired keys,
re-wraps every device credential and every SSO secret under the active key, prints the report,
and exits non-zero if any row failed.

Rejected alternatives:

* **Automatically at startup.** Three processes start at once and all three would race to
  re-wrap the same rows. The conditional write makes that *safe*, but a rotation is a change to
  a security control, and it should happen when an operator decides, appear in their terminal,
  and be something they can point at in a change ticket. Not something that happened because a
  container restarted.
* **An admin API route and a button.** It walks every credential in every tenant — `list_all`
  is deliberately cross-tenant — which does not fit an API whose every other route is scoped to
  one tenant, and a long walk is a poor fit for an HTTP request. A subcommand runs where the key
  files already are.

It is a subcommand of the server rather than a new binary because the server already loads
this configuration and already has both stores; a second binary would be one more thing to ship
and keep in the image.

### 3.3 Before anything else, the product says which keys its rows need

At startup the server counts sealed rows per `kek_id` across `credential` and `identity_provider`
and compares them with the ring:

* a row whose key **is not in the ring** is logged loudly, with the count and the id, naming
  `UOPS_KEK_RETIRED_DIR` as the fix — so "I rotated and forgot the old key" is one line at boot,
  not every poll failing quietly for a week;
* rows on a **retired** key are reported as a count, so an operator can see a rotation is
  pending.

`rotate-kek` prints the same table before and after. **The old key may be destroyed when, and
only when, that table shows no row on it** — and the document's procedure says exactly that.

## 4. The procedure this produces

1. Move the current key into the retired directory, named by its id:
   `mkdir -p /srv/kek/retired && mv /srv/kek/kek.hex /srv/kek/retired/default.hex`.
2. Write a new active key to `/srv/kek/kek.hex`, and choose a new id —
   `UOPS_KEK_ID=kek-2026-10`.
3. Set `UOPS_KEK_RETIRED_DIR=/srv/kek/retired` and the new `UOPS_KEK_ID` on **every** service
   that mounts the key, and restart them. New writes now use the new key; old rows still open.
4. Run `uops-server rotate-kek`. Read the report: `failed` must be 0.
5. When the table shows no row on `default`, delete `/srv/kek/retired/default.hex` — and the
   copy in whatever backs up the key, which is the step people forget.

A rotation interrupted at any point leaves every row openable, because nothing is removed from
the ring until step 5, and step 5 is a person deleting a file after reading a count.

## 5. Acceptance criteria

- [x] A retired key is loaded from `UOPS_KEK_RETIRED_DIR`, by file name, with the active key's
      permission check; a malformed or unreadable file stops the process —
      `KekRing::load_retired_dir`, four tests including a file that claims the active id. The
      permission check is the *same function* the active key uses, not a copy of it
- [x] An installation with no `UOPS_KEK_RETIRED_DIR` behaves exactly as before — the active
      key is still `UOPS_KEK_FILE` and `UOPS_KEK_ID`, and the new variable is optional
- [x] `uops-server rotate-kek` re-wraps device credentials **and** SSO client secrets, prints
      the per-key table before and after, and exits non-zero on any failure
- [x] After rotating, every credential and SSO secret opens with only the new key in the ring
      — `crates/uops-server/tests/rotation.rs`, which runs the real binary against a scratch
      database, deletes the old key, and opens both rows. A control shows the new key alone
      opens nothing *before* the rotation, so the success after it is the rotation's doing.
      Verified by mutation: a re-wrap that reports success and writes nothing fails the test,
      because it checks the stored row and not the report
- [x] Server startup reports rows on keys the ring does not hold, and rows on retired keys
- [x] The poller and runner load retired keys too, so they keep opening rows during steps 3–4
- [x] `docs/security-overview.md` and `docs/dev-environment.md` describe the procedure

**Not done, and named:** the compose file does not set `UOPS_KEK_RETIRED_DIR`, because an
installation that has never rotated has nothing to put there; the procedure in §4 says to set
it on every service that mounts the key. And the startup report is printed rather than exposed
on `/api/v1/health` — a rotation left half-done shows in the log at every start, not yet in a
monitoring check.
