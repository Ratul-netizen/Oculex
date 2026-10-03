/**
 * The one layout: left nav, header, content.
 *
 * The header holds the two controls that are not about any particular view — the tenant
 * switcher and the time range — and the context bar sits under it, naming what the whole
 * application is currently about. SPEC calls the range "the single most-used control in the
 * product", which is why it is in the chrome rather than repeated per page: a range that
 * lives on a page is a range that resets when you leave it.
 */

import { Link, Outlet, useNavigate, useRouterState } from "@tanstack/react-router";
import { Fragment, useEffect, useState } from "react";

import { api } from "./api";
import { Wordmark } from "./brand";
import { ContextBar } from "./contextbar";
import { CommandPalette } from "./palette";
import { PRESETS, describeRange, useShell, type ShellSearch, type TimeRange } from "./shell";
import { zoneLabel } from "./time";

/**
 * The sidebar, grouped by the question each section answers — UI-SPEC §11.2.
 *
 * Only what exists. An entry with no screen behind it, or a screen with no data behind
 * it, is the product telling the operator it is unfinished every time they look at it —
 * and the sidebar is on every page, so it says so more often than anything else. This
 * grows as the product does; it is not a roadmap.
 *
 * Observability holds one item because metrics, logs and traces are all the Explorer with
 * a different `signal`. Three entries pointing at one screen with a preselected dropdown
 * would be three lies about how the product is built.
 */
const NAV: { heading: string; items: { to: string; label: string; exact?: boolean }[] }[] = [
  {
    heading: "Network",
    items: [
      { to: "/resources", label: "Resources" },
      { to: "/topology", label: "Topology" },
      { to: "/discovery", label: "Discovery", exact: true },
      // Address space. Under Network beside Discovery, and not inside it: sweeping finds
      // devices, and a declared range is address space an operator watches whether or not
      // anything is in it — `docs/ipam.md` §2.1.
      { to: "/subnets", label: "Addresses" },
      { to: "/flow", label: "Flow" },
      { to: "/map", label: "Map" },
    ],
  },
  {
    heading: "Observability",
    items: [
      { to: "/explore", label: "Explore" },
      { to: "/services", label: "Services" },
      // An objective is a statement about a service, so it sits beside them rather than
      // under Operations — `docs/slo.md` §2.5.
      { to: "/slos", label: "Objectives" },
    ],
  },
  {
    heading: "Operations",
    items: [
      { to: "/incidents", label: "Incidents" },
      // Under Operations rather than in a section of its own. A firewall deny and a link
      // going down are the same kind of question — what did the estate just report — and a
      // separate "Security" heading would suggest a separate product, which M11 §1 is
      // explicit that this is not.
      { to: "/security", label: "Security" },
      { to: "/alerts", label: "Alerts", exact: true },
      { to: "/alerts/rules", label: "Rules" },
      { to: "/alerts/channels", label: "Channels" },
      // Not under Network, although a collector sits on one. This is the list an
      // operator checks when telemetry has stopped arriving, which is an operations
      // question rather than an inventory one — and the answer is often that a process
      // died rather than that a device did.
      { to: "/collectors", label: "Collectors" },
      // How telemetry gets in from a host nobody here administers — `docs/packaging.md` §4.2.
      // Beside Collectors because they are the two halves of ingress: a collector is a process
      // an operator runs, an ingest token is what lets somebody else's machine reach it.
      { to: "/ingest", label: "Ingest" },
      // Who changed the estate and who saw it — SPEC §M0.8. Under Operations rather than
      // behind a settings page: an audit log nobody can find is one nobody checks, and
      // this is the evidence a regulated buyer asks for. Admin-only, and the screen says
      // so rather than the sidebar hiding it — a control that vanishes by role is one
      // people ask each other about.
      { to: "/audit", label: "Audit" },
      // The people who can sign in, and who may see which customer. Beside the audit log
      // rather than behind a settings gear: the two answer halves of one question a
      // regulated buyer asks, and until this screen existed an installation using passwords
      // had exactly one user forever. Admin-only, and the screen says so — see Audit above
      // for why that is not the sidebar's job.
      { to: "/users", label: "People" },
      // The customers this installation carries. Beside People because they are the two
      // halves of one question — who may see what — and because a role is granted *on* a
      // tenant, so a screen for one without the other is half an answer. Until this existed
      // an installation had exactly one tenant, permanently.
      { to: "/tenants", label: "Customers" },
      // Under Operations, and next to the things it is used during. A runbook is not part
      // of the inventory — it is what somebody does to the inventory at 3 a.m.
      { to: "/runbooks", label: "Runbooks" },
      { to: "/runs", label: "Runs" },
    ],
  },
];

/**
 * Sections that stand alone, below the groups.
 *
 * Dashboards is not a group: a heading reading "Dashboards" above a single item reading
 * "Dashboards" says the word twice and means it once. Observability keeps its heading
 * despite also holding one item, because there the heading says something the item does
 * not — that this is where logs, metrics and traces will live.
 */
const LOOSE: { to: string; label: string }[] = [{ to: "/dashboards", label: "Dashboards" }];

/** Carries the shell's search params through every navigation. */
function keepSearch(old: ShellSearch): ShellSearch {
  return old;
}

function TenantSwitcher() {
  const { me, tenant, setTenant } = useShell();

  // A single-tenant install is the common case on-premise, and a select with one option
  // is a control that looks interactive and is not.
  if (me.tenants.length === 1) {
    return (
      <span className="dim" title={tenant.tenant_id}>
        {tenant.name}
      </span>
    );
  }

  return (
    <select
      aria-label="Tenant"
      value={tenant.tenant_id}
      onChange={(e) => setTenant(e.target.value)}
    >
      {me.tenants.map((t) => (
        <option key={t.tenant_id} value={t.tenant_id}>
          {t.name}
        </option>
      ))}
    </select>
  );
}

/**
 * Which clock every time on the screen is in.
 *
 * Shows the zone in force — `+06` or `UTC` — rather than a word like "Local", because the
 * offset is the thing an operator needs when comparing a timestamp here with one in a
 * ticket from another site. One click swaps every time on the screen; see `./time`.
 */
function ZoneToggle() {
  const { zone, setZone } = useShell();
  const local = zoneLabel("local");
  return (
    <button
      type="button"
      className="quiet zone-toggle"
      aria-label={zone === "utc" ? `Times in UTC. Show local time (${local}) instead` : `Times in local time (${local}). Show UTC instead`}
      title={zone === "utc" ? `Times are in UTC. Click for local time (${local}).` : `Times are in your local time (${local}). Click for UTC.`}
      onClick={() => setZone(zone === "utc" ? "local" : "utc")}
    >
      {zone === "utc" ? "UTC" : local}
    </button>
  );
}

function RangePicker() {
  const { range, setRange, zone } = useShell();
  const [editing, setEditing] = useState(false);

  if (editing) {
    return (
      <form
        className="range"
        onSubmit={(e) => {
          e.preventDefault();
          const form = new FormData(e.currentTarget);
          const next: TimeRange = {
            from: String(form.get("from") ?? ""),
            to: String(form.get("to") ?? ""),
          };
          setRange(next);
          setEditing(false);
        }}
      >
        <input name="from" defaultValue={range.from} aria-label="From" size={20} />
        <input name="to" defaultValue={range.to} aria-label="To" size={20} />
        <button type="submit" className="primary">
          Apply
        </button>
        <button type="button" onClick={() => setEditing(false)}>
          Cancel
        </button>
      </form>
    );
  }

  return (
    <div className="range">
      <span className="label">{describeRange(range, zone)}</span>
      {/* One segmented control rather than five separate buttons: the presets are
          alternatives to each other, and drawing them apart said they were five unrelated
          actions sitting next to Sign out. */}
      <span className="presets">
        {PRESETS.map((p) => (
          <button
            key={p.label}
            className="preset"
            aria-pressed={range.from === p.range.from && range.to === p.range.to}
            onClick={() => setRange(p.range)}
          >
            {p.label}
          </button>
        ))}
        <button onClick={() => setEditing(true)} title="Absolute or relative, e.g. now-90m">
          Custom
        </button>
      </span>
    </div>
  );
}

export function Layout() {
  const { me } = useShell();
  const navigate = useNavigate();

  // On a phone the sections are behind a button. Without it the sidebar stacked above
  // the page and filled the whole first screen — twenty-five links before the Resources
  // table or the Explore form appeared, on an app whose manifest says it belongs on a
  // phone's home screen. Found by screenshotting at 390 px on 2026-10-03. On a desktop the
  // button is not displayed and this state is never read.
  const [navOpen, setNavOpen] = useState(false);
  const path = useRouterState({ select: (state) => state.location.pathname });

  // Choosing a destination is the end of wanting the menu. Keyed on the path, so it
  // closes however the navigation happened — a link, the command palette, the back button.
  useEffect(() => setNavOpen(false), [path]);

  // And Escape closes it, because an open menu is a thing a keyboard has to be able to
  // leave without walking to the button.
  useEffect(() => {
    if (!navOpen) return;
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") setNavOpen(false);
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [navOpen]);

  return (
    <div className="shell">
      <Wordmark />
      <button
        type="button"
        className="nav-toggle quiet"
        aria-expanded={navOpen}
        aria-controls="sections"
        onClick={() => setNavOpen((open) => !open)}
      >
        {navOpen ? "Close" : "Menu"}
      </button>

      <header className="header">
        <TenantSwitcher />
        <div className="spacer" />
        <RangePicker />
        <ZoneToggle />
        {/* The name is the link to one's own account, which is where a password is
            changed. Not in the sidebar: it is not a place in the estate, it is the one
            page about the person reading the screen. */}
        <Link to="/account" search={keepSearch} className="dim" title={me.email}>
          {me.display_name}
        </Link>
        <button
          className="quiet"
          onClick={() => {
            // The cookie is cleared by the server; this only stops showing a shell the
            // session behind it no longer supports.
            void api.logout().finally(() => navigate({ to: "/login" }));
          }}
        >
          Sign out
        </button>
      </header>

      {/* Under the header and above everything else, because it says what everything
          else is about. §13. */}
      <ContextBar />

      <nav id="sections" className={navOpen ? "nav open" : "nav"} aria-label="Sections">
        {/* Outside every group: the answer to the question you ask before you have one. */}
        <Link
          to="/"
          search={keepSearch}
          activeProps={{ className: "active" }}
          activeOptions={{ exact: true }}
        >
          Overview
        </Link>

        {NAV.map((group) => (
          <Fragment key={group.heading}>
            {/* Not a link. A heading that navigates has to decide which of its children
                it means, and the answer is always arbitrary. */}
            <h2 className="nav-heading">{group.heading}</h2>
            {group.items.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                search={keepSearch}
                activeProps={{ className: "active" }}
                {...(item.exact ? { activeOptions: { exact: true } } : {})}
              >
                {item.label}
              </Link>
            ))}
          </Fragment>
        ))}

        {LOOSE.map((item) => (
          <Link
            key={item.to}
            to={item.to}
            search={keepSearch}
            activeProps={{ className: "active" }}
            className="nav-loose"
          >
            {item.label}
          </Link>
        ))}
      </nav>

      <main className="content">
        <Outlet />
      </main>

      {/* Outside the grid: it covers the page rather than occupying a cell. */}
      <CommandPalette />
    </div>
  );
}
