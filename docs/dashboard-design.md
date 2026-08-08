# Dashboard design specification (M6 Step 6.2 / 6.3)

This is the visual and interaction specification for the euvd-watch dashboard. It sits
**under** the engineering contract — `plans/implementation_plan.md` §6.2,
`plans/test_plan.md` §6.2, and the storage/vocabulary already in the codebase — and
fills in *how it should look and behave*. Where this document and those specs disagree
on behavior, they win; this document governs appearance, layout, states, and copy.

An implementing agent (Sonnet 5) should be able to build the templates from this file
without further design decisions. A companion interactive visual mockup of all four
pages is published as an Artifact —
<https://claude.ai/code/artifact/4859edee-edb7-4c0e-aaee-553172192ddf> (also noted in
`tasks/todo.md`). This file is the source of truth if the two ever drift.

---

## 1. Design principles (the non-negotiables)

1. **This is an operations console, not a document.** It is scanned and operated, not
   read top to bottom. Every page surfaces a summary before its detail. What needs a
   human's attention must read at a glance — before any number is parsed.
2. **State is encoded in form, not color alone.** Every status carries a text label
   **and** a shape (a severity stripe, a pill, an icon) in addition to its color. This
   is a WCAG 2.1 AA requirement (1.4.1 Use of Color), not a nicety — a red/green-blind
   operator must never miss an overdue clock.
3. **Trust through restraint.** The subject is legal deadlines and tamper-evident
   records. Calm, dense, precise legibility signals reliability; visual flash signals
   the opposite. No gradients-as-decoration, no animated flourishes, no marketing hero.
4. **The tool never acts on its own — and neither does the UI.** The dashboard is
   read-mostly. Its only writes are recording a human's CRA-stage completion and VEX
   decision *hints*. **No control anywhere submits anything to an external authority.**
   Copy must never imply the tool filed or will file a report.
5. **Honest degradation.** Every page has a designed empty state, a designed error
   state, and a designed "data is stale" state. "No findings" is only ever shown when
   we truly matched and found none — never when data was missing (mirrors the CLI's
   "refusing to report 'no findings' on missing data").
6. **No build chain, no CDN.** Server-rendered Jinja2, one hand-written CSS file, zero
   JavaScript frameworks. Any interactivity is progressive enhancement over working
   HTML. Fonts are system stacks (see §3) — nothing is fetched from a network.

---

## 2. Color tokens

Defined as CSS custom properties on `:root`, themed for light and dark. Style every
component **through the tokens**, never with raw hex. All foreground/background pairs
listed meet WCAG AA (≥ 4.5:1 for body text, ≥ 3:1 for large text and UI boundaries);
re-verify with an axe/contrast check in CI (§9), never by eye.

### Neutrals — cool, blue-biased (never pure grey)

| Token | Light | Dark | Use |
|---|---|---|---|
| `--ground` | `#f5f7fb` | `#0e1621` | page background |
| `--surface` | `#ffffff` | `#16202e` | cards, tables, nav |
| `--surface-raised` | `#eef2f8` | `#1e2a3a` | hover rows, wells, code blocks |
| `--border` | `#d3dbe7` | `#2a394d` | hairlines, dividers |
| `--text` | `#16202e` | `#e6ecf3` | primary text |
| `--text-muted` | `#5a6b80` | `#9fb0c4` | secondary text, captions, labels |

### Accent — institutional blue (interactive only; not a status)

| Token | Light | Dark | Use |
|---|---|---|---|
| `--accent` | `#2b5fb3` | `#6ea3e6` | links, primary buttons, focus ring, active nav |
| `--accent-strong` | `#123a72` | `#8ab6ee` | top bar, table headers, button text-on-tint |
| `--accent-tint` | `#e8eff9` | `#1c2c44` | active nav background, info wells |

### Semantic — the compliance-state scale (separate from the accent, colorblind-safe)

Each maps to a `ClockState` or severity. Pills use a **tinted background + dark
foreground** so the text itself always passes contrast; the hue is reinforced by the
label and the stripe.

| Token (fg / bg) | Light fg | Light bg | Dark fg | Dark bg | Meaning |
|---|---|---|---|---|---|
| `--ok` | `#0f6b46` | `#e4f3ec` | `#5ecf9e` | `#123024` | `pending` (on track), `fixed` |
| `--warn` | `#8a5510` | `#fbefdc` | `#e8b46a` | `#33260f` | `due_soon` |
| `--crit` | `#a12318` | `#fbe7e4` | `#f0897c` | `#3a1512` | `overdue`, **exploited** |
| `--neutral` | `#4a5a70` | `#eaeef4` | `#aebccd` | `#22303f` | `awaiting_anchor`, `under_investigation` |
| `--done` | `#3a5578` | `#e7edf6` | `#9db4d4` | `#1d2a3d` | `completed` |

**Exploited** is the single loudest marker in the product — it always uses `--crit`
plus a filled (not outline) pill and a ⚠ glyph, so it out-shouts everything on a busy
Findings table. Nothing else may use a filled critical pill.

---

## 3. Typography

Two roles, both system stacks — no webfonts (honest to the no-build-chain
constraint, and the pragmatic choice for a self-hosted app):

- **UI / body:** `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica
  Neue", Arial, sans-serif`.
- **Data / mono (the character face):** `ui-monospace, "SF Mono", "SFMono-Regular",
  Menlo, Consolas, "Liberation Mono", monospace`. Mono is where the subject's
  vernacular lives — use it for **every** EUVD id, CVE alias, purl, component
  version, SHA-256 audit hash, and countdown timer. Always with
  `font-variant-numeric: tabular-nums` so digits align in columns.

Type scale (rem, 16px base): `0.75 / 0.8125 / 0.875 / 1 / 1.125 / 1.375 / 1.75`.
Body is `0.875`–`1`. Page titles `1.75`, section titles `1.125`. Uppercase labels
(stat-tile captions, table eyebrows) are `0.75` with `letter-spacing: 0.04em` and
`--text-muted`. Give headings `text-wrap: balance`. Keep prose blocks (finding
explanations) to ~65ch max-width even inside a wide page.

---

## 4. Layout shell

```
┌────────────────────────────────────────────────────────────────────┐
│ TOPBAR: ● euvd-watch     [demo-scenario · state as of 12:04 UTC]  ⧉ │  ← --accent-strong ground
├───────────┬────────────────────────────────────────────────────────┤
│ SIDEBAR   │  MAIN                                                    │
│ (fixed)   │  ┌── page title ──────────────────────────────────────┐ │
│           │  │ Overview                                            │ │
│ Overview  │  ├─ stat tiles (summary before detail) ───────────────┤ │
│ Findings  │  │ [ 5 findings ] [ 1 exploited ] [ 1 clock ⚠ ] [ …] │ │
│ CRA events│  ├─ primary content ──────────────────────────────────┤ │
│ Audit log │  │ open CRA clocks · recent findings …                 │ │
│           │  └─────────────────────────────────────────────────────┘ │
│ ───────   │                                                          │
│ signed in │                                                          │
│ as admin  │                                                          │
└───────────┴────────────────────────────────────────────────────────┘
```

- **Sidebar** fixed, ~232px, `--surface`, hairline right border. Four nav items, each
  an icon + label; the active item gets `--accent-tint` background, an `--accent` left
  bar (3px), and `aria-current="page"`. A footer block shows the signed-in user. On
  narrow viewports (< 720px) the sidebar collapses to a top row of nav chips — still
  server-rendered, no JS drawer required.
- **Topbar** `--accent-strong` ground with light text: product mark on the left; on the
  right, the **data-scope chip** (which state dir / scenario) and the **freshness
  stamp** ("state as of HH:MM UTC"). The freshness stamp is load-bearing trust UI —
  it tells the operator how current the read model is.
- **Main** max-width ~1120px, generous `--ground` gutter. Vertical rhythm via a flex
  column with `gap: 1.5rem`; never per-element margins that collapse.

---

## 5. Component library

### 5.1 Stat tile
A `--surface` card: uppercase caption, then a large tabular number, then a one-line
delta/qualifier in `--text-muted`. A tile that represents something needing attention
(exploited > 0, any overdue clock) gets a semantic left stripe and its number in the
semantic fg. Tiles are links to the filtered list they summarize.

### 5.2 Severity stripe + pill
The core status device, used on every findings row, CRA event, and clock.
- **Left stripe:** 3px bar in the semantic color on the row/card's leading edge.
- **Pill:** rounded, tinted background + dark fg + a short label. Outline pill for
  ordinary states; **filled** pill reserved for `overdue` and `exploited`.
- Every pill has a text label; color is never the only signal.

### 5.3 Deadline bar (the countdown)
A horizontal track showing elapsed→deadline progress, the state color as fill, and the
**time remaining in mono** to its right (`23:41:08` counting down, or `+02:11:54`
past due in `--crit`). States:
- `awaiting_anchor` → no bar, `--neutral` pill "Awaiting remediation date" (there is
  genuinely no deadline yet; do not fake a bar).
- `pending` → `--ok` fill.
- `due_soon` (≤ 25% left) → `--warn` fill.
- `overdue` → `--crit` filled bar, remaining time shown as `+HH:MM:SS` overrun.
- `completed` → `--done`, bar replaced by "Completed HH:MM UTC · by <note>".
- Live ticking is **progressive enhancement**: server renders the correct static value;
  a tiny inline-free script may tick the mono readout. Countdowns carry
  `aria-live="polite"` but update no faster than every 30s to avoid screen-reader spam.

### 5.4 Data table (Findings, CRA events)
`--surface`, hairline row dividers, sticky header in `--surface-raised` with uppercase
`--text-muted` headers and `scope="col"`. Leading severity stripe cell. Mono for ids
and versions. Whole row is a link to detail (with a real `<a>`, keyboard-focusable).
**Paginated** — never unbounded (the CLI table gets the matching "… and N more" cap).
Filters render as a labelled `<form>` (GET) above the table: confidence, exploited,
VEX status. Filters are real querystring params so a filtered view is linkable and
back-button-safe.

### 5.5 Definition list / evidence block
Finding detail and audit entries use a two-column definition list (label in
`--text-muted`, value in `--text`/mono). The finding **explanation** renders verbatim
from the store in a `--surface-raised` well, ≤ 65ch — it is the load-bearing
"why did the tool decide this" text and must never be truncated or paraphrased.

### 5.6 Buttons & forms
Primary button: `--accent` ground, white text. Secondary: `--surface` with `--border`
and `--accent` text. Destructive actions do not exist (nothing is deleted). Every
interactive element has a visible `:focus-visible` ring (2px `--accent`, 2px offset).
Write actions ("Mark stage complete") open a small form page/section, never act on
click without confirmation, and are the only place a password-gated POST happens.

---

## 6. The five pages

Demo-scenario data is used throughout below (the committed
`examples/sboms/demo.cdx.json` + seeded exploited record), so the mockup and the tests
share one narrative: **jinja2 3.1.6** matches an **exploited** EUVD record
(`EUVD-DOGFOOD-0001`, alias `CVE-2099-0001`), which fired one CRA event with a running
24-hour clock.

### 6.1 Overview — "what needs my attention, now"
```
Overview
┌ FINDINGS ┐ ┌ EXPLOITED ┐ ┌ OPEN CRA CLOCKS ┐ ┌ AUDIT LOG ┐
│    5     │ │    1  ⚠   │ │   1  ⚠ due soon │ │ ✓ intact  │
│ 2 medium │ │ jinja2    │ │ early warning   │ │ 3 entries │
└──────────┘ └───crit────┘ └─────warn────────┘ └────ok─────┘

OPEN CRA CLOCKS
▎⚠ EUVD-DOGFOOD-0001  jinja2 3.1.6   early warning (24h)  [■■■■■■■□□] 05:41:22 left
                                     vulnerability report (72h) [■■□□□□□□] 53:41:22 left

RECENT FINDINGS                                              [ View all findings → ]
▎⚠ jinja2 3.1.6      EUVD-DOGFOOD-0001  exploited · medium · under investigation
▎  requests 2.31.0   EUVD-2026-1180     medium · under investigation
```
- Four stat tiles first. Any non-zero exploited or any due-soon/overdue clock makes its
  tile semantic and pulls the eye. The **audit-log tile** shows chain integrity
  (`✓ intact` / `✗ broken at entry N`) — a broken chain is a `--crit` filled state.
- "Open CRA clocks" lists only events with a live/overdue stage, each with §5.3 bars.
- "Recent findings" is the top slice of the Findings table, exploited first.
- **Empty state:** "No findings in the current scan. Last matched HH:MM UTC." (calm,
  not celebratory — absence of findings is not a guarantee of safety, and the copy
  must not imply it is).

### 6.2 Findings — the filterable inventory
- Filter form (GET): Confidence (low/medium/high), Exploited (yes/any), VEX status
  (under_investigation/not_affected/affected/fixed). Active filters shown as removable
  chips; a "Clear" link.
- Table columns: ⎸stripe · Component (mono version) · EUVD id (mono) · Aliases (mono,
  truncated with title) · Exploited (⚠ filled pill or —) · Confidence (pill) · VEX
  status (pill) · EPSS (mono %, tabular) · KEV (✓/—).
- Sort default: exploited desc, then confidence desc, then component. Deterministic —
  same data, same order (mirrors the tool's determinism invariant).
- Paginated (e.g. 50/page) with a mono "1–50 of 128" readout.
- **Empty (filtered):** "No findings match these filters. [Clear filters]".

### 6.3 Finding detail — "why did the tool decide this"
- Header: component + version (mono), EUVD id (mono, linking out to the EUVD record),
  and the status pills (exploited / confidence / VEX).
- **Explanation well** (§5.5) verbatim from the store — the single most important block
  on the page.
- Definition list: matching strategy (structured/partial/fuzzy), EUVD title &
  description, affected version range (as EUVD text, not invented purls), EPSS score,
  KEV membership, aliases.
- **VEX status** section: current status + justification; if `under_investigation`,
  show the **decision-shortcut instructions** — the exact `vex-decisions.yaml` snippet
  and CLI command to record a human decision. The UI shows *how*; it does not silently
  set `affected`/`fixed` (those are human calls, per the VEX invariants).
- If this finding fired a CRA event, a link across to §6.4.

### 6.4 CRA events — the reporting clocks
- Table of events: ⎸stripe · EUVD id (mono) · component · first seen (mono UTC) ·
  fired rules (chips: exploited / KEV / EPSS≥threshold) · worst current stage state.
- Event detail: the immutable first-fire record (finding, fired rules, policy
  snapshot, first_seen — all clearly labelled "recorded when the clock started, never
  changed"), then each stage as a §5.3 deadline bar. Per open stage: **"Mark stage
  complete"** (auth-gated POST → `cra mark`) and **"View / copy notification draft"**
  (renders `cra draft`, read-only, with the `TODO-HUMAN` markers highlighted).
- A persistent, unmissable disclaimer banner: *"euvd-watch assists preparation and
  record-keeping. Legal validation and submission to your CSIRT/authority remain your
  responsibility — this tool never files anything."*

### 6.5 Audit log — tamper-evidence made visible
- Top: a big integrity verdict — `✓ Chain intact · 3 entries · verified HH:MM UTC` in
  `--ok`, or `✗ Chain broken at entry N` in `--crit` (filled), naming the first broken
  entry (re-uses `cra/audit.py::verify` — never a reimplemented check). A **Re-verify**
  button re-runs it.
- Below: the append-only entries newest-first, each a card with the action, the
  event/stage it concerns, the UTC timestamp, and — in mono, truncated with a
  copy-to-clipboard affordance — the `entry_hash` and `prev_hash`. Genesis entry
  labelled as such.
- Explain-what-it-means aside: what "tamper-evident" honestly covers and doesn't
  (echoing `docs/cra.md` — a local hash chain can't bind a fully-privileged attacker).

---

## 7. States every page must design

| State | Treatment |
|---|---|
| **Loading** | Server-rendered; effectively none. If a re-verify/POST is slow, disable the button and label it "Verifying…". |
| **Empty** | Page-specific calm copy (see each page). Never celebratory; never implies safety. |
| **Error** | A `--crit` bordered card: what went wrong + how to fix (e.g. "State DB not found at <path>. Run `euvd-watch db migrate` or check `state_dir`."). No stack traces, no apologies. |
| **Stale / partial data** | If the read model is older than the last scan, or a source (EPSS/KEV) was unavailable, a `--warn` banner: "Enrichment data unavailable; EPSS/KEV columns may be blank." |
| **Unauthorized** | 401 with `WWW-Authenticate: Basic` → the browser's own native credential prompt (real HTTP Basic auth, per the engineering contract's "basic auth from config"; there is no custom HTML login page - a 401 response is never shown as a page, browsers intercept it). Username and password are each checked in constant time (`hmac.compare_digest`), never a short-circuiting `==`, so response timing never leaks which one was wrong. |

---

## 8. Accessibility (WCAG 2.1 AA — a hard gate, §6.3)

- Landmarks: `<header>` (topbar), `<nav aria-label="Primary">`, `<main>`; a
  **skip-to-content** link is the first focusable element.
- Full keyboard operability: every link/button/row reachable and operable by keyboard;
  visible `:focus-visible` on all; logical tab order; no keyboard traps.
- Color is never the only signal (§1.2). Contrast ratios from §2 are AA-verified.
- Tables: `<th scope="col">`; captions where a table's purpose isn't obvious from
  context.
- Countdowns: `aria-live="polite"`, throttled ≥ 30s; provide the absolute deadline in
  a `title`/visually-hidden span so a screen reader gets "due 13:04 UTC", not only a
  ticking delta.
- Respect `prefers-reduced-motion` (no ticking animation, just value updates).
- Target size and spacing comfortable for pointer + touch.
- **CI gate:** pa11y (axe engine) against every page rendered with demo data — zero
  serious/critical violations. Manual keyboard-pass checklist in
  `docs/accessibility.md`, executed and dated per release.

---

## 9. Implementation notes for Sonnet

- One template base (`base.html`) with the shell (§4); one `dashboard.css` using the
  §2 tokens; page templates extend base. No inline `style=` and **no inline event
  handlers** (`onclick=` etc.) — the CSP-friendliness test greps for them.
- All display values come **through `web/store.py`** and the existing models — never a
  second query path. Render `Confidence`/`Status`/`ClockState` enum values through a
  single Jinja filter that maps enum → (label, token, pill-variant) so the vocabulary
  lives in one place.
- Determinism holds in the UI too: stable sort orders, no gratuitous timestamps in
  markup (the one freshness stamp is deliberate and labelled).
- Build order matches §6.1→6.5; ship Overview + Findings first (they prove the shell,
  tokens, and read model), then detail/CRA/audit.
- Theme: tokens on `:root`, redefined under `@media (prefers-color-scheme: dark)` and
  again under `:root[data-theme="dark"]/[light]`; a small theme toggle in the topbar
  stamps `data-theme` (progressive enhancement; default follows OS).
- Copy rules (§1.4, §6.4): never a sentence implying the tool submitted, filed, or will
  file anything. Buttons say exactly what they do; confirmations say exactly what
  happened.
```
