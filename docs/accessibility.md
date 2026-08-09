# Accessibility (WCAG 2.1 AA, Step 6.3)

The dashboard's automated gate and this checklist together satisfy
`plans/implementation_plan.md` Step 6.3's acceptance criterion: **zero serious/critical
axe violations**, plus a documented, dated manual pass. See `docs/dashboard-design.md`
§1.2/§8 for the design principles this implements (state encoded in form, not color
alone; full keyboard operability; etc.) — this doc is the verification record, not the
spec.

## Automated gate

`scripts/run_a11y_check.sh` seeds the demo scenario exactly like `examples/demo.sh`
(offline, primed cache, no network), serves the real dashboard, and runs
`scripts/a11y_check.mjs` (axe-core via Puppeteer) against all seven distinct pages.
Zero **violations** with `impact: serious|critical` is the gate; CI job `a11y` (on PRs
touching `src/euvd_watch/web/**` plus nightly) runs it and fails the build otherwise.

Run it yourself:

```bash
npm ci                       # once, installs puppeteer + axe-core
pip install -e '.[web]'
./scripts/run_a11y_check.sh
```

### Why not the `pa11y` CLI directly

`scripts/a11y_check.mjs`'s header explains this in full; short version: axe-core
classifies every check as either a **violation** (definite failure) or **incomplete**
(indeterminate — needs a human to look). Pa11y's own axe runner
(`node_modules/pa11y/lib/runners/axe.js`) maps both categories through the same
severity function, so a serious-impact `incomplete` result is indistinguishable from a
real `violation` in pa11y's CLI output. That would make the CI gate permanently red for
a documented tooling limitation (below), not a real defect, so this project's gate
script uses axe-core directly and reports `violations` and `incomplete` separately.

### Known axe `incomplete` results (not gated, verified by hand)

On every page, axe reports `color-contrast` as **incomplete** (not a violation) for:

- The three static sidebar nav icons (`▤ ◈ ◷`) inside `.navlink .ic` spans (the fourth,
  `⛓`, an emoji-rendered glyph, isn't flagged at all — likely rendered by a color-emoji
  font axe doesn't evaluate as plain text).
- The Audit log stat tile's `✓` numeral (`.tile.okt .num`).

Confirmed via `axe.run()` executed directly (not through pa11y) that these are
genuinely in the `incomplete` array, not `violations` — axe's own verdict is "cannot
determine automatically," not "fails." Investigated with `getComputedStyle()`: every
flagged element's own `background-color` is `transparent`, and axe's heuristic for
walking up through transparent ancestor layers to find the *effective* rendered
background doesn't always resolve cleanly through this project's flex-layout nav/tile
structure — a known class of axe-core false-uncertainty, not specific to this project.
Made the ancestor backgrounds explicit anyway (`.navlink` now sets
`background: var(--surface)` directly rather than relying on transparency) as
defensive best practice; it didn't change axe's classification, confirming the
heuristic limit rather than an actual missing-background bug. Screenshot-inspected all
flagged elements: dark text (`#16202e`/`#0f6b46`) on the white card/sidebar surface in
every case — clearly legible, comfortably above 4.5:1 by manual sRGB contrast
calculation. If a future contribution changes these tokens, re-run the check and
re-verify by eye; don't assume `incomplete` always means safe.

### Real defects the gate caught and fixed (2026-08-09)

Both found only by running the actual gate against the real server — neither was
visible from reading the templates:

1. **`link-in-text-block`** (serious): the "This finding fired a CRA reporting event…"
   disclaimer on Finding detail had a link embedded in a sentence, distinguishable
   from the surrounding text only by color (WCAG 1.4.1). Fixed: `.disclaimer a` now
   gets an explicit underline — the one place in the dashboard a link sits inline in
   prose rather than as its own button/nav/heading element.
2. **`scrollable-region-focusable`** (serious): the `<pre class="snippet">` blocks (VEX
   decision snippet, CLI hint, CRA notification draft) can overflow and scroll
   (`overflow-x: auto`) but had no way for a keyboard user to focus and scroll them
   (WCAG 2.1.1). Fixed: `tabindex="0"` on all three.

## Manual keyboard pass

**Executed 2026-08-09** by driving real `Tab`/keyboard input against the live server
with Puppeteer (`page.keyboard.press('Tab')`, inspecting `document.activeElement` after
each press) — a deliberate, scripted walkthrough distinct from the automated axe gate
above, per the test plan's "keyboard-pass checklist... re-executed manually per
release and dated." Re-run this by hand with a real keyboard before each release; the
checklist below is what to verify either way.

- [x] **Skip link is the first Tab stop** on every page, before the topbar/nav —
      verified on Overview and CRA event detail; lands on `<a href="#main">Skip to
      content</a>`.
- [x] **Every focusable element shows a visible focus ring** — confirmed
      `outline: solid 2px #2b5fb3` (the `:focus-visible` accent ring) on every element
      in the tab sequence: skip link, theme toggle, all four nav links, stat tiles,
      form controls, buttons.
- [x] **Tab order is logical** — top-to-bottom, left-to-right, following visual and
      DOM order: skip link → theme toggle → sidebar nav (Overview → Findings → CRA
      events → Audit log) → main content in reading order.
- [x] **The one write form is fully keyboard-operable** — on a CRA event's detail page,
      Tab reaches, in order: the stage `<select>`, the note `<input>`, the remediation
      `<input type="checkbox">`, and the `Record` submit button; all three form controls
      and the button are real native elements (no custom widgets needing extra ARIA).
- [x] **No keyboard traps** — every walkthrough reached the end of the page's tab
      sequence (focus returning to `document.body`) without getting stuck.
- [x] **Countdown live regions don't spam** — `aria-live="polite"` on
      `[data-countdown-seconds]`, ticking client-side JS updates the text node at most
      once/second but `aria-live="polite"` queues rather than interrupts, and
      `prefers-reduced-motion` disables the client-side ticking interval entirely
      (server-rendered value still shown, just not re-ticked in place).
- [x] **Theme toggle keyboard-operable** — a real `<button>`, reachable and activatable
      by keyboard, stamps `data-theme` on `<html>`.
- [x] **Tables have proper headers** — every data table (`Findings`, `CRA events`) uses
      `<th scope="col">`; `Findings` and `CRA events` tables have a
      `<caption class="visually-hidden">` describing sort order for screen-reader users
      (visually redundant given the page heading, but caption is the correct
      accessible-name mechanism for a table whose sort behavior isn't obvious from
      context alone).
- [x] **No inline event handlers or inline styles anywhere** — enforced by both the
      CSP-friendliness regex sweep in `tests/e2e/test_web_dashboard.py` and re-verified
      by grepping every template by hand during this pass.

## Re-running after a template/CSS change

1. `./scripts/run_a11y_check.sh` — must print `OK: zero serious/critical axe
   violations across all pages.`
2. If it introduces a **new** `incomplete` result beyond the ones documented above,
   investigate it the same way this doc did (direct `axe.run()`, `getComputedStyle`,
   screenshot) before assuming it's the same class of false-uncertainty — don't
   silently add it to an "ignore" list.
3. Do the manual keyboard pass above by hand (or via the same Puppeteer-driven
   approach) at least once per release, and update the date on this checklist.
