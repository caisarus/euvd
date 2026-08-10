# Web dashboard

Self-hostable, server-rendered read-mostly view over the state store: findings, VEX
statuses, CRA countdowns, the audit log. Implemented in `src/euvd_watch/web/`
(`store.py`, `dashboard.py`, `app.py`) per `plans/implementation_plan.md` Step 6.2 and
`docs/dashboard-design.md` (the visual/interaction spec — read that first if you're
changing anything user-facing).

> **Status: beta.** The whole of M6 is implemented and tested end-to-end: the app and all
> five pages (Step 6.2), the WCAG 2.1 AA accessibility gate (Step 6.3, `docs/accessibility.md`),
> and a tested Docker Compose + Caddy deployment (Step 6.4, `docs/deploy.md`). "Beta" now
> means the surface may still change before the `1.1` GA release — not that pieces are
> missing. For a production deployment, follow `docs/deploy.md`.

## Install

The dashboard needs extra dependencies the core CLI doesn't:

```bash
pip install 'euvd-watch[web]'
```

Without the extra, `euvd-watch web serve` exits `2` with that exact install hint —
the core `euvd-watch` install never pulls in FastAPI/uvicorn.

## Set a password

The dashboard is HTTP Basic auth only — the browser's native credential prompt, not a
custom login page. Every route requires it, including `/static/*`'s CSS is the only
exception. Generate a hash (prompts interactively, hidden input, so the plaintext
password never lands in your shell history):

```bash
euvd-watch web hash-password
```

Put the result in `euvd-watch.yaml`:

```yaml
web:
  username: admin       # default; change if you like
  password_hash: "pbkdf2_sha256$600000$<salt>$<hash>"
```

`web serve` refuses to start without `web.password_hash` set — there is no
"unauthenticated by accident" mode.

## Run it

```bash
euvd-watch watch sbom.cdx.json --once   # populate a findings snapshot first
euvd-watch web serve sbom.cdx.json --host 127.0.0.1 --port 8642
```

The dashboard shows the **stored watch snapshot** for the SBOM you pass — it never
matches live on page load (that would make every page load an EUVD call and defeat
the point of the state store being the read model). If you haven't run `watch` for
that SBOM yet, the Overview and Findings pages show a friendly "no findings yet, run
watch first" state instead of an error.

`--host`/`--port` default to `127.0.0.1:8642`. **Bind only to localhost** and put a
real reverse proxy (Caddy, nginx, Traefik) in front for TLS and any network exposure
— the CLI says so on startup, and it's said again here because it matters. A full
example is in `docs/deploy.md`.

## What's on each page

| Page | Shows | Can you change anything here? |
|---|---|---|
| Overview | Counts, open CRA clocks, recent findings | No |
| Findings | Filterable/paginated inventory of matched findings | No |
| Finding detail | Match explanation (verbatim), EUVD data, VEX status, a **VEX decision-shortcut**: the exact `vex-decisions.yaml` snippet + CLI command to record your own judgment | No — it shows you *how*; it never sets `affected`/`fixed` itself |
| CRA events | Every trigger event and its deadline clocks | **Mark stage complete** / record remediation availability — the one write action, password-gated, logged to the audit trail exactly like `cra mark` |
| Audit log | The hash-chained log, verified on every page load | No — a **Re-verify** control just re-runs the check |

The disclaimer on every CRA-related page is not decoration: *euvd-watch assists
preparation and record-keeping; legal validation and submission to your CSIRT/
authority remain your responsibility.* Nothing in the dashboard, or anywhere else in
this tool, ever files anything externally.

## Security notes

- Password hashing is stdlib PBKDF2-HMAC-SHA256, 600,000 iterations (the 2023 OWASP
  floor), random 16-byte salt per hash. Verification is constant-time
  (`hmac.compare_digest`); a malformed stored hash fails closed.
- No CSRF tokens on the one write form. HTTP Basic credentials aren't cookies, so the
  classic cookie-CSRF exposure doesn't apply the same way, but this is still a
  same-origin-trust simplification appropriate for a single-operator tool behind a
  reverse proxy on a private network — not a public multi-tenant admin panel.
- No inline `style=`/`onclick=` anywhere in the rendered HTML (checked in CI,
  `tests/e2e/test_web_dashboard.py`) — safe to put a strict CSP in front of it at the
  reverse-proxy layer.
