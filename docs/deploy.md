# Self-hosting the dashboard (M6 Step 6.4)

A working Docker Compose deployment: a **watch** service that re-matches your SBOM against
fresh EUVD data on a schedule, a **web** service that serves the read-only dashboard over
that state, and **Caddy** terminating TLS in front. Copy-pasteable example files live in
[`examples/deploy/`](../examples/deploy/); this guide is the walkthrough. Cold-start to a
running dashboard is **under a minute** (well inside the < 15-minute target) — this whole
flow was exercised end-to-end before shipping, including the three deviations its testing
caught and fixed (the image now ships the `[web]` extra, named volumes are writable by the
non-root user, and the local-TLS Caddy block names a host).

## What runs

```
        ┌─────────┐   TLS    ┌──────────┐   HTTP    ┌──────────┐
 you ──►│  caddy  │─────────►│   web    │──────────►│  state   │◄── writes ── watch
        │  :443   │  (edge)  │  :8642   │  (reads)  │  volume  │  (re-match on a schedule)
        └─────────┘          └──────────┘           └──────────┘
```

- **web** binds `0.0.0.0:8642` **inside the container only** — it is never published to the
  host. Caddy on the internal network is the sole ingress and does TLS; the app itself
  stays plain HTTP by design (see `docs/web.md`).
- **watch** and **web** share the state volume and mount the **same SBOM at the same path**
  — the dashboard finds the watch snapshot by a hash of the SBOM's resolved path, so the
  paths must match (both `/work/sbom.cdx.json` in the example).

## Prerequisites

- Docker Engine + the Compose plugin (`docker compose version`).
- The published image that ships the dashboard: `ghcr.io/caisarus/euvd-watch:latest` from
  release **`0.4.0`** onward (the `[web]` extra is baked in). To try it before that release,
  use the `:edge` tag, or build locally with
  `docker build -f docker/Dockerfile -t euvd-watch:local .` and set that image in
  `compose.yaml`.
- The **watch** service needs outbound network to the EUVD API, FIRST.org (EPSS) and
  CISA (KEV). The **web** and **caddy** services do not.
- For real TLS: a DNS name pointing at the host and inbound `80`/`443`. For local/internal
  use, Caddy issues its own certificate (see the Caddyfile).

## Steps

From a working directory (e.g. a copy of `examples/deploy/`):

**1. Generate a dashboard password hash** (the plaintext never touches a file or your
shell history):

```bash
docker run --rm -it ghcr.io/caisarus/euvd-watch:latest web hash-password
```

**2. Write `euvd-watch.yaml`** — copy `euvd-watch.example.yaml` and fill in the hash from
step 1 plus your organization details (used to prefill CRA notification drafts):

```yaml
web:
  username: admin
  password_hash: "pbkdf2_sha256$600000$...."   # from step 1
organization:
  name: "Example S.R.L."
  contact_email: "security@example.com"
  product_name: "Example Product"
```

**3. Provide your SBOM** as `sbom.cdx.json` (CycloneDX or SPDX JSON):

```bash
syft dir:/path/to/your/project -o cyclonedx-json > sbom.cdx.json
```

**4. Set your domain** in `Caddyfile` — replace `euvd.example.com` with your DNS name, or
switch to the commented `localhost { tls internal }` block for a local check.

**5. Start it:**

```bash
docker compose up -d
```

Browse to `https://your-domain/` (or `https://localhost/`) and sign in with the
credentials from step 2. On the very first load — before watch has finished its first
cycle — the dashboard shows a calm "no findings yet, run watch" state; it fills in within
seconds once the first match completes.

## Keeping it fed

- **New release of your product?** Regenerate `sbom.cdx.json` and restart watch so it
  re-matches the new inventory:
  `docker compose restart watch`.
- **CRA events** (the dashboard's countdown clocks) are opened by `cra check`. Run it
  on demand or on a schedule, against the same config and SBOM:
  ```bash
  docker compose run --rm watch --config /work/euvd-watch.yaml cra check /work/sbom.cdx.json
  ```
  Mind its exit codes (`docs/cra.md`): `1` = a new event opened, `3` = indeterminate
  (a required signal source was unavailable). Recording completion of a stage
  (`cra mark`) can be done from the dashboard's CRA event page or the CLI.

## Backups

Two things matter, and they must be backed up **together** (they cross-reference):

- `euvd-watch.sqlite` — the consolidated state DB (CRA events, watch snapshots).
- `cra-audit.jsonl` — the append-only hash-chained audit log.

Both live in the **state volume** (`euvd-watch_state`, mounted at
`/home/euvd/.local/share/euvd-watch`). Two ways to back it up:

**Simplest — a brief pause, fully consistent:**

```bash
mkdir -p backup
docker compose stop watch web
docker run --rm -v euvd-watch_state:/s -v "$PWD/backup:/backup" alpine \
  tar czf "/backup/euvd-state-$(date +%F).tgz" -C /s .
docker compose start watch web
```

**No downtime:** the DB runs in WAL mode, so a plain file copy of the live database can
miss the not-yet-checkpointed WAL tail — use SQLite's online backup (the image has no
`sqlite3` CLI, so drive it through the bundled Python `sqlite3`); the audit log is
append-only, so a plain copy of it is safe:

```bash
mkdir -p backup
docker compose run --rm -v "$PWD/backup:/backup" --entrypoint python web -c \
  "import sqlite3; s=sqlite3.connect('/home/euvd/.local/share/euvd-watch/euvd-watch.sqlite'); d=sqlite3.connect('/backup/euvd-watch.sqlite'); s.backup(d); d.close(); s.close()"
docker run --rm -v euvd-watch_state:/s -v "$PWD/backup:/backup" alpine cp /s/cra-audit.jsonl /backup/
```

See `docs/storage.md` for the full storage model and the WAL-vs-copy caveat. There is no
retention/expiry logic and none is planned — CRA records must outlive the vulnerability.

## Upgrades

```bash
docker compose pull            # fetch the new image
docker compose up -d           # recreate the services
```

Schema migrations run transparently on the next state access (and you can run them
explicitly with `docker compose run --rm watch db migrate`). The audit log and
`vex-decisions.yaml` are never rewritten by an upgrade. Pin a specific tag
(`ghcr.io/caisarus/euvd-watch:0.4.0`) instead of `:latest` if you want reproducible
upgrades.

## Security notes

- TLS is terminated at Caddy; the dashboard app is HTTP on the internal Docker network and
  **must not** be published to the host (no `ports:` on the `web` service).
- Auth is HTTP Basic from the hashed password in config (PBKDF2-HMAC-SHA256). It is a
  single-operator credential designed to sit behind this reverse proxy — see the security
  notes in `docs/web.md` (including the deliberate no-CSRF-token scope for the one write
  action).
- The image runs as a non-root user (uid 1000). Keep the state volume on storage you back
  up; treat `cra-audit.jsonl` as the legal record it is.
