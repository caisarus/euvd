# EUVD API — verified surface

> Verified live on **2026-07-10** against `https://euvdservices.enisa.europa.eu/api`.
> The API is beta and unauthenticated; everything here may change. When behavior diverges
> from this document, re-verify and update it — `euvd/client.py` and `euvd/models.py`
> encode exactly these findings.

## Endpoints used by euvd-watch

| Endpoint | Method | Behavior |
|---|---|---|
| `/search` | GET | Primary workhorse. Returns `{"items": [...], "total": N}`. Verified params: `text` (full-text incl. descriptions), `product`, `vendor`, `exploited=true`, `page` (0-based), `size` (**hard cap 100** — larger values silently clamp) |
| `/enisaid?id=EUVD-…` | GET | Single record, richer than search items (adds `enisaIdAdvisory`, `enisaIdVulnerability`). **Missing id → HTTP 204 with an empty body** — not 404, not JSON |
| `/lastvulnerabilities` | GET | JSON array of the latest records (~4) |
| `/exploitedvulnerabilities` | GET | JSON array of only the **latest few** exploited records — *not* the full catalog. The full catalog is `search?exploited=true` (total 1,639 on verification day → ~17 pages) |

## Endpoints that do NOT work

| Endpoint | Observed |
|---|---|
| `/vulnerability?id=CVE-…` | **HTTP 403 for every CVE tried** (existing, nonexistent, old, new) — dead or auth-gated. CVE alias lookup is therefore implemented as `search?text=CVE-…` + client-side filtering for an exact match in the record's `aliases` list (full-text search also matches CVE mentions in descriptions, so filtering is mandatory) |

## Record shape quirks (all encoded in `euvd/models.py`)

- **`aliases` and `references` are newline-joined strings**, not arrays
  (`"CVE-2026-56290\nGHSA-gxrr-wfg5-xqqf\n"`). Split on newlines, strip empties.
- **`epss` is on a 0–100 scale** (e.g. `2.91`), unlike FIRST.org's 0–1. Normalized to 0–1
  on ingest so it is comparable with the configured `epss_threshold` and FIRST data.
- **There is no `exploited` boolean.** The presence of `exploitedSince` is the flag.
- **Dates are US-format display strings** (`"Jul 7, 2026, 12:00:00 AM"`). Kept verbatim in
  the model (determinism rule); parsed only where comparison is genuinely needed.
- Affected software is **vendor/product/version-range text**, not purls:
  `enisaIdProduct: [{product: {name, vendor: {name}}, product_version: "1.0.0-6.6.1"}]`.
  Observed `product_version` shapes: `A-B` (hyphen range), `<X`, `<=X`, exact versions,
  and free text. The matcher treats unparseable ranges as "ambiguous" (confidence-capped).
- `id` is the EUVD id (`EUVD-YYYY-NNNNN`); `enisaUuid` also exists but is not used.
- A record without a usable `id` is skipped with a logged warning (hardening rule).

## Transport behavior

- No rate-limit headers observed; no `ETag` (`Cache-Control: no-cache, no-store`). The
  client still sends `If-None-Match` when it has an etag — a no-op today, ready if the
  server ever supports it.
- The client retries 429/5xx with exponential backoff + jitter (max 5 attempts) and
  identifies itself with a `euvd-watch/<version>` User-Agent.
- **`Retry-After` wins over that schedule** (RFC 9110 §10.2.3, both the delay-seconds and
  HTTP-date forms). When the server states a wait, guessing is pointless — and retrying
  sooner than asked just earns another 429. A cooldown longer than 60 s stops the run
  immediately with the requested wait in the message (exit `2`) instead of sleeping
  through it or hammering: a scan that silently hangs for an hour is worse than one that
  fails with a number you can schedule around. An unparseable header is ignored and the
  normal backoff applies — a malformed value must never stop us retrying. Relevant in
  practice: ENISA has been observed returning 429 to shared CI runner IPs during EU
  working hours.
- Responses are cached on disk (SQLite, TTL from `cache_ttl_hours`) so repeated runs and
  tier-2 per-product queries don't hammer the beta service.

## Fixture provenance

`tests/fixtures/euvd/*.json` are real responses captured by `scripts/capture_fixtures.py`
(run manually; see `tests/fixtures/README.md`). Tests replay them through respx and never
hit the network.
