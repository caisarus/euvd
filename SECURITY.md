# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public issue.

- **Preferred:** GitHub private vulnerability reporting —
  [Security → Report a vulnerability](https://github.com/caisarus/euvd/security/advisories/new)
  on this repository.
- **Fallback (if you cannot use GitHub):** email
  <cezar.alexandru.vasilescu@gmail.com> with `[euvd-watch security]` in the subject.

You can expect an acknowledgement within **7 days** and a triage decision within
**14 days**. Please include reproduction steps and the version
(`euvd-watch version`) you tested.

## Supported versions

Until `1.0.0`, only the **latest released version** receives security fixes.

## Scope notes

- euvd-watch stores **no secrets** and submits **nothing** anywhere on its own;
  drafted CRA notifications are files a human reviews and submits.
- The audit log is *tamper-evident, not tamper-proof*: its threat model and
  explicit limits are documented in [`docs/cra.md`](docs/cra.md) — attacks it
  does **not** defend against are documented there and are not considered
  vulnerabilities.
- Tier-2 matching sends SBOM-derived product names to the ENISA EUVD API; the
  `tier2_product_search` config toggle disables this for confidential
  inventories (documented data-sharing behaviour, not a vulnerability).
- Findings, VEX statements, and CRA drafts are **decision support**, not legal
  or exploitability guarantees; matching confidence tiers are documented in
  `docs/matching.md`.
