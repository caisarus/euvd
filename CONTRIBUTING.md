# Contributing to euvd-watch

Contributions are very welcome — especially bug reports where the matcher got something
wrong, and EUVD naming quirks you have hit in the wild. This document covers the setup,
the workflow, and the few rules that are not negotiable, with the reasoning behind each.

By contributing you agree that your contribution is licensed under
[EUPL-1.2](LICENSE), like the rest of the project.

## Setup

Python **3.11 or newer**.

```bash
git clone https://github.com/caisarus/euvd.git
cd euvd
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"      # editable install with the dev toolchain
pre-commit install           # ruff, ruff-format and mypy on every commit
```

The dashboard needs one more extra:

```bash
pip install -e ".[dev,web]"
```

## The checks

```bash
pytest                       # full suite; coverage gate is --cov-fail-under=85
pytest tests/unit/test_config.py::test_epss_threshold_negative_is_rejected   # one test
pytest -m unit               # markers: unit, integration, e2e, invariant, slow, live
ruff check .                 # lint (line length 100)
ruff format .                # formatting
mypy src                     # strict mode; must pass with zero errors
```

Two things that surprise people:

- **Running a single test file usually "fails".** The coverage gate applies to whatever
  you ran, so one file yields ~1% coverage and exit code 1. That is the gate, not your
  test. Read the coverage line before believing a red exit.
- **`live` tests are excluded by default** (`-m 'not live'` is in the pytest config). They
  are the only tests that touch the real network, and they run nightly in CI.

## Rules that are not negotiable

These exist because this tool is used as a CI gate and as an input to a legal reporting
duty. A silent failure here is worse than a crash.

**No network in unit, integration, or e2e tests. Ever.** External APIs are replayed from
committed fixtures through `respx`. Fixtures over mocks: a fixture is a real recorded
response, a mock is our belief about one.

**All HTTP goes through `http.py`'s `ApiClient`.** Retry, backoff, caching and logging
live in exactly one place. An invariant test enforces that nothing else imports `httpx`.

**Outputs are deterministic.** Same inputs, byte-identical outputs — stable ordering,
sorted keys, no gratuitous timestamps. Golden-file tests depend on this, and so does the
credibility of an audit trail.

**Nothing may silently suppress a finding.** `not_affected` requires machine-checkable
proof *and* a human-readable explanation; anything uncertain stays
`under_investigation`; `affected` and `fixed` come only from human decisions. When in
doubt, keep the finding alive.

**Confidence caps are hard invariants.** A synthesized identifier can never reach `high`
confidence, and neither can a verdict resting on the fallback version comparator.

**The tool drafts; it never files.** No code path may submit anything anywhere. This is
enforced structurally by INV-8, not by convention — see
[`tests/invariants/test_m5_invariants.py`](tests/invariants/test_m5_invariants.py).

The full list of ten invariants is in [ARCHITECTURE.md](ARCHITECTURE.md), and each one is
an executable test in [`tests/invariants/`](tests/invariants/).

## The truth tables are the project's memory

Three YAML files hold the regression memory:

| File | What it pins |
|---|---|
| `tests/fixtures/matching/cases.yaml` | component × EUVD record → expected outcome and confidence |
| `tests/fixtures/vex/rules-cases.yaml` | finding → expected VEX status |
| `tests/fixtures/cra/trigger-cases.yaml` | signals → does the CRA trigger fire |

**Every wild bug becomes a row *before* its fix merges.** Write the row, watch it fail,
then fix the code and watch it pass. A fix without a row is not finished, because nothing
stops the bug from coming back. Rows are append-mostly — deleting one requires a comment
explaining why the case no longer exists.

## The alias table needs evidence, not intuition

`src/euvd_watch/euvd/aliases.yaml` maps purl coordinates to the vendor and product names
EUVD actually uses. It is powerful: an alias entry can make a match, and it can veto one.

So every new entry must:

1. **cite a real EUVD record id** showing that vendor/product naming, in a comment on the
   entry; and
2. **add a matching truth-table row** proving the entry does what you think it does.

"I'm fairly sure Apache calls it that" is not evidence. A record id is.

## Fixtures and golden files

- **Fixtures** are captured with `scripts/capture_fixtures.py` against the real APIs, then
  committed. Refresh them when the nightly live-smoke reports drift, or quarterly —
  whichever comes first — and always as its own PR, so the behavioural diff is reviewable
  separately from a feature.
- **Golden files** (`tests/fixtures/golden/`) are compared byte for byte. There is no
  auto-update flag: regenerate the file deliberately, and explain the diff in the PR
  description. *A golden update with no explanation is a review blocker* — it is exactly
  how a subtle output regression gets waved through.

## Commits and pull requests

[Conventional Commits](https://www.conventionalcommits.org/), with the types
`feat | fix | refactor | chore | docs | test`:

```
fix(match): a purl namespace must not veto a product-name match
```

Write the body for the person who will read it in a year: what was asked, what changed,
and any side effect or judgement call worth knowing. Skip file lists — the diff has those.
If the change fixes a real defect, say what the concrete failure was and how you verified
it is gone.

For a PR:

- CI must be green (lint, typecheck, tests on 3.11 and 3.12, dogfood, pip-audit, demo).
- New behaviour comes with tests; a bug fix comes with the truth-table row or regression
  test that was red first.
- Documentation is part of the change, not a follow-up. If you altered a command's
  behaviour, the README's command table and the relevant `docs/` page change in the same
  PR.

## Reporting things

- **A vulnerability in euvd-watch itself:** do not open a public issue — follow
  [SECURITY.md](SECURITY.md).
- **A wrong match** (false positive or, worse, a false negative): open an issue with the
  component's purl, the EUVD record id, and what you expected. These are the most valuable
  reports this project can receive, and they usually become a truth-table row.
- **An EUVD API surprise:** the API is beta and its shape does change.
  [docs/euvd-api.md](docs/euvd-api.md) records what was verified and when.

## Good first contributions

- A new alias-table entry for a vendor whose EUVD naming does not match its purl.
- Translating a `GLOSSARY.md` term, or improving the Romanian in
  [GLOSSARY.ro.md](GLOSSARY.ro.md).
- A new notification sink in `watch/sinks.py` — the interface is deliberately a small
  `Protocol`.
- Distro packaging.

## Be decent

Assume good faith, keep criticism about the code, and remember that people reporting
compliance problems are often under real deadline pressure. Behaviour that makes the
project a worse place to contribute is not welcome, whatever its technical merit.
