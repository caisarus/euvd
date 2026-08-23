# DefCamp 2026 — talk submission draft

> **Deadline: wave #2, 2026-08-30** (waves: 15 Jun / **30 Aug** / 15 Oct; def.camp states
> selection is first-in-first-out, so wave 2 beats wave 3). Conference **19–20 November
> 2026, Bucharest**. Submit at <https://sessionize.com/defcamp-2026/>.
>
> Drafted 2026-08-23. **[OWNER]** marks what the agent cannot write — the bio is about you.
> The exact Sessionize fields sit behind their login wall; everything DefCamp is known to
> ask for is below, so it should be paste-and-go.

## Form values

| Field | Value |
| --- | --- |
| **Track** | Web, Software & Infrastructure Security — it is the track that explicitly lists *supply chain security* |
| **Alternate track** | Governance, Compliance & Business Strategy — it lists *regulatory landscape* and *sovereign tech*. Pick this one **only** if you would rather give the compliance talk than the engineering talk; the abstract below is written for the engineering track. |
| **Level (100–400)** | **300.** Their guidance: "Target 300-400 level technical content; 100 and 200 level content is in low demand." This talk earns 300 on the version-comparison and matching internals — do not undersell it as 200. |
| **Length** | 45 min if offered; the outline collapses to 30 by cutting section 5. |

## Title

> **Provably Safe: EUVD, the CRA Clock, and the False Negative I Shipped**

Alternates, if the committee or you prefer a different emphasis:

- *Reading Europe's Own Vulnerability Database* — softer, more inviting, less memorable.
- *No Findings, Exit Code 0* — the punchiest, but it hides the EU angle that makes the
  talk unique at a CEE conference.

## Abstract (submit this)

Since 11 September 2026, Article 14 of the EU Cyber Resilience Act has been running a
clock: find an actively exploited vulnerability in your product, and you have 24 hours to
warn ENISA and your national CSIRT, then 72 hours to follow up. ENISA also operates the
EU's own vulnerability database — the EUVD — which carries an *actively exploited* flag
and records the American sources do not always mirror.

Almost nothing open reads it. Not because nobody wants to, but because the EUVD describes
affected software the way humans write it — a vendor name, a product name, a version range
as free text — while every SBOM ever generated identifies software by package URL. Nobody
built the bridge, so Europe's own vulnerability data is effectively unreadable by the tools
European developers actually run.

I spent a year building that bridge in the open, and this talk is what I found. The real
behaviour of the EUVD API, documented from the wire: an endpoint that returns 403 for every
input tried, a page-size cap that silently clamps, "arrays" that are newline-joined strings,
EPSS on a 0–100 scale instead of FIRST.org's 0–1, and no `exploited` boolean at all. The
identity problem underneath it, and why matching on product name while ignoring vendor is
how scanners quietly lie to you.

Then the part I would rather not present. My own version comparator read an inverted range
as *provably outside* and reported **no findings, exit code 0**, at high confidence, for a
component sitting on exactly the affected version. It shipped. I found it in a pre-1.0
audit, fixed it, and disclosed it against my own releases.

You will leave knowing how to query the EUVD yourself, what to test in whatever scanner you
already run, and why a security tool must be built so that uncertainty degrades to "a human
should look at this" and never to "you are clean".

## Short version (~90 words, if a field is capped)

The EU Cyber Resilience Act has been running a 24-hour reporting clock since 11 September,
and ENISA operates the EU's own vulnerability database to go with it — carrying an actively
exploited flag, and read by almost no open tooling. The reason is an identity problem: the
EUVD speaks vendor, product and free-text version ranges; every SBOM speaks package URLs.
This talk is a year of building that bridge in the open: the EUVD API's real behaviour, the
matching internals, and the false negative I shipped and disclosed — a scanner reporting
"no findings, exit code 0" for a component on exactly the affected version.

## Outline (organiser notes / 45 min)

1. **The clock (5 min).** What Article 14 actually obliges, who it binds, and the detail
   everyone misses: the trigger is *actively exploited*, not *critical*. Where the 24 and
   72 hour stages come from, and why they belong in config rather than in code.
2. **The database nobody reads (7 min).** What the EUVD is, what it carries that NVD and
   OSV do not, and a live query. Why "just use the API" ends the moment you look at a
   record.
3. **Field notes from a beta API (8 min).** Verified behaviour, on the wire: `/vulnerability`
   403s for every CVE tried; `size` silently clamps at 100; `aliases` and `references` are
   newline-joined strings; `epss` is 0–100; there is no `exploited` boolean, only the
   presence of `exploitedSince`; a missing record is HTTP 204 with an empty body, not 404;
   dates are US display strings. Each one is a bug in your client if you assume otherwise.
4. **The identity problem (10 min).** Bridging `(vendor, product, version-range)` text to
   `pkg:pypi/pillow@9.0.0`. A four-tier candidate derivation — CPE fields, a curated alias
   table, purl namespace, bare name — with a hard confidence ceiling per tier. Why informed
   candidates must be decisive: a vendor-less fallback that resurrects a match the known
   vendor already contradicted is how you generate noise nobody trusts.
5. **Versions, where it actually breaks (8 min).** EUVD publishes ranges as text with no
   declared scheme. `1.0.0-2` is a Debian revision *and* a semver pre-release, and they
   order differently. PEP 440, semver, dpkg and RPM EVR disagree on real inputs. Then the
   confession: an inverted range read as "provably outside", scoring **high** confidence,
   producing no finding and exit code 0 for a component on exactly the affected version.
   Shipped in `0.4.0`. Found in audit, fixed in `0.4.1`, disclosed against my own releases.
6. **Building so it fails safe (5 min).** A false positive costs a human five minutes; a
   false negative costs an unreported exploited vulnerability, and now a missed legal
   deadline. Confidence caps as hard invariants rather than guidelines. Conservative VEX:
   `not_affected` only with machine-checkable proof. A truth table as regression memory —
   every wild bug becomes a row *before* its fix merges. And the invariant enforced by
   tests over the source: the tool drafts the notification, and never files it.
7. **What you can do on Monday (2 min).** Query the EUVD yourself. Three tests to run
   against whatever scanner you already have. Where the code and the API notes live.

## Takeaways

- How to query the EUVD directly, and what its records actually contain.
- Why matching SBOM components to CVE-derived advisories is an unsolved identity problem,
  and the specific ways it fails silently.
- Three checks to run against your existing scanner before you trust its exit code.
- What CRA Article 14 obliges, when the clock starts, and what "actively exploited" means
  in practice.

## Prerequisites / audience

Developers, DevSecOps and product security engineers who run SBOM scanning in CI, and
anyone at a manufacturer that now carries a CRA reporting duty. Familiarity with SBOMs and
CVEs helps; no EUVD knowledge assumed.

## Materials offered (def.camp: "White paper and/or slides are a plus")

- Slides, released with the talk.
- The tool itself, EUPL-1.2, released and on PyPI — including the API notes and the
  matching-strategy document the talk draws on, both written before the talk existed.
- Two published security advisories against my own earlier releases.

## Bio — **[OWNER], you must write this**

The agent will not invent biography. Keep it to 60–90 words, first or third person as you
prefer, and use the artefacts rather than titles if this is your first conference talk —
"maintainer of an EUPL-licensed CRA reporting toolkit, released 1.0.0 in August 2026,
disclosed two advisories against his own releases" is a stronger opening than any job title.
Sessionize will also want a photo, and DefCamp covers travel.

## Before you submit — two honesty checks

1. **"Almost nothing open reads it."** True as far as we have checked, and the repo has
   made this claim since the README was written — but it is exactly the sentence an
   audience member will challenge from the floor, and the ecosystem may move before
   November. Re-verify against Trivy, Grype, OSV-Scanner and Dependency-Track before the
   talk, and soften to "no mainstream open scanner I have found" if anything has changed.
2. **The confession is the strongest part of this submission — do not cut it.** A speaker
   who shipped a false negative in a security tool, found it, disclosed it against their
   own releases and can explain the class of bug is far more interesting than one
   presenting a working tool. It is also the reason the talk is 300-level rather than a
   product walkthrough.
