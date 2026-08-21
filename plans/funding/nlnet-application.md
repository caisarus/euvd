# NLnet application — working draft

> **Status:** draft for the owner. Claude wrote the answers below; the owner is the named
> applicant, edits freely, and submits. Fields marked **[OWNER]** cannot be drafted for
> you — they are about you, not the project.
>
> **Drafted 2026-08-21** against the form and fund pages as they read that day
> (`nlnet.nl/propose`, `nlnet.nl/codesupply`, the 2026-06-12 and 2026-08-03 news posts).
> Re-check the fund page before submitting: CodeSupply's own page still said "the first
> call will open up soon" on the drafting day.

---

## 0. Which fund — this changed since `plans/next_steps_plan.md` was written

`next_steps_plan.md` §Phase 5 names **NGI Zero Commons Fund** as the primary target and
says calls run "roughly every two months". Both facts are now stale, and one of them is
stale in our favour:

- **NGI Zero Commons Fund is finished.** Its thirteenth and final call closed
  **2026-06-01**. NLnet paused open calls on 2026-06-12 while transitioning from NGI to
  the **Open Internet Stack**.
- **Three successor programmes open 2026-09-03**, first deadline **2026-11-03, 12:00
  CEST**: *Restack* (the general bottom-up FOSS successor to NGI Zero), **CodeSupply**,
  and *ELFA* (encrypted local-first architecture — not us).
- The cadence also shifted: deadlines are now the **third day of every odd month**
  (Jan/Mar/May/Jul/Sep/Nov), moved off the even months to dodge summer holidays and
  FOSDEM.

**Apply to CodeSupply, not Restack.** CodeSupply exists specifically to fund
*software supply chain* tooling — €400 000 reserved for open calls, grants of
**€5 000–€50 000** — and states three objectives:

1. publish current, correct, and comprehensive **software metadata**;
2. establish a scalable, sustainable mechanism for **democratic access to data sets**;
3. create a **foundational framework** for future iterations and new data sets.

euvd-watch sits on objective 1 and 2 almost word for word, and the work programme below
is deliberately shaped so that the *data set we produce* — a public, versioned mapping
between EUVD's free-text affected-software entries and package identifiers — is a
deliverable in its own right, not a side effect of a CLI tool. That framing is what makes
this a CodeSupply proposal rather than a generic Restack one.

Restack stays as the fallback if CodeSupply's first call slips or is scoped narrower than
its page suggests; the answers below need only the abstract and the budget re-pointed.

---

## 1. Contact information

- **Your name:** [OWNER]
- **Email address:** [OWNER]
- **Phone number:** [OWNER]
- **Organisation:** [OWNER — natural persons are eligible; leave blank or state
  "independent developer" if there is no legal entity. Do not invent one.]
- **Country:** [OWNER]
- **PGP pubkey (optional):** [OWNER]

## 2. Proposal name

**euvd-watch — European vulnerability data, usable by machines**

> Alternatives, if you prefer the compliance angle over the data angle:
> "euvd-watch — EUVD-native supply-chain watch and CRA Article 14 reporting", or simply
> "euvd-watch". The data-first title is chosen to match CodeSupply's objectives; the
> compliance angle is still the second paragraph of the abstract either way.

## 3. Website / wiki

`https://github.com/caisarus/euvd`

> Should be the documentation site once Phase 4.1 (MkDocs on GitHub Pages) is live —
> a docs site reads better to a reviewer than a repo root. Not a blocker.

## 4. Abstract

> *Can you explain the whole project and its expected outcome(s).*
> NLnet asks for something concise; this is ~1 500 characters. Keep it tight — the
> detail belongs in the budget and challenges answers.

The EU now runs its own vulnerability database. ENISA's European Union Vulnerability
Database (EUVD) went live in 2025 and carries data the American sources do not,
including an *actively exploited* flag. But EUVD describes affected software the way
humans write it — vendor name, product name, a version range as free text — while every
SBOM in existence identifies software by package URL. Nothing bridges the two, so
Europe's own vulnerability data is effectively unreadable by the tools European
developers actually run.

euvd-watch is a self-hostable toolkit that closes that gap. It ingests an SBOM
(CycloneDX or SPDX), matches every component against EUVD with an explicit confidence
model, drafts conservative OpenVEX statements to suppress genuine false positives, and —
when a component is hit by an actively exploited vulnerability — drafts the EU Cyber
Resilience Act Article 14 notification and starts the 24-hour clock against a
tamper-evident audit log. It never submits anything; a human always files.

Version 1.0.0 is released under EUPL-1.2 (PyPI, container image, GitHub Action), with
611 tests and a WCAG 2.1 AA dashboard.

The requested work turns the private bridge inside that tool into public infrastructure:
a versioned, openly licensed **EUVD-to-package-identifier mapping data set** with a
transparent curation pipeline and a measured accuracy harness, so that any scanner — not
only ours — can consume EUVD correctly. Expected outcomes: the published data set and its
API, a measurably lower false-negative rate on EUVD matching, distribution packages, and
documented upstream feedback to ENISA on the beta API.

## 5. Have you been involved with projects or organisations relevant to this project before?

**[OWNER]** — only you can answer this, and NLnet reads it closely. Material worth
including if it is true of you: prior open-source maintenance or contributions (link
them), any professional work in security, compliance, SBOM or vulnerability management,
and involvement in relevant communities (OWASP chapters, DefCamp, CycloneDX, OpenSSF).

If euvd-watch is your first substantial open-source project, say so plainly and point at
the artefact instead of the CV — it is a stronger answer than padding. Concrete things
you can point to, all verifiable in the repository:

- a 1.0.0 release shipped to PyPI and GHCR under EUPL-1.2, with a documented stability
  contract and a reproducible release pipeline;
- 611 tests at 94.5 % coverage, mypy-strict, with ten machine-checked invariants
  (including "nothing is ever submitted automatically", enforced by AST tests over the
  package source, not by policy);
- a documented security process: two advisories drafted for defects we found in our own
  shipped releases, and a fix released before disclosure;
- `docs/euvd-api.md` — a written, dated record of the EUVD beta API's real behaviour
  (undocumented endpoints, a hard page-size cap, newline-joined "arrays", EPSS on a
  0–100 scale, HTTP 204 for a missing record), which is the kind of upstream fieldwork
  this proposal proposes to formalise.

## 6. Requested amount

**€45 000**

> See the note at the end of §7 for a €24 000 reduced-scope variant. Pick one before
> submitting — do not submit both.

## 7. Explain what the requested budget will be used for

> *Does the project have other funding sources, both past and present? A breakdown in
> the main tasks with associated effort is appreciated. Make rates explicit.*

**Other funding: none.** The project has received no grants, no sponsorship and no
commercial revenue, past or present. All work to date (M0–M6, releases 0.1.0 through
1.0.0) was unpaid. GitHub Sponsors is not yet enabled. If that changes before
submission, update this paragraph — NLnet asks directly and the answer must stay true.

**Rate: €60 per hour**, one developer, no overhead or subcontracting. 750 hours over
twelve months (roughly 15 h/week alongside other work — deliberately not a full-time
plan, so the schedule survives a bad month).

| # | Task | Hours | Cost |
|---|---|---|---|
| A | **Public EUVD↔package-identifier data set.** Extract the mapping now buried in `euvd/aliases.yaml` into a standalone, versioned, openly licensed data set with a published schema and a stable download; build the curation pipeline (proposal → evidence from real EUVD records → review → release) and the contribution path that lets other tools' users file mappings. | 160 | €9 600 |
| B | **Matching accuracy, measured.** A per-ecosystem version-range comparator (today a single fallback comparator handles ranges EUVD publishes as free text) and an accuracy harness that scores matching against a labelled corpus, so "we improved recall" becomes a number in CI rather than a claim. Every regression enters the truth table before its fix. | 140 | €8 400 |
| C | **Dashboard 1.1 GA.** Promote the beta dashboard to a stable, documented surface: multi-SBOM projects, the VEX decision workflow end-to-end in the browser, and a repeat WCAG 2.1 AA audit including a manual screen-reader pass. | 120 | €7 200 |
| D | **EUVD API resilience and upstream feedback.** Harden the client against a beta service (pagination under rate limiting, schema drift detection, a public conformance report), and work the findings into structured feedback to ENISA — the relationship with the data provider is part of the deliverable. | 80 | €4 800 |
| E | **Distribution.** Debian and Fedora packaging plus a Nix flake, and signed, provenance-attested releases (SBOM and attestation for our own artefacts — a supply-chain tool that cannot prove its own supply chain is not credible). | 90 | €5 400 |
| F | **Documentation and reach.** Documentation site, an SME-facing CRA onboarding guide, and translation of the user-facing docs and glossary beyond the existing English and Romanian. | 70 | €4 200 |
| G | **Security process and maintenance.** Coordinated disclosure handling, dependency and advisory response, issue triage, and release engineering across the grant period. | 90 | €5 400 |
| | **Total** | **750** | **€45 000** |

Everything produced stays under EUPL-1.2 (code) and an open data licence for the data
set (CC0 or CC-BY-4.0 — CC0 preferred, so that other scanners can absorb the mapping
without a licence conversation).

> **Reduced-scope variant (€24 000, 400 hours)** — if you would rather ask for less on a
> first application: tasks **A** (160 h), **B** (140 h), **D** (80 h) and a trimmed **G**
> (20 h). That keeps the data set, the measured accuracy and the ENISA work — i.e. the
> whole CodeSupply-shaped core — and drops the dashboard, packaging and translation,
> which are the parts that most plausibly happen unfunded anyway. A smaller, entirely
> on-theme ask is usually the stronger one.

## 8. Compare your own project with existing or historical efforts

**Be accurate and generous here. Never disparage — most of these are tools we depend on
or would happily be replaced by.**

*SBOM generation* is a solved problem we do not touch: **Syft**, **cdxgen** and
**Trivy**'s generator produce our input, and euvd-watch reuses them rather than competing.

*Scanning against US-hosted data* is mature and well engineered. **Trivy**, **Grype** and
**OSV-Scanner** match components against NVD, GitHub Security Advisories and OSV.dev, and
do it faster and across more ecosystems than we do. **Dependency-Track** (OWASP) is the
established platform for continuous SBOM monitoring at organisational scale, with a
component inventory and policy engine far beyond ours.

Two gaps separate this project from all of them, and neither is a quality judgement:

1. **None of them read the EUVD.** Europe's own vulnerability database, operated by
   ENISA, carries an actively-exploited flag and records that are not always mirrored in
   the US sources — and no open scanner consumes it, because doing so requires solving
   the identity problem in Task A rather than reading a purl out of a JSON field. A
   European organisation that wants to check its software against European vulnerability
   data currently has no open tool that does it. This proposal's data set is aimed
   precisely at making that a solved problem *for every tool*, including the four named
   above. Success looks like Trivy or OSV-Scanner consuming our mapping.
2. **None of them touch the reporting duty.** The CRA's Article 14 obligation — a
   24-hour early warning to ENISA and the national CSIRT when an actively exploited
   vulnerability is found in your product, then a 72-hour follow-up — becomes applicable
   on **2026-09-11**. Scanners tell you what is vulnerable. They do not tell you that a
   legal clock has started, draft the notification, or leave a tamper-evident record of
   who decided what and when. euvd-watch does exactly that, and deliberately stops short
   of submitting: it drafts, a human files.

*Adjacent and complementary:* **OpenVEX** and `vexctl` define and manipulate the VEX
statements we emit — we are a producer for their format, not an alternative to it.
**CSAF/VEX** tooling from the German BSI covers the same suppression problem with a
heavier document standard; supporting CSAF output is a plausible future contribution
rather than a competing claim. **OpenSSF Scorecard** and **in-toto/SLSA** address
producer-side supply-chain integrity, an orthogonal axis to consumer-side vulnerability
matching.

*Historically:* the closest ancestor is **OWASP Dependency-Check** (2012–), which
pioneered CPE-based matching from build artefacts and hit exactly the identity problem
this proposal addresses — CPE-to-package matching produced enough false positives to
become the standard complaint about it. The industry's answer was to move to purls and
purl-native databases (OSV). EUVD, being CVE-derived, is still on the vendor/product/CPE
side of that divide, which is why the bridge has to be built rather than assumed.

## 9. What are significant technical challenges you expect to solve during the project?

1. **Identity across two vocabularies, without silent false negatives.** EUVD says
   `(vendor: "python-pillow", product: "pillow", version: "1.0.0-6.6.1")`; the SBOM says
   `pkg:pypi/pillow@9.0.0`. Neither side is normalised and neither is authoritative. Our
   current answer is a four-tier candidate derivation (CPE fields → curated alias table →
   purl namespace → bare name) with a confidence ceiling per tier, guarded by a truth
   table that every historical bug is added to before its fix merges. The hard part is not
   matching more; it is **never dropping a real finding while matching more** — a
   false-positive costs a human five minutes, a false negative costs an unreported
   exploited vulnerability. We shipped 0.4.1 precisely because an inverted version range
   was being read as "provably safe", and the fix's regression test is now a row in that
   table. Scaling a hand-curated table of a few dozen entries to ecosystem coverage,
   without lowering that bar, is Task A and B's real content.

2. **Version-range comparison with no declared scheme.** EUVD publishes ranges as text —
   `A-B`, `<X`, `<=X`, an exact version, or prose — with no statement of which ordering
   applies. PEP 440, semver, Debian's `dpkg --compare-versions` and RPM's EVR disagree on
   real inputs (`1.0.0-2` is a Debian revision and a semver pre-release, and they order
   differently). The invariant we hold is that the fallback comparator may **never**
   produce high confidence, and an unevaluable range is ambiguous — kept for a human, not
   discarded.

3. **Automated VEX that is safe to trust.** `not_affected` is only emitted with
   machine-checkable proof and a written justification; everything uncertain stays
   `under_investigation`; `affected` and `fixed` come only from recorded human decisions.
   No code path may silently suppress a finding — this is an invariant with a test, not a
   guideline.

4. **Evidence that survives scrutiny.** CRA notifications are regulatory artefacts, so
   the audit log is append-only and hash-chained, and outputs are byte-for-byte
   deterministic (stable ordering, no gratuitous timestamps) so that any run can be
   reproduced and diffed. Determinism is enforced by golden-file tests.

5. **Depending on a beta service.** The EUVD API is unauthenticated and beta: undocumented
   endpoints, one that returns HTTP 403 for every input tried, a page-size cap that
   silently clamps, "arrays" that are newline-joined strings, EPSS on a different scale
   than FIRST.org's, and 429s to shared CI runner addresses during EU working hours. A
   nightly live-smoke job exists to detect drift. Task D turns this from defensive coding
   into a published conformance report and structured feedback upstream.

## 10. Describe the ecosystem of the project, and how you will engage with relevant actors and promote the outcomes

**Users.** European manufacturers of products with digital elements — overwhelmingly SMEs
— who acquire an Article 14 reporting duty on 2026-09-11 and have no in-house compliance
function. Also their CI/CD engineers, who meet the tool as a GitHub Action or GitLab
template rather than as a compliance product. Self-hosting is a requirement, not a
preference: an SBOM is a disclosure of your entire attack surface, and the tool is built
so that it never has to leave your infrastructure.

**Data providers.** **ENISA** operates the EUVD and is the actor whose data quality
determines this project's ceiling. `docs/euvd-api.md` is already a dated record of the
beta API's real behaviour; Task D converts it into structured feedback and a public
conformance report. This is the engagement that matters most, and it runs in both
directions: better EUVD metadata makes every downstream tool better, which is CodeSupply
objective 1 stated from the other end.

**Standards and peer projects.** CycloneDX and SPDX (input formats), OpenVEX (output
format, via the OpenSSF working group), and the scanner projects named in §8 — the
explicit goal of the Task A data set is that they consume it. We will bring it to the
**OpenSSF** SBOM Everywhere and Vulnerability Disclosure working groups, and to the
CycloneDX community, as a data contribution rather than a tool announcement.

**National CSIRTs and regulators.** The recipients of the notifications the tool drafts.
Engagement here is about the *format* of the draft matching what they actually want to
receive; the CRA stage configuration is deliberately config rather than code so it can
track guidance without a release.

**Distributions.** Debian and Fedora packagers (Task E) — for a compliance tool, being
installable from the OS repository is a trust signal an SME cannot get from `pip`.

**Promotion.** Documentation site and a Zenodo DOI for citability; an honest comparison
page (the substance of §8) rather than a marketing page; conference talks where the
audience is the user — DefCamp (Bucharest), FOSDEM's security devroom, OWASP chapters;
and submissions to the relevant awesome-lists. The CRA applicability date itself will
generate attention in September 2026; the outreach is timed to it, with the tool already
released rather than announced.

**Governance and sustainability.** EUPL-1.2, the European public licence, chosen
deliberately for a European compliance tool. Contribution is designed so that users
become curators: the EUVD-data-mismatch issue template feeds the alias table and the
truth tables directly, which is the mechanism by which the Task A data set can outgrow
one maintainer. Beyond the grant, the sustainability model is services (support and CRA
consulting) around a tool that stays fully open — never a licence change.

## 11. Attachments

Suggested, all ≤50 MB, in accepted formats (HTML, PDF, ODF, plain text):

- `docs/euvd-api.md` as PDF — the strongest single piece of evidence that this work is
  grounded in the real data source rather than in a proposal.
- `docs/matching.md` as PDF — the confidence model and its invariants.
- Optionally the asciinema cast rendered to an HTML page (Phase 4.2) — a reviewer who
  can watch the tool work in 90 seconds is worth several paragraphs.

Do **not** attach the whole repository; link it.

## 12. Generative AI disclosure — read this before submitting

NLnet's form now asks, as required fields:

- *Did you use generative AI in writing this proposal?* → **Yes.** Answer honestly; this
  file was drafted by Claude (Anthropic) in Claude Code on 2026-08-21.
- *Which model did you use? What did you use it for?* → The form asks for **dates,
  prompts, and unedited output**. Suggested answer, to be adjusted to whatever you
  actually change below:

  > Claude Opus 5 (Anthropic), via Claude Code, on 2026-08-21. The maintainer asked it to
  > research the current NLnet call structure and draft answers to the application form
  > from the project's own repository, plans and documentation. Sections about the
  > applicant personally, the requested amount, and the final wording were written or
  > revised by the maintainer. The unedited draft is attached, together with the prompt
  > that produced it.

- *Optional files containing prompts* → attach this file as generated (keep an
  unmodified copy before you start editing — `git show` of the commit that introduced it
  is exactly that) plus the session prompt.

**Keep an unedited copy.** The commit that adds this file to the repository is the
unedited output; edit in later commits so the original stays retrievable.

---

## Pre-submission checklist

- [ ] CodeSupply's call is confirmed open (its page said "coming soon" on 2026-08-21) —
      otherwise apply to **Restack** and re-point the abstract and budget.
- [ ] Fill every **[OWNER]** field; answer §5 yourself.
- [ ] Choose the €45 000 or the €24 000 scope; delete the other.
- [ ] Re-check the "other funding sources" paragraph in §7 is still true (GitHub Sponsors,
      any sponsorship, any revenue).
- [ ] Documentation site live, so §3 can point at docs rather than a repo (Phase 4.1).
- [ ] README's "work in progress / may change until 1.0.0" banner removed — a reviewer
      who follows the link must not read that the project is pre-1.0 (fixed 2026-08-21).
- [ ] Generative-AI disclosure completed with the real prompts and the unedited draft.
- [ ] Deadline: **2026-11-03, 12:00 CEST**. Submit days early; NLnet does not extend.
