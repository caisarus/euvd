# Getting paid to work on euvd-watch

> Written 2026-08-23 in answer to "I want somewhere where I can be paid to continue to
> work on this". Everything dated was read from the funder's own page that day; anything I
> could not verify is marked.
>
> Read the framing first — it changes which of these is worth your time.

## The framing: grants are not a salary

Almost every open-source funding programme pays **a project against milestones**, not **a
person for their time**. NLnet's €24–45k is real money, but it arrives in tranches against
deliverables over roughly a year, and it does not replace an income.

Only two things on this page are actually "someone pays you to do this work": the
**Sovereign Tech Fellowship**, and **a job at a company in this space**. Everything else
buys runway, credibility and evidence — which is exactly what makes those two reachable.

So: chase the grants because they make you fundable and hireable, and chase the fellowship
and the job because they are the answer to the question you actually asked.

---

## Tier 1 — open now, or already in flight

### 1. GitHub Secure Open Source Fund · **rolling applications** · apply this month

The only one you can act on today, and it is squarely on theme.

- **What:** $10,000 per project, plus three weeks of structured security education, a
  maintainer cohort, Copilot Pro and Azure credits.
- **Paid:** $6,000 during the programme, $2,000 at six months, $2,000 at twelve.
- **Eligibility:** current maintainer of an open-source project with a valid open-source
  licence, located in a region GitHub Sponsors supports. Romania is supported. **This ties
  to runbook step 3** — enabling GitHub Sponsors is on your list anyway and is the
  eligibility gate here.
- **Where:** <https://github.com/open-source/github-secure-open-source-fund>. Applications
  are rolling and considered for all sessions; selected applicants get a virtual interview.
- **Why you specifically:** it funds maintainers to *reduce security risk in their own
  project*. You have already found, fixed and disclosed a false negative in yours. That is
  the exact story the fund exists to reward, and almost nobody applies with it.

**Do this first.** Rolling means no deadline pressure and no reason to wait.

### 2. NLnet CodeSupply · **2026-11-03, 12:00 CEST** · already drafted

€24 000 or €45 000 over roughly twelve months, milestone-paid. Everything is written and
waiting in `plans/funding/nlnet-application.md`; see the runbook for what remains yours.

Not a salary — but at the €24k scope that is meaningful compensation for part-time work,
and an NLnet grant is a credential that makes every later application easier.

---

## Tier 2 — the paths that actually produce an income

### 3. Sovereign Tech Fellowship (Germany) · **the literal answer, and a 2027 target**

This is the programme that pays people to maintain open source. Germany's Sovereign Tech
Agency has put **over €24.6 million into 60+ projects** since 2022, and the Fellowship is
its people-shaped arm:

- **Freelance contracts, 3–12 months, 6–32 hours a week** — i.e. compatible with keeping
  your job — **or fixed-term employment for two years**, full or part time.
- The 2026 cohort was 14 maintainers, community managers and technical writers.

**Two obstacles, both solvable:**

1. **The 2026 round closed on 6 April.** Next round presumably early 2027 — watch
   <https://www.sovereign.tech/programs/fellowship>. *(I could not confirm 2027 dates; the
   FAQ page returned 403.)*
2. **Eligibility requires being a maintainer of or contributor to at least three FOSS
   projects.** You have one.

That second one is the actionable part, and it converges with everything else you are
already doing. Over the winter, make real contributions to two projects that are already
adjacent to euvd-watch:

- **CycloneDX** libraries — you consume their format and have opinions about it.
- **OpenVEX / `vexctl`** — you are a producer for their format.
- **`packageurl-python`** — you depend on it and have hit its edges.
- **OSV-Scanner, Grype or Syft** — a purl/version-range fix from someone who has built a
  matcher is a welcome patch.

These are not busywork. They are the same ecosystem relationships the CodeSupply
application promises to build, and a merged patch in Grype is better evidence for that
promise than any paragraph. **One plan, two payoffs.**

### 4. A job where this *is* the job · **highest certainty, and the timing is unusual**

You have thirteen years of Linux and DevOps, and now a shipped, independently verifiable
tool in a regulatory niche that became legally binding on 11 September 2026. That
combination is rare and it is worth the most right now, while every manufacturer selling
into the EU is working out what Article 14 means.

Categories worth watching, roughly by fit:

- **Supply-chain security vendors:** Anchore, Chainguard, Endor Labs, Sonatype, Snyk,
  JFrog, Aikido, Tidelift.
- **Distributions and platforms with CRA obligations:** Canonical, SUSE, Red Hat, GitLab,
  Docker — several run open-source programme offices that pay people to do exactly this.
- **Foundations:** the Linux Foundation and OpenSSF employ people on supply-chain security
  and CRA readiness directly.
- **European institutions:** ENISA itself, and the Commission's open-source programme
  office. You would be applying with a tool built on their database.

*(I have not checked current openings — that would be stale within a week. This is where to
look, not what is posted.)*

Your application there is not a CV, it is a URL. Most candidates describe experience; you
can hand over a released 1.0.0, 615 tests, published advisories against your own releases,
and the only open documentation of ENISA's API.

### 5. LSEG, internally · **cheapest to explore, and you are already there**

Worth one conversation before any of the above, because it costs an email. LSEG ships
software and lives under DORA-shaped obligations; an internal SBOM-to-obligation capability
has real value to them, and they already employ the person who built one.

Possible shapes: an internal open-source programme office, an innovation or 20%-time
allocation, or simply adopting euvd-watch internally with your maintenance time recognised.

Ask this **before** you publish anything naming LSEG. It is also the conversation in which
you find out their policy on speaking and publishing under your own name, which you need
anyway.

---

## Tier 3 — revenue: slowest to arrive, only one that compounds

The plan already names this and it remains right: **services, not licences.** The tool
stays EUPL and free; you sell time and certainty around it.

- **CRA compliance consulting for SMEs.** The market exists as of 11 September and most
  affected manufacturers are small companies with no compliance function. You are one of
  very few people who can say "I built the tooling" rather than "I read the regulation".
- **Hosted or managed instances** for SMEs that want the watch cycle without self-hosting.
- **Support and assurance contracts** — the thing a manufacturer actually wants is someone
  to call when the clock starts.
- **GitHub Sponsors** — small money, but it is the eligibility gate for Tier 1.1 and it
  signals sustainability on every view of the repository.

The launch-week posts are also your first marketing for this, whether or not you think of
them that way.

---

## Not yet — do not spend time here

- **EU Sovereign Tech Fund.** Proposed, not operating. A feasibility study and a
  parliamentary coalition exist, but it is tied to the EU's **2028–2034** budget
  negotiation. Watch it, do not plan around it.
- **OpenSSF Alpha-Omega.** Funds critical, widely-depended-upon projects. Revisit once
  there is adoption data.
- **Prototype Fund (Germany).** Requires German residency.

---

## What I would actually do, in order

1. **This month:** apply to the GitHub Secure Open Source Fund. Rolling, on theme, and your
   disclosure story is unusually strong. Enable GitHub Sponsors as part of it.
2. **This month:** have the LSEG conversation. It is one email and it unblocks two other
   decisions.
3. **By 3 November:** submit NLnet CodeSupply at the €24k scope.
4. **Over the winter:** land merged contributions in two adjacent projects. This unlocks
   the Sovereign Tech Fellowship, and it is simultaneously the ecosystem work the NLnet
   application promises.
5. **Starting now, not later:** watch the job market in that list. CRA week is the peak of
   demand for what you happen to have.

The realistic outcome is not one big cheque. It is $10k from GitHub, €24k from NLnet, a
fellowship or a job in 2027, and consulting revenue that starts small and grows — with each
one making the next easier to get.
