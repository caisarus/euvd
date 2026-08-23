# Launch posts — drafted for the CRA Article 14 week

> Drafted 2026-08-23 for posting around **2026-09-11**, the day CRA Article 14 becomes
> applicable. **The owner posts. Every one of these.** Nothing here is submitted by the
> agent — the project's own principle applied to the project.
>
> **Rules I could not verify:** Reddit blocks automated fetching and the subreddit rule
> pages are not indexed, so the r/Python and r/netsec formats below are written from
> well-established community convention, **not** from today's sidebar. Read the live
> sidebar of each subreddit before posting. A removed post wastes the news cycle, and the
> news cycle is the whole point of the timing.

## Timing

**11 September is a Friday** — the worst day of the week to post a Show HN. Split it:

| When | Where |
| --- | --- |
| **Fri 11 Sep**, morning CEST | Mastodon, LinkedIn, r/devops — ride the day the obligation lands |
| **Fri 11 Sep** or the weekend | r/netsec, once the write-up has a real URL (see below) |
| **Tue 15 Sep**, ~14:00–16:00 UTC | **Show HN** — weekday US morning, the standard window |
| Following week | r/Python, deliberately separated so it does not read as a blast |

Block out the day you post to Hacker News. A Show HN where the author answers every comment
for eight hours does far better than a better project posted and abandoned.

---

## 1. Show HN

**Submit:** the GitHub repository URL. **Title** (74 chars, no trailing period):

> `Show HN: Euvd-watch – SBOM scanning against the EU's vulnerability database`

Alternate, if you would rather lead with the regulation than the data source:

> `Show HN: Euvd-watch – open-source CRA Article 14 reporting from your SBOM`

**Then immediately post this as the first comment.** This is the convention on Show HN, and
it is where the actual pitch goes:

> Author here. This started because the EU built its own vulnerability database — ENISA's
> EUVD — and I could not find an open tool that reads it.
>
> The reason turned out to be more interesting than I expected. EUVD is CVE-derived, so it
> describes affected software the way a human writes it: a vendor name, a product name, and
> a version range as free text. Every SBOM identifies software by package URL. Nobody built
> the bridge, so the EU's own vulnerability data is largely unreadable by the tools people
> actually run in CI.
>
> euvd-watch ingests a CycloneDX or SPDX SBOM, matches components against EUVD with an
> explicit confidence model, drafts conservative OpenVEX statements, and — when something
> is flagged actively exploited — drafts the CRA Article 14 notification and starts the
> 24-hour clock against a hash-chained audit log. It drafts. It never files anything; a
> human always does that.
>
> Two things I would rather say up front than have found:
>
> The matching is the hard part and it is not solved. Confidence is capped per evidence
> tier, an unevaluable version range stays "a human should look at this" rather than
> becoming "clean", and every bug I have hit is a row in a truth table that runs in CI. I
> shipped a false negative earlier this year: an inverted range read as provably-outside at
> high confidence, so the tool reported no findings and exited 0 for a component sitting on
> exactly the affected version. I found it in a pre-1.0 audit, fixed it, and published
> advisories against my own releases.
>
> The EUVD API is beta and it shows: an endpoint that 403s for every input I tried, a page
> size that silently clamps at 100, "arrays" that are newline-joined strings, EPSS on a
> 0–100 scale, and no `exploited` boolean at all — the presence of `exploitedSince` is the
> flag. All of it is documented in docs/euvd-api.md, from the wire.
>
> `pip install euvd-watch`. EUPL-1.2. I would especially like to hear from anyone who has
> tried to match SBOM components to CVE-derived advisories and knows where this breaks.

**Do not** edit the post to add "EDIT: thanks for the upvotes". Answer questions instead.

---

## 2. r/netsec

**This one is gated.** r/netsec's whole culture is that the submission must be the
technical content, not the project — a GitHub link reads as an advert and gets downvoted by
regulars. The submission is therefore the **EUVD API write-up**, which needs to exist at a
real URL that is not a repository file.

> **Blocks this post:** the MkDocs documentation site (Phase 4.1). It is on my list as
> "non-blocking" — it is not; it blocks the strongest post of the week. Say the word and I
> will build it before 11 September.

**Title:**

> `Field notes from ENISA's EU Vulnerability Database API: what actually comes back on the wire`

**Body** — keep it to a couple of sentences; the content is the link:

> The EU's own vulnerability database has been live since 2025 and carries an
> actively-exploited flag, but the API is beta and behaves in ways that will break a naive
> client. I documented every quirk I hit building a scanner against it: an endpoint
> returning 403 for every CVE tried, `size` silently clamping at 100, `aliases` and
> `references` arriving as newline-joined strings rather than arrays, EPSS on a 0–100 scale
> instead of FIRST.org's 0–1, no `exploited` boolean (presence of `exploitedSince` is the
> flag), HTTP 204 with an empty body for a missing record, and affected software described
> as vendor/product/version-range text rather than package URLs — which is the reason no
> mainstream scanner consumes this source today.
>
> Everything is dated and verified against the live service; the client that encodes it is
> EUPL-1.2 if anyone wants it.

Mention the tool once, at the end, as a footnote. That is the ratio that survives r/netsec.

---

## 3. r/Python

Post **the week after** the others, flaired **Showcase**. Long-standing convention is that
a project post must answer three specific headings — verify against the live sidebar, but
the structure is good regardless:

**Title:**

> `euvd-watch: scan your SBOM against the EU's vulnerability database and draft CRA reports`

**Body:**

> **What My Project Does**
>
> It reads an SBOM (CycloneDX or SPDX), matches every component against ENISA's European
> Union Vulnerability Database, and tells you what is vulnerable — with an explicit
> confidence level per finding rather than a flat yes/no. It drafts OpenVEX statements to
> suppress genuine false positives, and if a component is hit by something flagged actively
> exploited it drafts the EU Cyber Resilience Act Article 14 notification and starts the
> 24-hour reporting clock against a tamper-evident audit log. It never submits anything.
>
> Python 3.11+, Typer and pydantic v2, `pip install euvd-watch`, EUPL-1.2. There is a
> GitHub Action, a GitLab template and a container image. 611 tests, mypy strict, and no
> network in the test suite — every external API is a committed fixture replayed through
> respx.
>
> **Target Audience**
>
> Production, and specifically European teams who acquired a legal reporting duty on
> 11 September. It runs in CI as a gate, or on a schedule reporting only what changed.
> It is also usable as a plain "what is in my SBOM" scanner if you never touch the CRA
> parts.
>
> **Comparison**
>
> Trivy, Grype and OSV-Scanner are faster than this, cover more ecosystems, and I use them.
> They match against NVD, GHSA and OSV. None of them read the EUVD, and none of them touch
> the reporting duty — they tell you what is vulnerable, not that a legal clock has started.
> Dependency-Track is the mature platform for continuous SBOM monitoring at organisational
> scale and does far more than this does. euvd-watch does not generate SBOMs; use Syft or
> cdxgen and feed it the output.
>
> The genuinely hard part, if anyone wants to look at code rather than a README: EUVD
> describes affected software as vendor/product/version-range text, so matching it to a
> purl is an unsolved identity problem. `euvd/match.py` and `euvd/versions.py` are where
> that lives, and `tests/fixtures/matching/cases.yaml` is the truth table every past bug is
> pinned to.

---

## 4. r/devops

Framed as the CI/CD problem, not the compliance product. **Title:**

> `CRA Article 14 starts today — has anyone actually wired the 24-hour clock into their pipeline?`

**Body:**

> As of today, manufacturers of products with digital elements in the EU have 24 hours to
> warn ENISA and their national CSIRT when an actively exploited vulnerability turns up in
> a product, then 72 hours to follow up.
>
> Every scanner I use tells me what is vulnerable. None of them tell me a legal clock just
> started, and none of them draft the notification. I ended up building the missing piece —
> SBOM in, EUVD match, and if something is flagged actively exploited it drafts the
> notification and tracks the deadline stages in an append-only audit log. Drafts only; a
> human files.
>
> Mostly I want to know how other people are handling this. Is anyone gating a pipeline on
> "exploited" rather than on severity? Where does the notification draft actually live in
> your process — ticket, runbook, someone's inbox?

Ask the question honestly and be ready for "we are ignoring it" as the most common answer.
That is still a useful thread.

---

## 5. Mastodon (fosstodon) — thread of three

> 1/ The EU built its own vulnerability database — ENISA's EUVD — with an actively-exploited
> flag. As of today the Cyber Resilience Act gives you 24 hours to report an exploited vuln
> in your product. Almost no open tooling reads the database the regulation is built around.
>
> 2/ So I built one. euvd-watch takes your SBOM, matches it against EUVD, drafts OpenVEX to
> cut false positives, and when something exploited lands it drafts the Article 14
> notification and starts the clock against a hash-chained audit log. It drafts — a human
> always files.
>
> 3/ European data, European regulation, European licence (EUPL-1.2). `pip install
> euvd-watch`, or run the container. The API notes are the interesting part if you have ever
> tried to consume EUVD yourself. #CRA #SBOM #OpenSource

## 6. LinkedIn

> The EU Cyber Resilience Act's Article 14 reporting duty becomes applicable today. If an
> actively exploited vulnerability is found in a product with digital elements, the
> manufacturer has 24 hours to warn ENISA and the national CSIRT, and 72 hours to follow up.
>
> Most affected manufacturers are SMEs with no compliance function, and the tooling gap is
> real: scanners tell you what is vulnerable, not that a legal clock has started.
>
> I have spent the past year building euvd-watch in the open to close that gap. It reads
> your SBOM, matches it against ENISA's own European Union Vulnerability Database, and
> drafts the Article 14 notification with a tamper-evident audit trail when the trigger
> fires. It drafts — it never submits. The decision stays with a human, which is where the
> regulation puts it.
>
> Free and open source under EUPL-1.2, released and in production use. If you are a
> manufacturer working out what this obligation means in practice, I am happy to talk.

---

## Being in the thread

The posts are the easy part. What actually determines the outcome:

- **Answer every question for the first eight hours**, especially the hostile ones. "Why
  not just use Trivy" is the question you will get most; the answer is in the r/Python
  Comparison section and it is a good-faith answer — they are better tools that read
  different data.
- **The false negative is an asset, not a liability.** If someone finds it, you have
  already published advisories against your own releases. Say so plainly.
- **Do not defend the EUVD API.** The quirks are real, ENISA knows the service is beta, and
  documenting them accurately is what makes you credible to the people who run it.
- **Never claim the tool decides what is legally reportable.** It drafts, a human files.
  That line is in the docs, on the dashboard, and it should be in every answer you give.
