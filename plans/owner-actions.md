# Owner action plan — rev 2

> Revised 2026-08-23. Deadlines read 22–23 August from `nlnet.nl`, `def.camp` and
> `sessionize.com`. Also published for reading:
> <https://claude.ai/code/artifact/f0574c8c-3af0-4831-8069-5422064db12c>
>
> Ordered **by deadline, not by topic**. Everything here leaves the repository, so the
> project's own rule applies to the project itself: the agent drafts, the owner sends.
> Each item names **who**, **where**, **what is prepared**, and **effort**.

**Hard dates:** DefCamp CfP wave 2 **2026-08-30** (7 days) · NLnet calls open
**2026-09-03** · CRA Art. 14 applicable **2026-09-11** (19 days) · NLnet deadline
**2026-11-03 12:00 CEST** (72 days).

## Cleared since rev 1 — nothing here needs the owner

- **Documentation site live** — <https://caisarus.github.io/euvd/>. All 24 internal links
  verified against the deployed pages. Unblocked step 8 and upgraded the application's
  website field.
- **DefCamp submission drafted** — `plans/talks/defcamp-2026-abstract.md`. Only the bio
  is missing.
- **All six launch posts drafted** — `plans/announcements/launch-posts.md`.
- **NLnet application updated** — §3 website field now points at the docs site; §11
  attachments carry their live URLs.

---

## This week — by Sunday 2026-08-30

### 1. Publish the two security advisories · **OVERDUE**

- **Who:** the owner alone — advisories can only be filed by a repository admin.
- **Where:** <https://github.com/caisarus/euvd/security/advisories/new>
- **Prepared:** `docs/advisories/draft-ghsa-01-silent-false-negatives.md` and
  `draft-ghsa-02-webhook-url-in-logs.md`, each opening with a table that maps straight
  onto the form (ecosystem `pip`, package `euvd-watch`, affected `< 0.4.1`, patched
  `0.4.1`, suggested CVSS vector, CWEs) plus a paste-ready body.
- **Effort:** ~30 minutes for both.
- **Why now:** drafted 2026-08-13 and still unpublished. Every release before `0.4.1` is
  affected and GitHub cannot alert anyone running one until a GHSA is live.
- **Two owner decisions:** (a) **request CVEs?** GitHub is a CNA, so it is a checkbox on
  the same form — yes makes them findable outside GitHub and reads well to a funder, and
  also creates permanent public records against the project's name. (b) **GHSA or release
  note?** Recommend GHSA for both; the webhook one especially, because upgrading does not
  fix it (users must **rotate the credential**) and an advisory is the only channel that
  says so.
- **Then:** send the agent the two GHSA URLs and the draft files become pointers to them.

### 2. Write the speaker bio, then submit to DefCamp · **2026-08-30**

- **Who:** the owner — biography is not the agent's to invent. Then the DefCamp programme
  committee reviews; travel is covered for accepted speakers.
- **Where:** <https://sessionize.com/defcamp-2026/> (Sessionize account + photo).
- **Prepared:** `plans/talks/defcamp-2026-abstract.md` — title, abstract, a ~90-word
  version if the field is capped, a 45-minute outline that collapses to 30, takeaways,
  audience, materials list, and the form values.
- **Effort:** ~1 hour, most of it the bio.
- **Detail:** wave 2 closes Sunday, selection is stated first-in-first-out, so this wave
  beats 15 October materially. Conference 19–20 November, Bucharest. Title *"Provably
  Safe: EUVD, the CRA Clock, and the False Negative I Shipped"*; track **Web, Software &
  Infrastructure Security**; **level 300** — their guidance says 100/200 level content is
  in low demand, so do not let it be filed as 200.

---

## Before the funding window opens — by 2026-09-03

### 3. Enable GitHub Sponsors

- **Who:** the owner — it needs bank and tax details. **With:** GitHub, and Stripe Connect.
- **Where:** <https://github.com/sponsors>, then a `.github/FUNDING.yml` the agent commits.
- **Effort:** 20 minutes plus GitHub's verification wait — start early, it is not instant.
- **CAUTION:** this **falsifies the application**. §7 states flatly that the project has no
  other funding, past or present, and NLnet asks directly. Tell the agent the moment it is
  enabled and that paragraph gets rewritten.

### 4. Decide the amount, delete the other scope

- **Who:** the owner alone — it is the owner's time being costed.
- **Where:** `plans/funding/nlnet-application.md` §6 and §7.
- **Options:** **€45 000 / 750 h** (data set, measured accuracy, dashboard 1.1 GA, ENISA
  work, distro packaging, docs and translation, maintenance) or **€24 000 / 400 h** (data
  set, accuracy, ENISA work only). Both at €60/h with a task breakdown.
- **Recommendation: the smaller one.** A first application entirely on CodeSupply's stated
  theme reads stronger than a larger one carrying items that plausibly happen unfunded.

### 5. Write §5 — "have you been involved before?"

- **Who:** the owner. The one section the agent genuinely cannot draft.
- **Where:** `plans/funding/nlnet-application.md` §5. **Effort:** ~30 minutes.
- **Detail:** NLnet reads it closely and it is about the person. If euvd-watch is the
  owner's first substantial open-source project, saying so plainly beats padding — the
  draft lists what to point at instead of a CV.

### 6. Fill the remaining `[OWNER]` fields

- **Who:** the owner. **Where:** `plans/funding/nlnet-application.md` §1. **Effort:** 5 min.
- Name, email, phone, country, optional PGP key. **Organisation:** natural persons are
  eligible — leave blank or write "independent developer". Do not invent an entity.

---

## Launch week — 2026-09-03 → 09-18

### 7. Confirm CodeSupply's call opened · **2026-09-03**

- **Who:** the owner checks, then tells the agent. **Where:** <https://nlnet.nl/propose/>
  and <https://nlnet.nl/codesupply/>. **Effort:** 2 minutes.
- CodeSupply is the right fund (€400k reserved for open calls, €5k–€50k grants, aimed at
  software supply-chain tooling) but its page still read "coming soon" on 2026-08-21.
- **If it did not open:** fall back to **Restack**; the agent re-points the abstract and
  budget, every other answer survives.

### 8. Post to r/netsec, Mastodon, LinkedIn, r/devops · **2026-09-11**

- **Who:** the owner posts and answers replies. **Where:** r/netsec, r/devops, fosstodon,
  LinkedIn. **Prepared:** `plans/announcements/launch-posts.md` §2, §4, §5, §6.
- **Effort:** ~1 hour to post, then stay reachable.
- **r/netsec submits the write-up, not the project** — that community reads a repo link as
  an advert. Submit <https://caisarus.github.io/euvd/docs/euvd-api/>.
- **CHECK FIRST:** Reddit blocks automated fetching, so the formats come from established
  convention, not from today's sidebar. Read the live rules of each subreddit. A removed
  post wastes the exact news cycle the timing exists to catch.

### 9. Show HN · **Tuesday 2026-09-15**, ~14:00–16:00 UTC

- **Who:** the owner, with the day free. **Where:**
  <https://news.ycombinator.com/submit>. **Prepared:** `launch-posts.md` §1 — the title
  and the first comment.
- **Effort:** 10 minutes to post, then ~8 hours in the thread.
- 2026-09-11 is a Friday, the worst day for a Show HN, which is why this is split out.
  Submit the repo URL, then immediately post the prepared comment — that is the convention
  and it is where the pitch goes.

### 10. r/Python, then the awesome-list PRs · week of 2026-09-21

- **Who:** the owner submits; list maintainers merge. **Where:** r/Python with *Showcase*
  flair; awesome-sbom, awesome-supply-chain-security, any CRA list that exists.
  **Prepared:** `launch-posts.md` §3. **Effort:** ~30 minutes each.
- r/Python comes a week later so the set does not read as a campaign.

---

## Relationships that strengthen the application — September–October

### 11. Find ENISA's contact route — then the agent writes the letter

- **Who:** the owner finds the address, the agent drafts, the owner sends.
  **With:** ENISA — the EUVD team.
- **Where:** <https://euvd.enisa.europa.eu/> feedback form, or ENISA's general contact.
  **Effort:** ~10 minutes to find it.
- **BLOCKED:** euvd.enisa.europa.eu returned an application error on 2026-08-22 and the
  agent will not invent an address for a European agency. The letter follows the same day
  the route is known.
- Highest-leverage relationship the project has, and the one the application leans on
  hardest. <https://caisarus.github.io/euvd/docs/euvd-api/> is already the dated record.

### 12. Introduce the data set to the standards communities

- **Who:** the owner — these are conversations, not submissions.
  **With:** OpenSSF (SBOM Everywhere, Vulnerability Disclosure WGs), CycloneDX, OWASP
  Romania. **Where:** OpenSSF public WG calls and Slack, CycloneDX Slack, the local chapter.
- **Effort:** ~1 hour a week for a few weeks.
- Bring the EUVD↔purl mapping as a **data contribution**, not a tool announcement. That
  framing is what makes it a CodeSupply proposal and is far more welcome in those rooms.

### 13. Mint a Zenodo DOI

- **Who:** the owner authorises; Zenodo does the rest. **Where:**
  <https://zenodo.org/account/settings/github/> — enable the repo, then cut a release
  (the agent can tag it). **Effort:** ~15 minutes.
- Makes the project citable, worth having on the application before submitting.

---

## The submission — by 2026-11-03, 12:00 CEST

### 14. Submit the CodeSupply application

- **Who:** the owner is the named applicant — NLnet funds people, not drafts.
  **Where:** <https://nlnet.nl/propose/>. **Prepared:**
  `plans/funding/nlnet-application.md`, every field answered. **Effort:** ~2 hours if
  steps 3–6 are done.
- Walk the checklist at the bottom of the draft first. **Submit days early — the deadline
  is noon, not midnight, and NLnet does not extend.**
- **The AI disclosure is required and must not be improvised:** model, dates, prompts and
  **unedited output**. The answer is yes, drafted 2026-08-21; commit `e9ade07` is
  deliberately that unedited output (`git show e9ade07`). Suggested wording is §12.

### 15. Watch for the FOSDEM 2027 devroom calls

- **Who:** the owner, when they appear. **With:** individual devroom organisers.
  **Where:** <https://fosdem.org/> — each devroom runs its own call on its own timetable.
- Early February, Brussels; calls typically open in autumn and close in November.
  **Nothing published for 2027 yet** — a watch item, not a deadline. The DefCamp abstract
  adapts in an afternoon.

### 16. Take the NLnet interview, if shortlisted

- **Who:** the owner. They are assessing the person, which is the point.
- **Prep:** <https://caisarus.github.io/euvd/docs/matching/> and
  <https://caisarus.github.io/euvd/ARCHITECTURE/>. Expect them to probe the confidence
  model, why `not_affected` requires machine-checkable proof, and why a false negative is
  the failure that matters.

---

## Still the agent's

- **The ENISA letter** — written the day the contact route is known (step 11).
- **The asciinema recording** of `examples/demo.sh` — optional, but the strongest
  attachment a reviewer absorbs in ninety seconds.
- **Advisory link commits** — on receipt of the two GHSA URLs (step 1).
- **§7 rewrite** — the moment GitHub Sponsors goes live (step 3).
- **A release tag** — whenever the Zenodo switch is flipped (step 13).
