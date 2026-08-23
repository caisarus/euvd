# Owner runbook — step by step, in detail

> Companion to `plans/owner-actions.md`, which is the one-screen overview. This file is
> the click-by-click version: what to type, what to paste, what each form field wants, and
> what "done" looks like.
>
> Written 2026-08-23. **Everything here is done by the owner** — these are the actions that
> leave the repository. Where the agent has already prepared something, the file is named.
>
> Dates verified 22–23 August from `nlnet.nl`, `def.camp`, `sessionize.com`. Anything the
> agent could not confirm is marked **UNVERIFIED** rather than guessed.

---

# Part 0 — Working on another PC

Verified on 2026-08-23 by doing exactly this: fresh clone, new venv, full gate, offline.
**Result: the repository is self-contained.** Nothing is needed that is not committed.

## 0.1 Clone

```bash
git clone https://github.com/caisarus/euvd.git
cd euvd
```

HTTPS needs no key. For push access either sign in with the `gh` CLI (`gh auth login`,
which also configures git credentials) or use SSH
(`git clone git@github.com:caisarus/euvd.git`) with a key added at
<https://github.com/settings/keys>.

There is **no Git LFS**, no submodules, and no secrets file. 222 tracked files, largest is
a 968 KB test fixture, so the clone is quick anywhere.

## 0.2 Python

Needs **3.11 or 3.12**. On a fresh Ubuntu/Debian box, `python3.11` may need the deadsnakes
PPA; check with `python3 --version` first.

```bash
python3.11 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
euvd-watch version                 # -> 1.0.0
```

**Always activate the venv.** Most confusing failures on a new machine are a venv that was
created and never activated.

## 0.3 Prove it works — offline

```bash
ruff check . && ruff format --check . && mypy src && pytest
./examples/demo.sh
```

Expected: **615 passed**, coverage **94.50%**, ruff and mypy clean, and the demo printing
seven numbered steps ending in `demo complete`. None of this touches the network — every
external API is a committed fixture. To prove that rather than trust it, point the machine
at a dead proxy and run it again:

```bash
http_proxy=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 pytest
```

Anything that tried to reach the internet would fail loudly. Nothing does.

## 0.4 Optional extras, only if you need them

| You want to… | Then |
| --- | --- |
| Build the docs site | `pip install -e ".[docs]"`, then `python scripts/build_docs_tree.py && mkdocs build --strict` |
| Run the dashboard | `pip install -e ".[web]"`, then `euvd-watch web serve <sbom>` |
| Run the accessibility gate | `npm ci` (needs Node), then `./scripts/run_a11y_check.sh` |
| Commit hooks | `pre-commit install` — runs ruff, ruff-format and mypy on every commit |

## 0.5 One gotcha, if the new PC is Windows + WSL

If the clone lives on `/mnt/c`, git cannot see Unix execute bits. A committed script can
lose `+x` and CI then fails with exit 126. If that happens:

```bash
git update-index --chmod=+x path/to/script.sh
git commit -m "fix: restore exec bit"     # commit with NO pathspec, or the chmod is dropped
```

This bit the project once already, on `examples/demo.sh`.

---

# Part 1 — Publish the two security advisories

**Overdue.** Drafted 2026-08-13. ~30 minutes for both.

## 1.1 Why this is first

Every release before `0.4.1` is affected. GitHub cannot warn anyone running an old version
until a GHSA exists — publishing is what turns a fixed bug into a notified user.

The second advisory is the urgent one in a way the first is not: it is a webhook credential
written to logs, and **upgrading does not fix it**. Affected users have to rotate the
credential, and an advisory is the only channel that tells them so.

## 1.2 Do it

1. Go to <https://github.com/caisarus/euvd/security/advisories/new>.
2. Open `docs/advisories/draft-ghsa-01-silent-false-negatives.md`. Its first table maps
   field-for-field onto the form:
   - **Title** — the one-line summary in the table
   - **Ecosystem** `pip` · **Package name** `euvd-watch`
   - **Affected versions** `< 0.4.1` · **Patched versions** `0.4.1`
   - **Severity** High · **CVSS vector** as suggested (adjust if you disagree)
   - **CWEs** CWE-697, CWE-754
   - **Description** — paste the body below the table
3. Publish, then repeat with `draft-ghsa-02-webhook-url-in-logs.md` (Moderate, CWE-532).

## 1.3 Two decisions that are yours

**Request CVEs?** GitHub is a CNA, so it is a checkbox on the same form.
*For:* findable outside GitHub, and it reads well to a funder assessing seriousness.
*Against:* permanent public records against the project's name, forever.

**GHSA or just a release note?** Recommendation: GHSA for both, for the rotation reason
above.

## 1.4 Then

Send the agent the two published GHSA URLs. Each draft file gets replaced with a pointer to
its published advisory, in a commit.

---

# Part 2 — DefCamp submission · deadline 2026-08-30

Wave 2 closes Sunday. def.camp states selection is **first-in-first-out**, so this wave is
materially better odds than wave 3 on 15 October. Conference is **19–20 November 2026,
Bucharest**. Travel is covered for accepted speakers.

## 2.1 Set up Sessionize

Account at <https://sessionize.com/defcamp-2026/>. You will need a **photo** and a **bio**;
everything else is drafted.

## 2.2 Paste from `plans/talks/defcamp-2026-abstract.md`

| Field | Value |
| --- | --- |
| Title | Provably Safe: EUVD, the CRA Clock, and the False Negative I Shipped |
| Abstract | The long version in the draft. If the field is capped, the ~90-word version is right below it. |
| Track | **Web, Software & Infrastructure Security** — the track that explicitly lists supply chain security |
| Level | **300.** Their guidance: "Target 300-400 level technical content; 100 and 200 level content is in low demand." Do not file this as 200. |
| Length | 45 min. The outline collapses to 30 by cutting section 5. |
| Notes to organisers | The seven-point outline |

## 2.3 The bio — yours to write

60–90 words. If this is your first conference talk, point at artefacts rather than titles.
Something in this shape, in your own words and only what is true:

> Maintainer of euvd-watch, an EUPL-licensed toolkit connecting SBOMs to ENISA's EU
> Vulnerability Database and the CRA's Article 14 reporting duty. Released 1.0.0 in
> August 2026; published two security advisories against his own earlier releases.

## 2.4 Two honesty checks before November

1. The abstract says almost nothing open reads the EUVD. True as far as we have checked and
   the repo's long-standing claim — but it is exactly what someone challenges from the
   floor, and the ecosystem may move. Re-verify against Trivy, Grype, OSV-Scanner and
   Dependency-Track before you are on stage.
2. **Do not cut the confession.** The false negative is the strongest thing in the
   submission and the reason it is a 300-level talk rather than a product walkthrough.

---

# Part 3 — Before the funding window opens · by 2026-09-03

## 3.1 GitHub Sponsors

<https://github.com/sponsors> → enrol → Stripe Connect for payouts. Needs bank and tax
details and GitHub's verification is not instant, which is why this is early.

**The moment it is live, tell the agent.** §7 of the application currently states flatly
that the project has no funding, past or present. NLnet asks directly, so that sentence
must change the same day.

## 3.2 Choose the amount

In `plans/funding/nlnet-application.md` §6/§7. Both scopes are costed at €60/hour with a
task-by-task breakdown, which is the shape NLnet asks for.

- **€45 000 / 750 h** — data set, measured accuracy, dashboard 1.1 GA, ENISA work, distro
  packaging, docs and translation, maintenance.
- **€24 000 / 400 h** — data set, accuracy, ENISA work. Nothing else.

**Recommendation: the smaller one.** Entirely on CodeSupply's stated theme. A first
application that is all on-theme reads stronger than a larger one carrying packaging and
translation, which plausibly happen unfunded anyway. **Delete the scope you do not choose**
— do not submit a document offering two prices.

## 3.3 Write §5 — prior involvement

The one section the agent will not draft, because it is about you. NLnet reads it closely.
Include prior open-source maintenance, any security or compliance work, community
involvement. If euvd-watch is your first substantial open-source project, say so plainly;
it is a stronger answer than padding, and §5 already lists what to point at instead of a CV.

## 3.4 Fill §1

Name, email, phone, country, optional PGP key. **Organisation:** natural persons are
eligible — leave blank or write "independent developer". Do not invent a legal entity.

---

# Part 4 — Launch week

## 4.1 Confirm the fund opened · 2026-09-03 · two minutes

Check <https://nlnet.nl/propose/> and <https://nlnet.nl/codesupply/>. CodeSupply is the
right fund (€400 000 reserved for open calls, grants €5 000–€50 000, aimed squarely at
software supply-chain tooling) but its page still read "coming soon" on 21 August.

If it did not open, tell the agent and the application re-points to **Restack**, the general
successor to NGI Zero. Only the abstract and budget framing change.

## 4.2 Friday 2026-09-11 — the day the obligation lands

Post these from `plans/announcements/launch-posts.md`:

| Where | Section | Note |
| --- | --- | --- |
| r/netsec | §2 | Submit **<https://caisarus.github.io/euvd/docs/euvd-api/>** — the write-up, not the repo. That community reads a GitHub link as an advert. |
| r/devops | §4 | Framed as a question, not an announcement. Expect "we're ignoring it" as the most common reply; still a useful thread. |
| Mastodon | §5 | Three-post thread. |
| LinkedIn | §6 | The register that room expects. |

**Read each subreddit's live sidebar first.** Reddit blocks automated fetching, so those
formats come from established convention rather than today's rules. A removed post wastes
the exact news cycle the timing exists to catch.

## 4.3 Tuesday 2026-09-15 — Show HN

Not Friday: the 11th is a Friday, the worst day of the week for Show HN. Post at
<https://news.ycombinator.com/submit> around **14:00–16:00 UTC**.

1. Submit the repository URL with the title from §1 of the drafts.
2. **Immediately** post the prepared first comment. That is the convention and it is where
   the pitch actually goes.
3. Stay in the thread. A Show HN whose author answers every comment for eight hours beats a
   better project posted and abandoned. Block the day.

Do not edit the post to thank people for upvotes. Answer questions instead.

The question you will get most is "why not just use Trivy". The honest answer is in the
r/Python Comparison section: they are good tools that read different data.

## 4.4 Week of 2026-09-21 — r/Python and the lists

r/Python with **Showcase** flair, §3 of the drafts (the three-heading format). Deliberately
a week later so the set does not read as a campaign.

Then one-line PRs to awesome-sbom, awesome-supply-chain-security, and any CRA-focused list
that exists by then. Quiet, durable traffic that keeps working long after a Show HN scrolls
away.

---

# Part 5 — Relationships · September–October

## 5.1 ENISA — **blocked on you**

The highest-leverage relationship the project has, and the one the application leans on
hardest. <https://caisarus.github.io/euvd/docs/euvd-api/> is already the dated record of the
beta API's real behaviour.

**What is needed from you:** the current contact route. `euvd.enisa.europa.eu` returned an
application error on 2026-08-22, and the agent will not invent an address for a European
agency. Look for a feedback form on the EUVD site or ENISA's general contact page.

Once you have it, the letter is drafted the same day. It goes as **structured feedback, not
complaint** — that is what makes you a known quantity to the people who run the data source
before you cite that source in a funding application.

## 5.2 Standards communities

OpenSSF **SBOM Everywhere** and **Vulnerability Disclosure** working groups (public calls
and Slack), the **CycloneDX** community Slack, and your local **OWASP** chapter.

Bring the EUVD-to-package-identifier mapping as a **data contribution other scanners can
consume**, not as a tool announcement. That framing is what makes the proposal a CodeSupply
one, and it is far more welcome in those rooms. The stated ambition in the application:
success looks like Trivy or OSV-Scanner consuming the mapping.

## 5.3 Zenodo DOI · fifteen minutes

<https://zenodo.org/account/settings/github/> → sign in with GitHub → toggle the `euvd`
repository on → then publish a GitHub release. The DOI appears by itself and makes the
project citable. Tell the agent when the toggle is on and it will cut the release tag.

---

# Part 6 — The submission · by 2026-11-03, 12:00 CEST

## 6.1 Before you open the form

Walk the checklist at the bottom of `plans/funding/nlnet-application.md`:

- every `[OWNER]` field filled
- §5 written in your own words
- one scope chosen, the other deleted
- the "other funding" paragraph still true (did you enable Sponsors?)

## 6.2 Submit

At <https://nlnet.nl/propose/>. **Days early.** The deadline is **noon**, not midnight, and
NLnet does not extend.

## 6.3 The AI disclosure — do not improvise this

The form asks whether generative AI was used, which model, what for, and it asks for the
**dates, the prompts and the unedited output**.

The answer is **yes**: the draft was written by Claude on 2026-08-21. Commit `e9ade07` is
deliberately that unedited output, so `git show e9ade07` retrieves the original however much
you edit afterwards. Suggested wording is §12 of the draft — adjust it to describe what you
actually changed, then attach the original.

## 6.4 Attachments

PDFs of `docs/euvd-api.md` and `docs/matching.md` — the strongest evidence the work is
grounded in the real data source rather than in a proposal. Both are also live on the docs
site. Link the repository; do not attach it.

---

# Part 7 — After

## 7.1 FOSDEM 2027 · **UNVERIFIED**

Early February, Brussels. Each devroom runs its own call on its own timetable, typically
opening in autumn and closing around November. **Nothing is published for 2027 yet** — this
is a watch item, not a deadline. The DefCamp abstract adapts in an afternoon.

## 7.2 The NLnet interview

NLnet talks to applicants before deciding, and they are assessing the person. Expect them to
probe the technical claims: the confidence model, why `not_affected` requires
machine-checkable proof, why a false negative is the failure that matters. Reread
<https://caisarus.github.io/euvd/docs/matching/> and
<https://caisarus.github.io/euvd/ARCHITECTURE/> beforehand. You shipped all of it.

---

# Waiting on you, so the agent can act

| Send the agent | And it will |
| --- | --- |
| The two GHSA URLs | Replace the draft files with pointers to the published advisories |
| "Sponsors is live" | Rewrite §7's other-funding paragraph |
| ENISA's contact route | Draft the feedback letter that day |
| "Zenodo is toggled on" | Cut the release tag that mints the DOI |
| "CodeSupply did not open" | Re-point the application at Restack |
| A request for the asciinema cast | Record `examples/demo.sh` as an embeddable player |
