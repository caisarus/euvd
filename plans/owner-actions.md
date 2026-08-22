# Owner action plan — what only the owner can do

> Written 2026-08-22, after `1.0.0` shipped. Deadlines read that day from `nlnet.nl` and
> `def.camp`. Also published as a private artifact for reading:
> <https://claude.ai/code/artifact/f0574c8c-3af0-4831-8069-5422064db12c>
>
> Ordered **by deadline, not by topic**. Everything here leaves the repository — an
> advisory, an application, a post, an email — so the project's own rule applies to the
> project itself: the agent drafts, the owner sends.

**Hard dates:** DefCamp CfP round 2 **2026-08-30** · CRA Art. 14 applicable
**2026-09-11** · NLnet calls open **2026-09-03** · NLnet deadline **2026-11-03 12:00
CEST**.

## This week

1. **Publish the two GHSA advisories.** *With: GitHub, no one else.* Drafts have sat in
   `docs/advisories/` since 2026-08-13; every release `< 0.4.1` is affected and nobody
   running an old version finds out until a GHSA is live. Paste at
   `github.com/caisarus/euvd/security/advisories/new`. Two owner decisions: **request
   CVEs?** (GitHub is a CNA — one checkbox; makes them findable outside GitHub and reads
   well to a funder, but creates permanent public records) and **GHSA or release note?**
   Recommend GHSA for both — the webhook-credential one especially, because upgrading
   does *not* fix it (users must **rotate**), and an advisory is the only channel that
   says so. Afterwards each draft file is replaced with its published GHSA link — say
   when they are live and the agent commits that.
2. **DefCamp CfP, round 2 — closes 2026-08-30.** *With: DefCamp programme committee via
   `sessionize.com/defcamp-2026`.* Conference is 2026-11-19/20 in Bucharest; rounds are
   15 Jun / **30 Aug** / 15 Oct and selection is stated to be first-in-first-out, so
   round 2 beats round 3 materially. Fits their Governance & Compliance track.
   **BLOCKED ON THE AGENT: no abstract drafted yet** — the one deadline where the
   artefact is still owed.

## Before 2026-09-03

3. **Enable GitHub Sponsors + `FUNDING.yml`.** *With: GitHub, Stripe for payouts.* Needs
   bank/tax details, so start before you are also writing an application. **Caution:** if
   enabled, the NLnet draft's "other funding sources" answer (§7) stops being true — it
   currently states flatly that there is none. Tell the agent and it updates §7.
4. **Choose the NLnet ask: €45 000 / 750 h or €24 000 / 400 h.** *With: yourself.* Both
   costed at €60/h with a task breakdown. **Recommendation: the smaller one** — entirely
   on CodeSupply's theme (data set + measured accuracy + ENISA work), where the larger
   carries packaging and translation that plausibly happen unfunded anyway.
5. **Write §5 "prior involvement" yourself.** *With: yourself — cannot be drafted.* NLnet
   reads it closely and it is about you. If euvd-watch is your first substantial
   open-source project, say so plainly; the draft lists what to point at instead of a CV.

## The announcement window, 2026-09-03 → 09-18

6. **Confirm CodeSupply's call actually opened (2026-09-03).** *With: nlnet.nl, two
   minutes.* Its own page still read "coming soon" on 2026-08-21. If it did not open, the
   fallback is **Restack**; the agent re-points the abstract and budget, the rest of the
   answers survive.
7. **Post, in the week Article 14 lands (2026-09-11).** *With: Hacker News, r/netsec,
   r/Python, r/devops, Mastodon, LinkedIn.* Show HN once, then stay in the thread all day.
   r/netsec is strict about self-promotion — the submission must be the technical
   write-up, and the EUVD API findings are that write-up. r/Python and r/devops get the
   CI/CD angle, not the compliance one. **BLOCKED ON THE AGENT: posts not drafted yet.**
8. **Awesome-list PRs.** *With: list maintainers.* awesome-sbom,
   awesome-supply-chain-security, any CRA list that exists by then. One-line PRs; quiet
   durable traffic long after a Show HN scrolls away.

## September–October — relationships that strengthen the application

9. **Send ENISA the EUVD API feedback.** *With: ENISA's EUVD team.* The
   highest-leverage relationship the project has and the one the application leans on
   hardest; `docs/euvd-api.md` is already the dated record. Sent as structured feedback
   rather than complaint, it makes you known to the people running the data source
   *before* you cite it in a funding application. **UNVERIFIED: the contact route** — the
   EUVD site returned an application error on 2026-08-22. Find the current address/form,
   then the agent drafts the letter.
10. **Introduce the data set, not the tool.** *With: OpenSSF SBOM Everywhere and
    Vulnerability Disclosure WGs, CycloneDX Slack, OWASP Romania.* Frame the EUVD↔purl
    mapping as a *data contribution* other scanners consume — that framing is what makes
    it a CodeSupply proposal, and it is far more welcome in those rooms than a tool
    announcement.
11. **Mint a Zenodo DOI.** *With: Zenodo, via the GitHub integration.* Switch it on, cut
    a release, the DOI appears. Worth having on the application before submitting.

## By 2026-11-03, 12:00 CEST

12. **Submit the CodeSupply application.** *With: NLnet Foundation — you are the named
    applicant.* Walk the checklist at the bottom of `plans/funding/nlnet-application.md`
    first. Submit days early; NLnet does not extend and the deadline is **noon**.
    **The form demands a generative-AI disclosure** — model, dates, prompts and
    **unedited output**. The answer is yes, drafted 2026-08-21; commit `e9ade07` is
    deliberately that unedited output (`git show e9ade07`), and §12 of the draft has
    suggested wording to adjust to whatever you actually changed.
13. **Watch for the FOSDEM 2027 security devroom CfP.** *With: devroom organisers.* Early
    February, Brussels; each devroom runs its own call, typically opening in autumn and
    closing in November. **2027 dates not yet published** — a watch item, not a deadline.
14. **Take the NLnet interview yourself, if shortlisted.** *With: NLnet reviewers.* They
    probe the technical claims — the confidence model, why `not_affected` needs
    machine-checkable proof, why a false negative is the failure that matters.
    `docs/matching.md` and `ARCHITECTURE.md` are the reread.

## Owed by the agent

In deadline order: the **DefCamp abstract/bio/outline** (8 days out — ask first), the
**Show HN post + Reddit variants** (before 09-11), the **ENISA letter** (once the contact
route is known). Further out and application-improving rather than blocking: the **MkDocs
site** (so the application's "website" field points at documentation, not a repo root) and
the **asciinema cast** of `examples/demo.sh` (the strongest attachment a reviewer absorbs
in ninety seconds).
