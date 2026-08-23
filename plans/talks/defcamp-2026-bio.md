# DefCamp speaker bio — drafted from Cezar's facts

> Written 2026-08-23 from the facts supplied: **Cezar Vasilescu**, DevOps engineer at
> **LSEG**, **13 years** as a Linux/DevOps engineer, no prior open-source or
> supply-chain-security work, GitHub **caisarus**, enjoys automation above anything else.
> Nothing else has been invented. Paste into the Sessionize **speaker profile** →
> *Tagline & Bio*, not into the session form.

## Two things to settle before you paste

### 1. Option A and B claim the advisories are published. They are not — yet.

"has published two security advisories against his own earlier releases" is the single
strongest line available to you: it is what turns a first-time open-source author into
someone with a track record of handling their own mistakes in public, and it is the line
that makes the talk's confession land as credibility rather than as an admission.

It becomes true the moment you complete **step 1 of the runbook**, which is already
overdue and takes about half an hour. Do that first and use **A** or **B**.

If you would rather not, **option D** says nothing untrue and is safe to submit today.

### 2. Naming LSEG is your call, and may not be only your call

A bio that names your employer creates an implicit association between them and a
conference talk about security failures — even though every bug in the talk is in your own
personal project, not theirs. Many financial institutions require sign-off before staff
speak publicly in a way that identifies them. **Check whether LSEG has a speaking or
external-communications policy before you submit**, because the bio is published with the
programme and is awkward to walk back.

If you would rather keep them out of it, every option below works with
"a DevOps engineer in Bucharest" or "a DevOps engineer at a financial institution" in
place of "a DevOps engineer at LSEG". Say the word and I will re-cut them.

*Also:* I have not put a city in any bio, because you did not give me one. Sessionize has
its own **Location** field on the profile — put Romania (and your city) there instead.

---

## The bios

Sessionize's guidance is around 600 characters; all four are comfortably under.

### A — plain and factual · **469 characters** · *recommended, after step 1*

> Cezar Vasilescu is a DevOps engineer at LSEG with thirteen years of Linux and automation
> behind him. euvd-watch is his first open-source project: an EUPL-licensed toolkit that
> matches SBOMs against ENISA's EU Vulnerability Database and drafts the Cyber Resilience
> Act's Article 14 notifications. He released 1.0.0 in August 2026 and has published two
> security advisories against his own earlier releases. He automates the parts of
> compliance nobody wants to do by hand.

### B — leads with the project · **447 characters** · *after step 1*

> euvd-watch connects SBOMs to ENISA's EU Vulnerability Database and the Cyber Resilience
> Act's 24-hour reporting clock. Cezar Vasilescu wrote it: his first open-source project,
> released 1.0.0 in August 2026 under the EUPL, with two advisories published against his
> own earlier releases. By day he is a DevOps engineer at LSEG, thirteen years into Linux
> and automation, which is roughly how a legal deadline came to look like something you
> automate.

### C — leads with the person · **437 characters** · *safe today*

> Thirteen years of Linux and automation have left Cezar Vasilescu with one conviction: if
> a task repeats, it should not be done by hand. So when the EU Cyber Resilience Act put a
> 24-hour reporting clock on manufacturers, he wrote euvd-watch, matching SBOMs against
> ENISA's vulnerability database and drafting the Article 14 notification. It is his first
> open-source project, released 1.0.0 in August 2026. He is a DevOps engineer at LSEG.

### D — fallback with no advisory claim · **470 characters** · *safe today*

> Cezar Vasilescu is a DevOps engineer at LSEG with thirteen years of Linux and automation
> behind him. euvd-watch is his first open-source project: an EUPL-licensed toolkit that
> matches SBOMs against ENISA's EU Vulnerability Database and drafts the Cyber Resilience
> Act's Article 14 notifications, released 1.0.0 in August 2026. He documented the EUVD's
> beta API from the wire, mostly so nobody else has to. He automates the parts of
> compliance nobody wants to do by hand.

**Recommendation: publish the advisories this week, then submit A.** It is the most direct
of the four, it earns the talk in one sentence rather than asserting expertise, and
"thirteen years" plus "first open-source project" is a genuinely interesting combination
that a programme committee will notice.

## Taglines — pick one

| Chars | Tagline |
| --- | --- |
| 50 | `DevOps engineer at LSEG · maintainer of euvd-watch` |
| 48 | `Maintainer, euvd-watch · DevOps engineer at LSEG` |
| 55 | `13 years of Linux and automation · author of euvd-watch` |
| 38 | `DevOps engineer · author of euvd-watch` |

The first is the safe default. The third is the better one if you keep LSEG out.

## Why "automation" is doing real work here

You said you enjoy automation above anything else, and three of the four bios end on it —
not as a personality note, but because it is the honest through-line of the whole
submission. The CRA gives manufacturers 24 hours to report. euvd-watch does not decide
anything: it drafts, and a human files. That is a bio, a talk and a design principle
agreeing with each other, which is rarer in a CfP than it sounds.

## Rest of the Sessionize profile

- **Photo** — required. Plain background, head and shoulders. A phone photo is fine.
- **Links** — <https://github.com/caisarus> at minimum.
- **Location** — Romania, and your city.
- Then submit the talk itself from `plans/talks/defcamp-2026-abstract.md`.
