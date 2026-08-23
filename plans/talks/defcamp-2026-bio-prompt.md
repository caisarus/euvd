# DefCamp speaker bio — where it goes, and a prompt to write it

> Deadline: the bio has to exist before you can submit, and wave 2 closes **2026-08-30**.

## 1. Where the field actually is

The bio is **not** part of the session submission. It lives on your **Sessionize speaker
profile**, which you fill in once and then reuse for every conference you ever submit to.

1. Create an account at <https://sessionize.com/> (or sign in).
2. Go to your profile → **Tagline & Bio**.
3. Fill in the whole profile while you are there — the submission form pulls from it:
   - **Full name**
   - **Tagline** — one short line, the thing printed under your name in the programme.
     Think "Maintainer, euvd-watch", not a sentence.
   - **Bio** — the paragraph. See the rules below.
   - **Photo** — required. A plain, well-lit head-and-shoulders shot. A phone photo against
     a blank wall is completely fine; a cropped group photo is not.
   - **Links** — GitHub at minimum, plus LinkedIn/Mastodon/website if you use them.
   - **Location** — Romania.
4. Only then go to <https://sessionize.com/defcamp-2026/> and submit the talk itself from
   `plans/talks/defcamp-2026-abstract.md`.

## 2. The rules the bio has to follow

- **Third person.** "He maintains…", never "I maintain…". This is the convention for
  conference programmes and Sessionize's own guidance says so.
- **About 600 characters** — roughly 80–100 words. The form shows a live counter; trust
  the counter over this number if they disagree.
- **Answer four things:** who you are, what you do and where, what makes you credible on
  *this specific topic*, and one human detail.
- **No marketing adjectives.** "Passionate", "seasoned", "thought leader", "cutting-edge"
  all read as filler to a security audience and cost you credibility on a talk whose whole
  premise is honesty about a bug you shipped.
- DefCamp does not ask about AI assistance, so there is nothing to disclose here — unlike
  the NLnet form, which does.

## 3. Fill this in first — the prompt is only as good as these answers

The AI cannot invent your life, and neither will I. Answer these seven, roughly, in any
form:

1. **Name**, and how you want it spelled in a programme.
2. **Day job** — role and employer, or "independent", or "student at X". If you would
   rather not name the employer, say so; "works in <industry> in Bucharest" is fine.
3. **Years in the field**, and in what — development, security, ops, something else.
4. **Anything prior that makes you credible on supply-chain security or EU compliance** —
   past projects, certifications, communities, previous talks. If there is nothing, say
   "nothing" and the bio leans on euvd-watch instead. That is a legitimate answer.
5. **Other open-source work**, if any.
6. **Public presence** — GitHub handle, Mastodon, LinkedIn, blog.
7. **One human detail** you are happy to have in print. Optional, but it is what stops a
   bio reading like a LinkedIn headline.

## 4. The prompt — paste this whole block

Everything about the project below is already correct, so the model does not have to guess
at it. Replace the bracketed parts with your answers from §3 and delete this line.

---

```text
You are writing a speaker biography for a technical security conference programme.

CONTEXT — THE CONFERENCE
DefCamp 2026, Bucharest, 19–20 November. The largest hacking and cyber security
conference in Central and Eastern Europe. The audience is practitioners: security
researchers, developers, DevSecOps engineers. They are allergic to marketing language.

CONTEXT — THE TALK THIS BIO ACCOMPANIES
Title: "Provably Safe: EUVD, the CRA Clock, and the False Negative I Shipped"
Track: Web, Software & Infrastructure Security. Technical level 300 of 400.
The talk is about building an open-source tool that reads ENISA's European Union
Vulnerability Database (EUVD) and drafts EU Cyber Resilience Act Article 14 reports. Its
spine is a confession: the speaker's own version comparator read an inverted version range
as "provably outside", so the scanner reported no findings and exited 0 for a component
sitting on exactly the affected version. He found it in a pre-1.0 audit, fixed it, and
published security advisories against his own earlier releases.

CONTEXT — THE PROJECT (all verified, use only what helps)
- euvd-watch: an EUPL-1.2 licensed toolkit. Reads an SBOM (CycloneDX or SPDX), matches
  components against ENISA's EUVD, drafts conservative OpenVEX statements, and drafts the
  CRA Article 14 notification with a tamper-evident audit log when an actively exploited
  vulnerability fires the trigger. It never submits anything; a human always files.
- Released 1.0.0 in August 2026, on PyPI and as a container image.
- 615 tests, 94.5% coverage, ten machine-checked invariants.
- Documented the EUVD beta API's real behaviour from the wire at
  https://caisarus.github.io/euvd/docs/euvd-api/
- Repository: https://github.com/caisarus/euvd

THE SPEAKER — these are the only facts about the person; do not add any others
- Name: [YOUR NAME]
- Role and organisation: [YOUR DAY JOB, or "independent developer"]
- Background: [YEARS AND FIELD, e.g. "eight years building backend systems, the last three
  on security tooling"]
- Prior relevant work: [PRIOR PROJECTS/COMMUNITIES/TALKS, or write "none — euvd-watch is
  his first substantial open-source project"]
- Public presence: [GITHUB HANDLE / LINKS]
- Human detail: [OPTIONAL, e.g. "runs a small home lab" or "translates the project's docs
  into Romanian"]

TASK
Write the speaker bio.

RULES
- Third person. Around 600 characters, which is roughly 80–100 words. Never exceed 600.
- Plain, factual, specific. Every clause must carry information.
- BANNED: passionate, seasoned, thought leader, expert in, cutting-edge, leverage,
  robust, journey, deep dive, and any superlative.
- Invent nothing. If a fact is missing, leave it out — do not fill the gap with a
  plausible-sounding claim. Do not add employers, degrees, certifications, years of
  experience or awards that are not listed above.
- Ground the credibility in what he has actually shipped, not in job titles.
- One sentence of it should make clear why he specifically is the person giving THIS talk.

ALSO PRODUCE
A "tagline": a single short line, under 60 characters, for printing under his name in the
programme. Not a sentence, not a slogan.

OUTPUT
Three bio options in different registers — one plain and factual, one leading with the
project, one leading with the person — each with its character count. Then three tagline
options. No commentary.
```

---

## 5. What a good answer looks like

For a hypothetical speaker, so you can recognise the shape — **do not use this, the facts
are invented**:

> **Tagline:** Maintainer, euvd-watch · Bucharest
>
> **Bio:** [Name] is an independent developer in Bucharest who has spent eight years
> building backend systems and the last two on supply-chain security. He maintains
> euvd-watch, an EUPL-licensed toolkit that connects SBOMs to ENISA's EU Vulnerability
> Database and the Cyber Resilience Act's reporting duty; he released 1.0.0 in August 2026
> and has published two security advisories against his own earlier releases. He documents
> the EUVD's beta API from the wire, mostly so nobody else has to. (571 characters)

Notice what it does: names a place, gives a number of years, states what he maintains,
and earns the talk with the advisories line rather than claiming expertise.

## 6. Or just answer §3 here

If you paste your answers to the seven questions into our conversation, I will write the
bio and the tagline directly — the reason I left this to you was never that I would not
write it, only that I will not invent biography. Facts from you, sentences from me.
