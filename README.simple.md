# euvd-watch, explained simply 🧁

*The same project as in [README.md](README.md), but told so that anyone — even a kid — can understand it.*

## The cake story

Imagine every computer program is a **cake**. 🎂

Nobody bakes a cake completely from scratch. You use **ingredients** made by other people: flour from one company, chocolate from another, sprinkles from a third. Programs are the same — they are built from many small pieces written by other people.

Now imagine there is a **list of ingredients** taped to the side of every cake box. For programs, that list is called an **SBOM**. It says exactly which pieces are inside, and which version of each piece.

## The problem

Sometimes, people discover that an ingredient is **bad**. Maybe a batch of chocolate turns out to be spoiled. 😱

In Europe, there is a big official notebook where all the bad ingredients are written down, the moment someone discovers them. It is called the **EUVD**, and it is kept by the EU's security agency (ENISA). The notebook even marks which bad ingredients are **being used by burglars right now** — those are the most dangerous ones.

But here's the thing: nobody has time to read your cake's ingredient list, then read the whole giant notebook, and compare them line by line, **every single day**. And new bad ingredients are added to the notebook all the time — even for cakes you baked last year!

## What euvd-watch does

**euvd-watch is a robot helper that does the comparing for you.** 🤖

Every day, it:

1. **Reads your cake's ingredient list** (your SBOM).
2. **Checks it against Europe's notebook of bad ingredients** (the EUVD).
3. **Tells you only what matters:** "Hey! The chocolate in your cake is on the bad list — and burglars are using it RIGHT NOW!"

It also does two clever extra things:

4. **It writes little notes explaining why some warnings are false alarms.** Sometimes an ingredient is on the bad list, but *your* batch is fine (you used version 2, and only version 1 was spoiled). The robot writes that down in a note (called **VEX**) so nobody panics for nothing. But the robot is very careful: **it only says "this is fine" when it can prove it.** If it's not 100% sure, it says "a human should look at this."
5. **It helps you tell the authorities in time.** In Europe there's a rule (the CRA): if a dangerous, actively-used bad ingredient is in your cake, you must inform the authorities **within 24 hours** of finding out. The robot starts a countdown timer ⏰, pre-writes the message for you, and keeps a diary of everything that happened — a special diary where **nobody can secretly rip out or change a page** without it being noticed.

One important rule: **the robot never sends anything by itself.** A human always reads the message, checks it, and presses "send". The robot just makes sure you're never late and never forget anything.

## Why it matters

- Bakers (programmers) find out about dangerous ingredients **fast**, instead of finding out from the news.
- People don't waste time on **false alarms**.
- Companies can **prove** they did the right thing, at the right time.
- And it's **free and open** — anyone can look inside the robot to check how it works, and anyone can use it. 🇪🇺

## The short version

> Your program has an ingredient list. Europe has a notebook of dangerous ingredients. **euvd-watch checks them against each other every day, warns you about the real dangers, calms you about the false alarms, and helps you notify the authorities in time — with a human always pressing the final button.**

That's it! For grown-up details, see the [full README](README.md).
