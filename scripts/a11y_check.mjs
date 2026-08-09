#!/usr/bin/env node
// SPDX-License-Identifier: EUPL-1.2
//
// Accessibility gate for the dashboard (Step 6.3, plans/test_plan.md §M6 6.3):
// "pa11y (axe) against every page ... zero serious/critical violations gate."
//
// Deliberately NOT the `pa11y` CLI itself: its bundled axe runner
// (node_modules/pa11y/lib/runners/axe.js) maps BOTH axe's `violations` (definite
// failures) and `incomplete` (axe could not determine a verdict - needs a human,
// per axe-core's own results schema) through the same `axeImpactToPa11yLevel()`
// severity mapping, so a serious-impact `incomplete` result is reported as an
// `error` indistinguishable from a real `violation`. In this dashboard that
// produces exactly one recurring false-positive class: `color-contrast` marked
// "incomplete" on elements with a transparent background over a layered
// flex/grid ancestor chain (icons, badge numerals) that axe's background-detection
// heuristic can't resolve through - confirmed by running axe.run() directly and
// inspecting the `incomplete` array (see docs/accessibility.md's "Known axe
// incomplete results" section for the specific elements and the manual contrast
// verification). Gating CI on pa11y's collapsed severity would make the a11y job
// permanently, unfixably red for a documented tooling limitation - not a real
// defect. This script uses the identical axe-core engine (same dependency pa11y
// itself wraps) but gates ONLY on `violations` with impact serious/critical, which
// is the literal acceptance criterion; `incomplete` results are printed for
// visibility and covered by the manual pass in docs/accessibility.md instead.
//
// Usage: node scripts/a11y_check.mjs <url> [<url> ...]
// Env:   A11Y_AUTH_HEADER - full "Basic <base64>" value sent as the Authorization
//        header on every request (the dashboard requires HTTP Basic on every route).

import puppeteer from "puppeteer";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const axeSource = readFileSync(require.resolve("axe-core"), "utf8");

const urls = process.argv.slice(2);
if (urls.length === 0) {
  console.error("Usage: node scripts/a11y_check.mjs <url> [<url> ...]");
  process.exit(2);
}

const authHeader = process.env.A11Y_AUTH_HEADER;

let failed = false;

const browser = await puppeteer.launch({ args: ["--no-sandbox"] });
try {
  for (const url of urls) {
    const page = await browser.newPage();
    if (authHeader) {
      await page.setExtraHTTPHeaders({ Authorization: authHeader });
    }
    await page.goto(url, { waitUntil: "networkidle0", timeout: 30000 });
    await page.evaluate(axeSource);
    const results = await page.evaluate(async () => {
      // eslint-disable-next-line no-undef
      return await axe.run(document, {
        runOnly: {
          type: "tags",
          values: ["wcag2a", "wcag21a", "wcag2aa", "wcag21aa", "best-practice"],
        },
      });
    });
    await page.close();

    const serious = results.violations.filter(
      (v) => v.impact === "serious" || v.impact === "critical",
    );
    const otherViolations = results.violations.filter(
      (v) => v.impact !== "serious" && v.impact !== "critical",
    );

    console.log(`\n=== ${url} ===`);
    if (serious.length === 0) {
      console.log("  no serious/critical violations");
    } else {
      failed = true;
      for (const v of serious) {
        console.log(`  VIOLATION [${v.impact}] ${v.id}: ${v.help}`);
        for (const node of v.nodes) {
          console.log(`    - ${node.html}`);
        }
      }
    }
    for (const v of otherViolations) {
      console.log(`  (minor/moderate, not gated) ${v.id}: ${v.help}`);
    }
    for (const v of results.incomplete) {
      console.log(`  (incomplete - needs human review, not gated) ${v.id}: ${v.help}`);
      for (const node of v.nodes) {
        console.log(`    - ${node.html}`);
      }
    }
  }
} finally {
  await browser.close();
}

if (failed) {
  console.error("\nFAILED: one or more pages have a serious/critical axe violation.");
  process.exit(1);
}
console.log("\nOK: zero serious/critical axe violations across all pages.");
