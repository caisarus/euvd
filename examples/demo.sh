#!/usr/bin/env bash
# End-to-end demo of the euvd-watch pipeline (plans/test_plan.md X.2), fully OFFLINE:
# the HTTP cache is primed from committed fixtures, so no network is needed — which is
# also why CI can run this script on every PR. Requires: euvd-watch installed
# (`pip install -e .` from the repo root).
#
#   ./examples/demo.sh
set -euo pipefail
cd "$(dirname "$0")/.."

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
export EUVD_WATCH_CACHE_DIR="$WORKDIR/cache"
export EUVD_WATCH_STATE_DIR="$WORKDIR/state"
# Offline: tier-2 sends one live search per component product; only the exploited
# catalog is primed. (match --exploited-only skips tier 2 by itself; watch does not.)
export EUVD_WATCH_TIER2_PRODUCT_SEARCH=false

SBOM=examples/sboms/demo.cdx.json

echo "==> 0. Prime the HTTP cache from a committed fixture (offline mode)"
python scripts/prime_cache.py

echo
echo "==> 1. scan: what is inside the SBOM?"
euvd-watch scan "$SBOM"

echo
echo "==> 2. match: exploited vulnerabilities only (served from the primed cache)"
# --fail-on none: the demo narrates findings, it is not a CI gate.
euvd-watch match "$SBOM" --exploited-only --no-enrich --fail-on none \
  --save-findings "$WORKDIR/findings.json"

echo
echo "==> 3. vex generate: conservative OpenVEX statements from those findings"
euvd-watch vex generate "$SBOM" --findings "$WORKDIR/findings.json" \
  --out "$WORKDIR/openvex.json"
echo "wrote $WORKDIR/openvex.json"

echo
echo "==> 4. cra check: did anything cross the CRA reporting trigger?"
# Exit 1 means a NEW event opened - expected here, the demo catalog is seeded with an
# actively exploited record that matches the demo SBOM.
euvd-watch cra check "$SBOM" --findings "$WORKDIR/findings.json" || [ "$?" -eq 1 ]

echo
echo "==> 5. cra status: the running deadline clocks"
euvd-watch cra status

echo
echo "==> 6. watch --once: first run reports the findings as new ..."
euvd-watch watch "$SBOM" --once --no-enrich || [ "$?" -eq 1 ]

echo
echo "==> 7. ... and an unchanged second run reports nothing (exit 0)"
euvd-watch watch "$SBOM" --once --no-enrich

echo
echo "demo complete"
