#!/usr/bin/env bash
# Accessibility gate (Step 6.3, plans/test_plan.md §M6 6.3): seeds the demo scenario
# exactly like examples/demo.sh (offline, primed cache, no network), serves the real
# dashboard, then runs scripts/a11y_check.mjs (axe-core via Puppeteer) against every
# page. Zero serious/critical axe violations is the gate; see that script's header
# for why it is not the `pa11y` CLI directly.
#
# Requires: euvd-watch installed with the [web] extra, and `npm ci` run at the repo
# root (puppeteer's bundled Chromium download happens then, not here).
#
#   ./scripts/run_a11y_check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

WORKDIR="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

export EUVD_WATCH_CACHE_DIR="$WORKDIR/cache"
export EUVD_WATCH_STATE_DIR="$WORKDIR/state"
export EUVD_WATCH_TIER2_PRODUCT_SEARCH=false
export EUVD_WATCH_ORGANIZATION__NAME="Demo Org"
export EUVD_WATCH_ORGANIZATION__CONTACT_EMAIL="sec@demo.org"
export EUVD_WATCH_ORGANIZATION__PRODUCT_NAME="Demo Product"

SBOM=examples/sboms/demo.cdx.json
PORT=8642
BASE="http://127.0.0.1:$PORT"
PASSWORD="a11y-check-only-$$"

echo "==> Seed the demo scenario offline (same fixture as examples/demo.sh)"
python scripts/prime_cache.py
# Seeding only needs state on disk; 1 (findings/new event) and 3 (indeterminate, because
# --no-enrich leaves KEV/EPSS unevaluable) are both normal here. Under `set -e` any code
# not listed aborts the whole a11y run, so 3 must be spelled out.
euvd-watch watch "$SBOM" --once --no-enrich || [ "$?" -eq 1 ]
euvd-watch cra check "$SBOM" --no-enrich || { code=$?; [ "$code" -eq 1 ] || [ "$code" -eq 3 ]; }

echo "==> Configure the dashboard"
HASH="$(printf '%s\n%s\n' "$PASSWORD" "$PASSWORD" | euvd-watch web hash-password | grep -o 'pbkdf2_sha256\$[^[:space:]]*')"
cat > "$WORKDIR/euvd-watch.yaml" <<EOF
web:
  password_hash: "$HASH"
organization:
  name: "Demo Org"
  contact_email: "sec@demo.org"
  product_name: "Demo Product"
EOF

echo "==> Start the dashboard"
euvd-watch --config "$WORKDIR/euvd-watch.yaml" web serve "$SBOM" --port "$PORT" \
  > "$WORKDIR/server.log" 2>&1 &
SERVER_PID=$!

up=""
for _ in $(seq 1 30); do
  if curl -s -o /dev/null "$BASE/static/dashboard.css"; then
    up=1
    break
  fi
  sleep 0.5
done
if [ -z "$up" ]; then
  echo "Dashboard never came up:"; cat "$WORKDIR/server.log"; exit 1
fi

AUTH="admin:$PASSWORD"
CRA_PATH="$(curl -s -u "$AUTH" "$BASE/cra" | grep -oE '/cra/[a-f0-9]+' | head -1)"
FINDING_PATH="$(curl -s -u "$AUTH" "$BASE/findings" | grep -oE '/findings/[a-f0-9]+/EUVD-DOGFOOD-0001' | head -1)"

if [ -z "$CRA_PATH" ] || [ -z "$FINDING_PATH" ]; then
  echo "Could not extract seeded finding/event URLs from the running dashboard."
  exit 1
fi

echo "==> Run the axe accessibility check against every page"
export A11Y_AUTH_HEADER="Basic $(printf '%s' "$AUTH" | base64 -w0)"
node scripts/a11y_check.mjs \
  "$BASE/" \
  "$BASE/findings" \
  "$BASE$FINDING_PATH" \
  "$BASE/cra" \
  "$BASE$CRA_PATH" \
  "$BASE$CRA_PATH/draft" \
  "$BASE/audit"
