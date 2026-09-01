#!/bin/bash
# publish-report.sh — measure a domain with the CLI and publish the sealed
# HTML report to https://resolutionscope.com/r/<domain>/<UTC-timestamp>.html
#
# The client-shareable report path, still with NO server: the report is a
# static, self-contained page whose seal re-derives from its own printed
# bytes. Publishing is one conditional S3 put behind the same bucket the site
# deploy uses.
#
# Requires:
#   - rescope on PATH (or RESCOPE=/path/to/resolution-scope)
#   - AWS credentials with s3:PutObject + cloudfront:CreateInvalidation
#   - RS_S3_BUCKET and RS_CF_DIST_ID in the environment (same values as the
#     deploy workflow's secrets)
#
# PRECONDITION — a store must be reachable (compose store up, or
# RS_STORE_URL set): the scan records to the sealed-history store per the
# persist-by-default ruling. This script deliberately does NOT pass
# --discard — a published report whose verdict was never recorded would be
# a report without a history row. On store refusal the CLI exits nonzero
# (its only exit codes: 2 = corpus-excluded fixture, 1 = propagated error;
# there is NO findings-based exit) and `set -e` aborts BEFORE any s3 cp —
# an unpersisted report is never published. Do not add an exit-code
# bypass; the abort is the doctrine working.
#
# Bucket-lifetime invariant: deploy-site.yml's HTML sync step carries
# --exclude "r/*" so published reports survive `s3 sync --delete` on site
# deploys. If the key prefix below ever changes, change that exclude in the
# same commit.
set -euo pipefail

DOMAIN="${1:?usage: publish-report.sh <domain> [YYYYMMDD-HHMMSS]}"
STAMP="${2:-$(date -u +%Y%m%d-%H%M%S)}"

: "${RS_S3_BUCKET:?RS_S3_BUCKET not set — the site bucket name (value of the deploy workflow's RS_S3_BUCKET secret)}"
: "${RS_CF_DIST_ID:?RS_CF_DIST_ID not set — the CloudFront distribution id (value of the deploy workflow's RS_CF_DIST_ID secret)}"

RESCOPE="${RESCOPE:-rescope}"
command -v "$RESCOPE" >/dev/null 2>&1 || {
  echo "no rescope on PATH — build it (cargo build --release, cli/) or set RESCOPE=/path/to/resolution-scope" >&2
  exit 1
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
OUT="$WORK/report.html"

"$RESCOPE" "$DOMAIN" --format html -o "$OUT"
[ -s "$OUT" ] || { echo "CLI produced no report for $DOMAIN" >&2; exit 1; }

# Tier-3 tripwire at the artifact boundary (the deferral-ships-tripwire
# standard, instance 1). The page's own re-derive block names its scheme
# and carries one name=Disposition=Tri line per SEALED control; every
# scheme seals an exact count (v3/v4: the founding eight; v5: ten). A
# binary that renders more controls than its scheme seals would publish
# a page whose seal is silent on rendered verdicts — the forbidden
# artifact. Refuse it here, mechanically, not in anyone's memory.
# (Exit 3 = tripwire, distinct from scan-error 1.)
#
# The table is exhaustive BY DESIGN (verifier-seat finding, 2026-08-31):
# the v4-only equality condition expired the moment #36 ships v5 — any
# future scheme published clean, hazards included. Unknown schemes
# refuse here (the next bump becomes impossible to forget), and a
# non-numeric count refuses here too (grep error → empty string →
# integer-expression error → previously fell through to publish; that
# fail-open path is closed). The guard-in-the-direction-of-the-real-
# mistake principle applied to the guard itself: refuse FIRST, publish
# only on a known-scheme/exact-count match.
SCHEME=$(grep -oE 'resolution-scope-sha3-512-v[0-9]+' "$OUT" | head -1 || true)
CONTROL_LINES=$(grep -cE '^[a-z_]+=[A-Za-z0-9]+=(Present|Absent|Indet|NotApplicable)$' "$OUT" || true)
if [ -z "$SCHEME" ]; then
  echo "tripwire: no seal scheme found in the report — refusing to publish an unsealed page" >&2
  exit 3
fi
# Fail-closed on a non-numeric count: a grep error must never fall through.
if ! [[ "$CONTROL_LINES" =~ ^[0-9]+$ ]]; then
  echo "tripwire: sealed-control line count is not a number (got '$CONTROL_LINES') — refusing to publish" >&2
  exit 3
fi
case "$SCHEME" in
  resolution-scope-sha3-512-v3|resolution-scope-sha3-512-v4)
    EXPECTED=8
    ;;
  resolution-scope-sha3-512-v5)
    EXPECTED=10
    ;;
  *)
    echo "tripwire: unknown seal scheme '$SCHEME' — refusing to publish (add its exact control count to the tripwire table when the scheme is minted; the seal event must ship WITH its tripwire, never after)" >&2
    exit 3
    ;;
esac
if [ "$CONTROL_LINES" -ne "$EXPECTED" ]; then
  echo "tripwire: $SCHEME seals exactly $EXPECTED controls but this page carries $CONTROL_LINES sealed-control lines — refusing to publish (the page's seal cannot cover this report; ship the seal event first)" >&2
  exit 3
fi

KEY="r/${DOMAIN}/${STAMP}.html"
aws s3api put-object \
  --bucket "$RS_S3_BUCKET" \
  --key "$KEY" \
  --body "$OUT" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public,max-age=3600,stale-while-revalidate=86400" \
  --if-none-match "*" >/dev/null

INVALIDATION=$(aws cloudfront create-invalidation --distribution-id "$RS_CF_DIST_ID" \
  --paths "/${KEY}" --query 'Invalidation.Id' --output text)

echo "published: https://resolutionscope.com/${KEY} (invalidation ${INVALIDATION})"
