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
