#!/usr/bin/env bash
# verify.sh — house-invariant check for the resolutionscope.com static site.
# EXTERNAL-CSS variant: this site's CloudFront headers policy pins
# style-src 'self', so the invariant is "no <style> blocks, no inline
# style=, stylesheet linked" — there is NO CSP hash to sync here.
# Dependency-free: bash + python3 stdlib. Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")"
python3 - <<'PY'
import re, json, os, struct, sys

fails = []
def k(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond: fails.append(name)

pages = ["index.html", "404.html"]
for page in pages:
    html = open(page, encoding="utf-8").read()
    p = page + ": "
    # External-CSS invariants (style-src 'self' — a <style> block would be BLOCKED live)
    k(p + "no <style> blocks (would be CSP-blocked live)", "<style" not in html)
    k(p + "external stylesheet linked", 'rel="stylesheet"' in html)
    k(p + "zero inline style= attributes", len(re.findall(r'\sstyle="[^"]*"', html)) == 0)
    k(p + "only ld+json <script> blocks",
      all("application/ld+json" in s for s in re.findall(r"<script[^>]*>", html)))
    k(p + "no external subresources",
      len(re.findall(r'(?:src|srcset)="https?://[^"]*"', html)) == 0)
    k(p + "CSP meta present", "Content-Security-Policy" in html)
    k(p + "no PLACEHOLDER tokens", "PLACEHOLDER" not in html)

html = open("index.html", encoding="utf-8").read()

# JSON-LD validity
m = re.search(r'<script type="application/ld\+json">(.*?)</script>', html, re.S)
k("JSON-LD block present", bool(m))
if m:
    try: json.loads(m.group(1)); k("JSON-LD parses", True)
    except Exception as e: k(f"JSON-LD parses ({e})", False)

# OG image must be a raster (Apple/iMessage will NOT render an SVG og:image)
og = re.search(r'property="og:image"\s+content="([^"]+)"', html)
k("og:image present", bool(og))
if og:
    k("og:image is raster (not svg — iMessage requirement)",
      not og.group(1).lower().endswith(".svg"))
    local = og.group(1).replace("https://resolutionscope.com/", "")
    k("og:image file exists in repo", os.path.exists(local))
    if os.path.exists(local) and local.endswith(".png"):
        with open(local, "rb") as f:
            sig, ihdr = f.read(16), f.read(8)
            w, h = struct.unpack(">II", ihdr)
        k(f"og:image is 1200x630 (got {w}x{h})", (w, h) == (1200, 630))

# Retired-vocabulary / product-boundary guard (case-insensitive, all shipped text).
# 'provenance' and 'proof of measurement' are forbidden seal vocabulary —
# seal.rs: the seal is tamper-evidence ("anyone can verify this verdict is the
# one that was sealed"); overstating it as proof a measurement occurred is the
# one thing the instrument must not do. The rest are Calibration Scope framing —
# the caught collusion must not regrow (Resolution Scope = DNS resolution).
FORBIDDEN = ["provenance", "proof of measurement", "proof-of-measurement",
             "any subject", "any substrate", "minds can actually do"]
shipped_ext = (".html", ".svg", ".txt", ".xml", ".json", ".webmanifest", ".css")
stale = []
for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in (".git",)]
    for fn in files:
        if not fn.lower().endswith(shipped_ext): continue
        txt = open(os.path.join(root, fn), encoding="utf-8", errors="ignore").read().lower()
        stale += [f"{fn}: '{ph}'" for ph in FORBIDDEN if ph in txt]
k("no retired/colluded phrases in shipped files" + (f" (hits: {stale})" if stale else ""),
  not stale)

# House endpoints
k("security.txt has Expires", "Expires:" in open(".well-known/security.txt").read())
k("robots.txt names the sitemap", "sitemap.xml" in open("robots.txt").read())
import xml.dom.minidom as X
try: X.parse("sitemap.xml"); k("sitemap.xml well-formed", True)
except Exception as e: k(f"sitemap.xml well-formed ({e})", False)

if fails:
    print("=" * 52); print(f"FAILED: {len(fails)} check(s)"); sys.exit(1)
print("=" * 52); print("All checks passed.")
PY
echo "site/verify.sh: OK"
