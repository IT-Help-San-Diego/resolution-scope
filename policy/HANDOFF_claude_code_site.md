# HANDOFF — Claude Code (frontend/site lane)

From: Hermes · Date: 2026-08-20 · Repo: `resolution-scope` @ main `36095a9`

## What this is

`resolutionscope.com` is **live and hardened** (DNS + hosting done). What
remains is **your lane**: the real site content/design + a GitHub repo + a
push-to-deploy pipeline. This is a handoff, not a request for infra work.

## Product positioning — READ THIS FIRST (a collusion was caught and fixed)

Resolution Scope is the **DNS resolution** instrument. It is NOT the
reasoning instrument. "Resolution" = DNS resolution, not reasoning.

- **Resolution Scope** = measures DNS resolution (8 controls: DNSSEC, DANE,
  SPF, DKIM, DMARC, MTA-STS, CAA, CDS/CDNSKEY), one truth-chain, SHA3-512
  sealed verdicts. Repo `resolution-scope` (AGPL-3.0).
- **Calibration Scope** = measures reasoning ("in any subject, on any
  substrate"). Different product, different domain (calibrationscope.com).

Do NOT reuse Calibration Scope's "measures reasoning… any subject, any
substrate" positioning for Resolution Scope. The honest framing is:

> "a sovereign instrument for measuring DNS resolution — what a domain
> actually publishes, verified against the protocol and sealed so anyone
> can re-check it."

## What's already deployed (verified live — do not re-provision)

| Resource | Value |
|---|---|
| Domain | `resolutionscope.com` (+ `www`, + sibling `resolutionscope.dev`) |
| S3 bucket | `resolutionscope.com-site` (us-west-2, private, OAC-only, versioned, AES256) |
| CloudFront | `E3R61QZ4G6BM8C` (`djd6cawr9o7rk.cloudfront.net`) |
| Headers policy | `0d6385ab-5b19-468a-8cfd-b66f9bbb9be8` |
| ACM cert | `arn:aws:acm:us-east-1:433198535569:certificate/aa124bf3-1295-4b9b-908c-537a26f8d91b` |
| OAC | `E3HVPPLL7EAOR` |
| Hosted zone | `Z06861878ZCLQVLWIW76` (com), `Z0978196WUN0HG9W0MC` (dev) |
| DNSSEC | signed + DS published, validating (KeyTag 7583 on both com+dev) |

Live checks: HTTPS 200 on apex + www, HTTP→HTTPS 301, `ad` flag set, full
A+ header set (`script-src 'none'`, `style-src 'self'`, HSTS preload, COOP/
COEP/CORP, `X-Permitted-Cross-Domain-Policies: none`, NO X-XSS-Protection).

## Your job

1. **Real site** replacing the placeholder now in the bucket (`index.html` +
   `style.css` + `404.html`). Family-standard: no-JS hardened HTML, dark
   scotopic theme (`#0d1117`/gold `#d4a853`/copper), owl semaphore branding,
   external `<link rel="stylesheet">` (NOT inline `<style>` — the header
   already pins `style-src 'self'`, no hash needed).
2. **GitHub repo** `IT-Help-San-Diego/resolution-scope` already exists (this
   repo, AGPL-3.0). Add the `site/` dir for content.
3. **Push-to-deploy Actions pipeline** — the `static-site-aws-cloudfront-deploy`
   skill's `templates/deploy.yml` pattern (immutable-asset sync + short-TTL
   text/xml + CloudFront invalidation), wired to the resource IDs above.
4. **House endpoints**: `llms.txt`, `.well-known/security.txt` (Canonical →
   resolutionscope.com), `sitemap.xml`, 1200×630 raster `og:image`.

## Constraints

- Zero executable JS (`script-src 'none'`). JSON-LD `ld+json` blocks are OK.
- No inline `style=` attributes (the header CSP uses `style-src 'self'` only).
- Self-host all assets (no external subresources — CSP forbids).
- "Demonstrate, don't sell" tone (Carey's standing rule) — no ad CTAs; quiet
  footer links to it-help.tech + calibrationscope.com already in the placeholder.
- AWS creds are in `~/.secrets_env` (do not echo).

See skill `hardened-static-site-aws-family` for the full house standard.
