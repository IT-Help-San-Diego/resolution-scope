# Baseline: DNSSEC algorithm 18 (ML-DSA-44) in the public DNS — 2026-08-29

**The claim, in one sentence:** as of 2026-08-29, DNSSEC algorithm 18 is an
assigned number with no *known* implementing signer and no measured publisher —
the post-quantum transition's failure mode (RFC 4035 §5.2, March 2005) is fully
armed while its measured trigger population is zero.

**Why publish a null result:** the first zone on Earth to publish algorithm 18
becomes detectable by re-running the queries below. Run twice, this baseline is
a longitudinal series; the null is the instrument, not the disappointment.
(Framing: claude-science lane, 2026-08-29. Measurements: two lanes
independently, receipts below.)

## The four facts, each re-derivable

### 1. The number is assigned

IANA `dns-sec-alg-numbers`, row 18: **ML-DSA-44, MLDSA44, ZoneSigning=Y**,
Signing MAY / Validation MAY, reference `draft-westerbaan-dnssec-mldsa-03`
(individual, informational — an early allocation, which is the normal order:
number first, implementations second).

Re-derive:

```bash
curl -s "https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers-1.csv" | grep "^18,"
```

Measured 2026-08-29 by two lanes independently (claude-code fetch; claude-science
fetch after its RFC-index-only search initially missed it — the RFC series is
not the registry that governs algorithm numbers).

### 2. No signer is known to implement it

Three evidence classes, at three different strengths — stated separately so
none inflates another (v2 correction, claude-science's own audit: a four-repo
code search is not a universal negative):

- **Open-source mainline** (BIND, Knot, PowerDNS, OpenDNSSEC): zero
  `ML-DSA`/`MLDSA` occurrences by code search (claude-science, 2026-08-29).
  **Caveat:** GitHub code search can be incompletely indexed — each project's
  algorithm-support table is the authoritative check, part of the re-run
  protocol.
- **Proprietary signers** (Route 53, Cloudflare, Verisign sign with in-house
  code): **NOT MEASURED** — nobody searched code nobody can read. One outward
  constraint IS measured: Route 53's public interface requires an
  `ECC_NIST_P256` KMS key (algorithm 13, the only option), which bounds what
  its signer can emit regardless of implementation. Cloudflare's and
  Verisign's own zones publish algorithm 13 today — evidence of current
  output, not of capability.

**Precision from the other lane's hunt:** research *forks* did implement the
predecessor — desec-io/pqc-dnssec (deSEC + SandboxAQ + PowerDNS field study,
DNS-OARC 43 / IETF 120) patched PowerDNS and BIND to sign with Falcon-512,
**Dilithium-2 (ML-DSA-44's pre-standardization form)**, SPHINCS+, and XMSS —
under *experimental* codepoints, pre-FIPS-204, not codepoint 18. So the exact
state is: **mainline signers: nothing; research forks: the predecessor, under
different numbers.** No software anywhere is known to emit algorithm-18-proper
records today.

### 3. No measured zone publishes it

Two independent surveys, 2026-08-29:

- **19 DNSSEC-forward zones** (adopter-biased by design — a sample biased
  toward finding the thing, that finds zero, beats a random sample of the same
  size): 13 publish DS, all algorithm 8 (×4) or 13 (×9); 6 publish none;
  **algorithm 18: zero** (also zero 15/16 — the eager cohort sits entirely on
  RSA-SHA256/ECDSA-P256). Re-derive:

```bash
for d in nlnetlabs.nl posteo.de mailbox.org iij.ad.jp open.nl cloudflare.com \
         ietf.org ripe.net internetsociety.org gov.uk apache.org wikipedia.org \
         dnssec-failed.org example.com example.net opendns.com dnssec-tools.org \
         kernel.org python.org; do
  printf "%s: " "$d"; dig +short DS "$d" @1.1.1.1 | awk '{print $2}' | sort -un | tr '\n' ' '; echo
done
```

- **14 guessed research hostnames** (pq-dnssec.nlnetlabs.nl, mldsa.nic.cz, et
  al.): NXDOMAIN; real research zones (research.cloudflare.com,
  cloudflareresearch.com, sidnlabs.nl) sign with algorithm 13
  (claude-science). **Caveat:** guessed hostnames are not a survey — absence
  means "not at the names tried."

- The one public PQ-DNSSEC testbed (`pq-dnssec.dedyn.io`, field-study era
  2023–24): parent answers under algorithm 13; the falcon/dilithium/sphincs
  example subzones are dark via public resolvers today (claude-code dig,
  2026-08-29).

- `draft-westerbaan-dnssec-mldsa` itself names **no test zones** — its only
  domain is a deterministic, byte-reproducible pedagogical example
  (claude-code fetch of the draft, 2026-08-29).

### 4. The failure mode predates the deployment by two decades

RFC 4035 §5.2 (March 2005), verbatim from the corpus, verified independently by
three lanes this week:

> "If the resolver does not support any of the algorithms listed in an
> authenticated DS RRset ... the resolver SHOULD treat the child zone as if it
> were unsigned."

RFC 6840 §5.2 extends the same rule to unsupported DS digest algorithms. A
validator meeting the post-quantum transition is *required* to misreport
"cannot evaluate" as "not signed" — unless it is an instrument rather than a
resolver. This repo's engine discriminates the two states
(`DnssecDisposition::ChainUnverified`, merged 2026-08-29, PR #31): an
authenticated DS RRset with no evaluatable record reports **"could not
evaluate," never "not signed."**

## The re-run protocol

1. IANA row 18 (curl above) — has the reference matured past draft?
2. Signer support tables — BIND ARM, Knot docs, PowerDNS docs, OpenDNSSEC
   docs: does any list ML-DSA-44? (Authoritative for the open-source half of
   fact 2.) For the proprietary half: provider documentation and announcements
   (Route 53 KMS key specs, Cloudflare blog/docs, Verisign) — the only
   readable surfaces of unreadable signers.
3. The 19-zone dig (above) — does any DS carry algorithm 18?
4. This repo's gate — `cargo test -p resolution-scope-engine rfc_known_answer_vectors`
   still pins D5a–D5j.

Any change in 1–3 is a finding. The day step 3 returns an 18, that zone is one
of the first post-quantum DNSSEC publishers on Earth, and this baseline is the
before-photograph.

## Standing proposal (not started — Carey/hermes decision)

Delegate a child zone (e.g. `pq.resolutionscope.com`) to a self-hosted signer
extended from the pqc-dnssec fork architecture to FIPS-204 ML-DSA-44 at
codepoint 18, DS published in the Route 53 parent we control (Route 53's own
signing is algorithm-13-only — measured against AWS docs 2026-08-29 — so the
child must live on our signer). That zone would be the gate's live positive
control and, per fact 2, plausibly the first algorithm-18-proper zone in the
public DNS.
