# Industry DNSSEC posture — cross-check of the SciSpace sweep (2026-08-23)

Claude Code lane, measured 2026-08-23 ~23:50 UTC from the local vantage
(macOS, dig via 1.1.1.1 validating resolver + Verisign RDAP + CISA page via
real browser). SciSpace's sweep (tasks 105–110, Verisign DNSSEC Debugger +
web research, cloud vantage) relayed by Carey; every claim below is marked
by who verified it and how. Discipline: relayed ≠ verified; a claim carries
only the strength of its named verification path.

## 1. Posture scorecard — VERIFIED, three disjoint paths

Paths: (a) SciSpace via Verisign DNSSEC Debugger (2026-08-23, screenshots in
its sandbox, results for akamai/markmonitor asserted but not shown in the
relay); (b) this lane via `dig DS` + `dig DNSKEY` + AD flag through 1.1.1.1;
(c) registry RDAP `secureDNS.delegationSigned` (apple.com, google.com).

| Zone | DS | DNSKEY | AD flag | Verdict |
|---|---|---|---|---|
| apple.com | none | none | no | UNSIGNED (a+b+c) |
| google.com | none | none | no | UNSIGNED (a+b+c) |
| microsoft.com | none | none | no | UNSIGNED (a+b) |
| markmonitor.com | none | none | no | UNSIGNED (b; a asserted-unshown) |
| icloud.com | none | none | no | UNSIGNED (a+b) |
| apple-dns.net | none | none | no | UNSIGNED (a+b) |
| cloudflare.com | yes | yes | **ad** | SIGNED+VALIDATING (a+b) |
| akamai.com | yes | yes | **ad** | SIGNED+VALIDATING (b; a asserted-unshown) |
| smtp.goog | yes | yes | **ad** | SIGNED+VALIDATING (a+b) |
| mx.microsoft | yes | yes | **ad** | SIGNED+VALIDATING (a+b) |

The split: infrastructure operators (Cloudflare, Akamai) sign their apex;
platform companies (Apple, Google, Microsoft) and brand registrar
MarkMonitor do not; Google and Microsoft each maintain a signed island
under a vanity TLD.

## 2. The mail-path measurement (new, this lane)

- `apple.com` MX: mx-in.g.apple.com + five regional mx-in hosts — **all
  inside unsigned apple.com space** (g.apple.com: no DS). Apple's mail path
  is unverifiable end-to-end; DANE is structurally impossible for it today.
  NS estate is in-house (a–d.ns.apple.com).
- `google.com` MX: smtp.google.com (unsigned zone); gmail.com and
  grow.google MX also resolve into unsigned google.com space. **No probed
  Google domain's MX points at the signed smtp.goog island**, and
  `_25._tcp.mx1.smtp.goog` / `_25._tcp.mx2.smtp.goog` /
  `_25._tcp.smtp.google.com` carry **no TLSA** (mx1.smtp.goog exists —
  NOERROR — but publishes no address records to us).
- `microsoft.com` MX: microsoft-com.mail.protection.outlook.com (classic
  unsigned path). `microsoft-com.mx.microsoft` returns NOERROR (name space
  exists) but no TLSA at `_25._tcp.`.

**Thesis strength, honestly stated:** "Google/Microsoft sign where DANE
matters" (SIDN's framing) is verified only up to *capability*: the signed
mail islands exist and validate, but from this vantage no live TLSA and no
MX referral into either island was observed. Record it as: signed
DANE-capable islands exist; DANE-in-use unconfirmed here; Apple has no
signed island at all — not even mail. (SciSpace's open task: TLSA
verification with tenant-level hostnames.)

## 3. Registrar decode (Carey's recollection, verified)

RDAP: apple.com registrar = **Nom-iq Ltd. dba COM LAUDE**; google.com
registrar = **MarkMonitor Inc.** Carey's dictated "Apple now has come
loud" = **Com Laude** — his memory was right; Wispr garbled the brand.
("Apple was previously MarkMonitor" remains unverified history — RDAP shows
only the present.) Note the shape: the registrar guarding google.com does
not sign its own zone (markmonitor.com unsigned), while apple.com's DNS is
run in-house on Apple's own NS with the delegation unsigned.

## 4. The statistics question ("where is the IC3 category?")

Carey's instinct is correct and the answer is doctrinal:

- **No IC3/FBI category exists** for DNS hijacking / cache poisoning
  (SciSpace, relayed; consistent with IC3's published category lists).
- **The state's severity measurement exists in a different register:**
  CISA **Emergency Directive 19-01** ("Mitigate DNS Infrastructure
  Tampering", January 22, 2019 — verified first-hand on cisa.gov this
  session). Its own background text: attackers who alter DNS records "can
  also obtain **valid encryption certificates** for an organization's
  domain names… **Since the certificate is valid for the domain, end users
  receive no error warnings.**" Multiple executive-branch domains were
  impacted. That is the government stating that the cert layer does not
  survive DNS-layer compromise — an emergency directive is what a
  crime-statistics line looks like at the nation-state tier.
- **The class DNSSEC uniquely closes leaves no receipt.** ED 19-01's class
  (credential-based record tampering at registrar/operator) is visible
  after the fact and only partially mitigated by DNSSEC (an attacker with
  registrar control can eventually strip DS — slowly and visibly). The
  in-transit class — off-path/on-path forgery against resolvers — produces
  no victim-side artifact: a poisoned resolution is indistinguishable from
  a real one at the endpoint, so it structurally cannot generate incident
  reports. Absence from crime statistics is therefore **Indeterminate, not
  Absent** — the project's own absent≠unmeasured doctrine applied to the
  threat ledger. Do not let the topology page read "no statistics" as "no
  attacks"; equally, do not cite the absence as evidence of prevalence.

## 5. Precision flags on the relayed material (before anything publishes)

- **MyEtherWallet 2018:** SciSpace's summary says BGP→DNS→"fraudulent
  cert". Contemporaneous write-ups (recalled, not re-fetched this session)
  describe a **self-signed** cert with browser warnings users clicked
  through (~$150K stolen). If the topology page repeats "valid cert" for
  MEW, re-verify at source first; the *valid-cert* mechanism is instead
  government-confirmed for the ED 19-01 campaign class (§4 quote).
- **Akamai/MarkMonitor:** SciSpace asserted both without shown output;
  both now verified by this lane (§1) — flag resolved.
- **Adoption/validation percentages** (NA <4%, .nl ~60%, Finland 95%,
  CZ 89%, Norid model, SIDN Registrar Scorecard, CZ.NIC/Knot history):
  relayed with sources, **not re-verified here**. Treat as
  cited-secondary until a lane pins them to primary stats (APNIC labs /
  SIDN/CZ.NIC publications) if they are to appear in public copy.

## 6. What this feeds

- **Claude Science (evidence standard, task 107 framing):** the Apple
  finding now has the strongest honest form — not "Apple fails" but:
  Apple's entire estate (apex, iCloud, apple-dns.net, and the whole mail
  path) is unverifiable to any validating resolver, while peers sign
  infrastructure (Cloudflare, Akamai) or at minimum built signed mail
  islands (Google, Microsoft). Unsigned ≠ insecure internally; unsigned =
  forgeable-in-transit to every relying party, and DNSSEC(+DANE for SMTP)
  is the only closure for the no-receipt attack class (§4).
- **Topology page:** the scorecard (§1) and the islands nuance (§2) are
  publishable as measured; §5's flags gate the narrative claims.
- **Resolution Scope engine:** our instrument's own verdicts on these
  domains are the next differential specimen set (engine currently
  measures exactly this DNSSEC/DANE/MX surface).
