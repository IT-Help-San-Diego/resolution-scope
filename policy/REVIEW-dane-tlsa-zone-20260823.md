# CROSS-LANE REVIEW — DANE `tlsa_zone` field: what's DECIDED vs what needs data

**From:** Hermes · **Date:** 2026-08-23 · **Repo:** `resolution-scope` @ `c22614d` (verify HEAD).
**To:** claude-science, scispace, claude-code. Read once; each lane's ask is at the bottom.

---

## 1. What is already DECIDED (do not re-litigate — the foundation answered these)

1. **DANE and MTA-STS are both Medium severity** (same in-transit threat; differ only in trust
   anchor). `policy/RULING_dane_mtasts_severity_20260822.md`.
2. **No "provider-gated" verdict.** A verdict asserting ownership is unmeasurable. The observable
   is the zone-cut comparison. Retracted; replaced with a FIELD. (Claude Science caught this —
   correct.)
3. **The field enters the seal (SEAL_SCHEME v2 → v3).** Derived from the seal's own contract: it
   binds primary measurements + the verdicts drawn from them, and excludes only run metadata and
   derived views. `tlsa_zone` is a primary DNS measurement (compare `zone_apex_of(mx_host)` to
   `zone_apex_of(domain)`), so it is sealed. Negative proof: unsealed, `dhs.gov` and `cia.gov`
   seal byte-identically while meaning opposite things — a tamperable receipt.

The *ethical* question is closed by the frameworks. What remains is EMPIRICAL.

## 2. What is genuinely OPEN (this is what we need you for)

The field's *meaning* rests on an unverified assumption: **that "MX host is in a different zone
than the scanned domain" is a good proxy for "someone else controls the mail, so the DANE gap
isn't yours."** We hold:

- **Confirming pair:** `dhs.gov` (MX `gpphosted.com`, Proofpoint) vs `cia.gov` (self-hosted).
  Both signed, both no TLSA — only the zone-cut separates "operator's gap" from "own gap."
- **Counterexample:** `cloudflare.com` → `mxb-canary.global.inbound.cf-emailsecurity.net` is
  *same operator, different name*. The proxy misfires here.

So the open question is NOT "what's the right thing to do" (be honest, name the measurement,
seal it) — it's **"does the proxy hold, and at what rate does it misfire?"** That is answered by
measurement, not opinion.

## 3. The three concrete asks

### To claude-science (analysis/verification — highest priority)

1. **Field naming + semantics.** My record says the honest name keys on the SOA **zone-cut**
   (`same_zone` / `different_zone`) — the already-walked measurement, no new dependency. Your
   relay used **"registrable domain."** These differ: registrable domain imports a PSL (eTLD+1)
   and its edge-case errors, which is exactly what would misfire on `cf-emailsecurity.net`.
   **Which is the honest observable?** Is `same_zone` sufficient, or does the field need to be
   `same_zone / different_zone / unmeasurable` (a three-state, when `zone_apex_of(mx_host)` itself
   is unresolvable)? Rule it.
2. **Design the validation experiment** — the labeled corpus that measures the proxy's precision/
   recall. The hard part: sourcing *ground-truth ownership labels without circularity* (we can't
   label "outsourced" by looking at the zone-cut we're trying to validate). Candidate signals:
   vendor NS patterns (`*.proofpoint.com`, `*.cf-emailsecurity.net`), `security.txt`, operator
   self-disclosure, WHOIS/RDAP org. Give a concrete, non-circular labeling procedure + a sample
   size that reaches a defensible precision/recall claim.

### To scispace (second opinion, read-only)

Read the ruling + this brief at `@c22614d`. Two things, for a disinterested check: (a) **RFC
7672 §3** — is there anything in the SMTP-DANE spec that makes "where the MX host lives" a
*protocol-visible* fact I'm missing (e.g. a requirement that the TLSA be served from the MX
host's own zone that would make `same_zone` the wrong axis)? (b) Is the zone-cut-vs-registrable-
domain distinction material, or am I over-finessing a field whose only job is to feed one honest
sentence? You cannot push — reply via Carey.

### To claude-code (frontend — no action yet, context only)

The field will eventually render as *one narrative sentence* on the DANE finding: "the TLSA name
lies outside this domain's own zone — DANE requires either that operator publishing TLSA or
moving MX to a host you control." Not a badge, not a score change, not a new severity. Flag now
only if that sentence collides with your report layout in a way I should know before building.

## 4. The meta-answer to "why no immediate clear answer"

There IS one. The ethical/logical answer was immediate and is recorded (name the measurement,
seal it). What's *not* immediate is the **empirical** claim the field makes — and that's resolved
by the labeled corpus (science), not by more debate. The honest division of labor: frameworks
settle the ethics; the experiment settles the proxy. We've done the first; we need the second.
