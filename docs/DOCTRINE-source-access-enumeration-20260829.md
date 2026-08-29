# Doctrine — Source-Access Enumeration
### The Verification Principle written as a procedure · 2026-08-29

> A subject — a resolver, a domain, a model, a person — is never measured by
> the *first* surface that happens to answer. It is measured by the *set* of
> legal angles from which it can be observed, with each angle's raw evidence
> retained at full fidelity. Divergence between angles is the signal.

---

## 1. The method, in one breath

1. **Enumerate every legal access path** to the source before touching any one.
   For a single source there are usually several surfaces, each a different
   shape of the same truth:
   - a **public website** → extract (Firecrawl / browser),
   - a **structured API** → query directly,
   - a **human-shaped interface** → MCP server,
   - a **protocol endpoint** → the wire itself (UDP/53, DoH, DoT, a probe).

2. **Keep the receipts other people throw away.** Most tools ask a source a
   question and keep only the collapsed answer. The method keeps the *verbose*
   receipt — the per-resolver AD flag, the rcode, the denial-proof type, the
   NSID of *which* node answered. A summary is a claim; a receipt is evidence.
   The summary can be wrong and look right; the receipt cannot be wrong without
   being visibly wrong.

3. **Trace authoritative intelligence back to the source**, and count the
   angles. For a resolver: the resolver's own answer, the *identity* of the
   node that answered (NSID), the registry clock versus the DNS clock, a second
   resolver, a probe on another continent. Each is an independent vantage on
   the same subject.

4. **Cross-reference the angles — and this is accuracy, not a later step.**
   Agreement across vantages is corroboration; disagreement is a finding with
   a named location. Then, and only then, is the last consideration **speed**.

The order is fixed: *enumerate, retain raw, trace authority, cross-reference —
then make it fast.* Speed is last and alone; everything before it is one move.

---

## 2. The distinction the whole method protects

The collapse this doctrine exists to prevent is **representation standing in
for measurement.** A derived field, a severity label, a "PASS/FAIL," a
collapsed boolean — these are *renderings* of a measurement, not the
measurement. The method never lets the rendering become the only copy.

This is the same rule the seal architecture already enforces (R-B): raw
records ride beside the sealed verdict at full fidelity, and the display
renders them readable. Source-access enumeration is that rule, aimed at the
*acquisition* step instead of the *storage* step.

---

## 3. The proof, from practice (2026-08-29)

During the post-quantum DNSSEC sweep, the method caught a defect in the
measuring instrument itself.

The DNS Tool's **derived** `algorithm` field returned garbage on ~50 rows —
`algorithm = "3600"`, `algorithm_name = "Algorithm 3600"` — because
`parseAlgorithm` read `fields[1]` assuming bare RDATA, and got the **TTL** on
the older full-dig-line form. The derived field had *thrown away* the
bare-RDATA-vs-dig-line distinction.

The sweep did not trust the derived field. It parsed the **raw**
`ds_records` / `dnskey_records` — the receipts — directly, and found the real
algorithm (nsa.gov = 7, RSA/SHA-1). The summary was wrong; the raw record was
not, and that separation is what surfaced the bug.

A summary-only tool would have silently shipped the TTL as the algorithm. The
receipt that "other people throw away" is precisely what caught it. That is
the method doing real work, not a slogan.

---

## 4. The general form — same strategy, any subject

The procedure does not care what the source is:

| Subject | Enumerate angles | Keep the raw receipt | Cross-reference |
|---|---|---|---|
| Domain | RDAP, CT logs, DNS, web (MTA-STS/security.txt) | full records, rcode, AD | resolver set, registry clock vs DNS clock |
| Resolver | UDP/DoH/DoT, probe fleet, NSID | per-resolver AD, rcode, TTL, node identity | vantages across geography |
| Model | API, TUI, verbose reasoning trace | raw output, reasoning_content, full log | a second model, a second substrate |
| Person | their words, the record, a third party | verbatim, provenance-stamped | the record vs their account of it |

The first three rows are the instrument as it already runs. The fourth is the
instrument aimed at its own operator — the human-calibration half — and the
method is identical.

---

## 5. What this is and is not

- **It is** the Verification Principle restated as a procedure: don't assert,
  enumerate; don't summarize, retain; don't trust one angle, diff several.
- **It is not** a new pillar. It is the *operational* form of Verification,
  Carrier Color (the receipt is the carrier's raw form, retained and labeled),
  and Star-Centric Transport (the retained receipt is the record that survives
  the moment) — one method, three names for its facets.
- **It is not** collection for its own sake. Every angle must be legal,
  passive-or-consented, and the *point* is cross-reference, not accumulation.
  A third angle that can't be reached legally is not "missing intelligence" —
  it is a boundary, recorded as such.

---

*Authored by Carey Balboa, notated by the hermes lane 2026-08-29. The
philosophy preceded the proof; the proof (the TTL-bleed catch) preceded the
notation. That is the correct order.*
