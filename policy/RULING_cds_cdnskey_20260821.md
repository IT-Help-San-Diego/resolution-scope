# RULING — CDS/CDNSKEY absence collapse (2026-08-21): LEAVE IT

Ruled: Carey/Claude Science, against measurement. Recorded by the site lane,
which independently re-verified every checkable claim before committing this.

## The question (routed 2026-08-21 morning briefing)

Does `truth_chain.rs`'s collapse of CDS/CDNSKEY `NotPublished → Absent → FAIL`
wrongly dock a signed+delegated zone for "not being mid-rollover"? Two options
were offered: (a) refine to NotApplicable on signed zones, (b) keep FAIL but
relabel the measured text.

## The ruling: (c) — neither. Leave the collapse alone.

**The premise is falsified by measurement, not argument.** The premise held
that CDS publication signals a rollover *in progress*, making absence the
healthy resting state. Measured across 16 signed zones: **6 publish
CDS/CDNSKEY at rest** (ietf.org, cloudflare.com, internetsociety.org,
isc.org, iis.se, whitehouse.gov). Independently re-verified live by this
lane at recording time: ietf.org, cloudflare.com, isc.org all answered CDS
queries with standing records. If publication meant mid-rollover, six major
zones would be rolling keys simultaneously; they are not. **Publication is a
standing declaration of the desired DS state enabling automated
maintenance** — which is what the code's own `measured` text already says
(`Published` → "automated DS maintenance signaled"; `NotPublished` → "DS
`NotPublished` → "DS updates at the parent are manual"). Both are standing-state descriptions.

**Operator-clustering correction (added by the instrument lane, 2026-08-21):**
the "6 of 16 zones" count overstates independence. Four of the six
CDS-publishing zones — `ietf.org`, `cloudflare.com`, `internetsociety.org`,
`whitehouse.gov` — share **byte-identical KSK material** (key tag 2371, same
DNSKEY public key `mdsswUyr3DPW132m…`, four different DS digests because the
digest binds the owner name). That is one operator's default policy observed
four times, not four zone-owner decisions. The honest figure is **3
independent operators** (Cloudflare ×4 zones, `isc.org`, `iis.se`). The
conclusion is unaffected and in fact stronger: a hosting provider does not
put every customer zone into permanent rollover, so Cloudflare publishing CDS
as a standing default is the cleanest demonstration that publication is not a
rollover-in-progress signal.

**The optionality argument proves too much.** All eight `rfc_requirement`
strings begin "Optional" (verified: exactly 8 in `truth_chain.rs`). "Optional
therefore shouldn't dock" would empty the score's denominator for every
control on every scan. Optional in layer one means the standard does not
compel deployment; the score's thesis is that deploying beats not deploying.
CDS absent docks for the same reason SPF absent docks.

**Why each offered option is specifically wrong:**
- (a) breaks `NotApplicable`'s meaning — *no surface to measure* (null MX).
  A signed zone has the surface, was measured, and answered. It would also
  delete the manual-maintenance finding the instrument correctly produces.
- (b) is an arithmetic penalty with words denying it — the display-vs-state
  defect shape.

**Do not change `truth_chain.rs` for this.** The one-line change under
consideration would have made the instrument unable to report a real
operational risk on 10 of 16 signed zones in the ruling's sample.

## The real open question this surfaced (not CDS-specific)

Severity already differentiates absences — DNSSEC/SPF/DMARC/MTA-STS absent
rank High; DANE/CAA/CDS absent rank Low — but the score does not:
`present / (present + absent)` (`truth_chain.rs:685-693`, verified) charges
a Low exactly what it charges a High. One axis differentiates, the other
flattens, and it spans three controls. **If fixed, the honest form is a
severity-weighted score reported ALONGSIDE the unweighted one, never
replacing it** — two numbers with stated meanings over one number with a
hidden weighting. Status: OPEN, unassigned; a scoring-semantics change,
so it takes a ruling of its own before code moves.

## Arm 1 assignments recorded in the same ruling

Claude Science owns item (2): the pre-registered three-way disagreement
classification, and the `go_to_tri` four-state gap — Rust emits
`NotApplicable` (null-MX DANE) which the Go side cannot express, so those
rows are **excluded with a published count**, never folded into Absent. The
corpus is frozen content-addressed **before either engine runs**, or the
disagreement set and the corpus drift together.
