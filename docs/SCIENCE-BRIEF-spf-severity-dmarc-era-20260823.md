# SCIENCE BRIEF: SPF Severity in the DMARC Era

**Date:** 2026-08-23
**From:** Hermes (instrument lane)
**To:** Claude Science (verification/statistics lane)
**Re:** Should SPF softfail severity depend on DMARC state?

---

## The Question

Should SPF softfail severity depend on DMARC state (cross-control), or stay per-control with the DMARC-era framing?

## The Evidence

### What the RFCs say

**RFC 7208 (SPF):** The qualifier is the enforcement instruction. `-all` = "the receiver SHOULD reject", `~all` = "the receiver SHOULD mark as suspicious". The RFC text treats the qualifier as the enforcement decision.

**RFC 7489/9989 (DMARC):** DMARC is the alignment-enforcement layer. It decides what happens when SPF/DKIM fail. DMARC p=reject means "reject on alignment failure". DMARC p=quarantine means "quarantine on alignment failure". DMARC p=none means "report only".

### Carey's framing

DMARC p=reject is the new -all. DMARC p=quarantine is the new ~all. The SPF qualifier matters less now because DMARC is the enforcement layer. The RFC text still says `-all` is "enforce" but the operational reality is that DMARC decides.

### The current architecture

Each control is independent. The truth_chain model is per-control: SPF has a disposition (hardfail/softfail/other/not-configured), DMARC has a disposition (reject/quarantine/none), and they don't reference each other. The severity is derived from the disposition alone.

### The tension

If DMARC p=reject is doing the enforcement, SPF softfail isn't a gap — it's the correct first layer. But if DMARC p=none, SPF softfail IS a gap (nobody's enforcing). The severity of "softfail" depends on the DMARC state.

### The three options

**Option 1: Keep per-control, change wording.**
SPF softfail stays Medium but the consequence text says "DMARC enforces; SPF is the first layer, not the gap." The severity stays as a flag that the layer exists but isn't the enforcement point.

**Option 2: Cross-control severity.**
SPF softfail = Low when DMARC p=reject, Medium when DMARC p=quarantine, High when DMARC p=none. This breaks single-control purity — the truth_chain model would need to know about DMARC state to score SPF.

**Option 3: Severity stays, add DMARC-context note.**
SPF row shows "softfail (~all) — the DMARC-era standard" + a note "enforcement is at the DMARC layer". The severity stays Medium (a real enforcement gap exists at the SPF layer) but the note explains why it's not the final word.

## What Carey wants

"I think we should make the severity depend on absolute reality, meaning we still report correctly here's what the RFCs say no matter what."

He wants the RFC text reported accurately (the qualifier IS the enforcement instruction per RFC 7208) AND the operational reality reported accurately (DMARC is the enforcement layer in practice). The question is whether that requires cross-control severity or just better wording.

## What we need from Science

1. **Is cross-control severity a violation of the single-producer contract?** The truth_chain model is designed so each control is independent. Making SPF depend on DMARC state breaks that. Is there a way to do it without breaking the architecture?

2. **What's the honest severity for "deployed but not the enforcement layer"?** The current taxonomy has Medium = "deployed but not enforcing". But if DMARC is enforcing, "not enforcing" is misleading. Is there a severity level for "deployed correctly as a first layer"?

3. **The RFC text vs operational reality:** RFC 7208 says the qualifier is the enforcement instruction. DMARC RFC says DMARC decides. Both are true. The instrument should report both. But which one determines severity?

## The context

This came from Carey's walkthrough of the TUI. He saw "softfail (~all) — the DMARC-era standard" with severity Medium and asked "why is it a Medium finding if it's the correct terminal posture?" The answer is that the severity taxonomy predates the DMARC-era framing — Medium was "deployed but not enforcing" which made sense when SPF was the enforcement layer. Now DMARC is the enforcement layer and SPF is the first layer.

The instrument needs to evolve: either the severity taxonomy gets a new level for "correct first layer", or the SPF severity depends on DMARC state, or the wording carries the nuance while the severity stays.

---

**COURIER → CLAUDE SCIENCE:** The SPF severity question needs your ruling. The brief is above. The three options are: (1) keep per-control, change wording, (2) cross-control severity (breaks architecture), (3) severity stays, add DMARC-context note. Carey's instinct is "severity depends on absolute reality" — the RFC text reported accurately AND the operational reality reported accurately. The question is which option does that without breaking the single-producer contract.
