# The Field Map — who builds verified, sealed, sovereign systems (and who wears the costume)

**Date:** 2026-08-22
**Author:** Hermes lane (instrument/backend)
**Purpose:** a grounded vector of the *whole* field around Resolution Scope's
mission — not just the aligned camps, but the opposition camps too, because a
map that only shows friendly terrain is useless. The opposition names the
precise failure modes; and per Carrier Color Theory, the hardest case is when a
group wears our exact vocabulary as a costume while doing none of the work.

**Method:** every claim below carries an inline citation to a source registered
in the grounded-citations ledger at the time of retrieval. "Thinks like us" is
defined operationally, not by vibe: a group *shares the Verification Principle* —
it builds something you can re-derive, re-check, or re-prove yourself, rather
than something you must take on faith.

---

## 0. The one lens that makes the map useful

The aligned camps and the opposition camps frequently use **the identical
vocabulary**: "verifiable," "sovereign," "trustless," "tamper-evident,"
"decentralized," "secure by design." The difference is never the words — it is
whether the verification **actually happens**. So the map's single job, for any
group, is to ask:

> **Does this group do the verification it claims, or does it wear the claim as
> a costume?**

This is Carrier Color Theory applied to the field at large. It is why you
cannot dismiss a signal for an ugly carrier (the jewel on a messy surface) and
cannot trust one for a pretty carrier (the grift wearing our words). The map
exists to separate those two, precisely.

---

## 1. The aligned vector — groups that do the work

### 1a. Verified substrate (the seL4 family)

- **seL4 Foundation / Trustworthy Systems (UNSW)** — the first (and still only
  production) OS kernel with a machine-checked, code-level functional
  correctness proof.[1] Founded on a membership that includes the verification
  leaders themselves.[3] Its commercial support roster (Proofcraft, Kry10,
  DornerWorks) exists specifically to keep the *proofs* current as the kernel
  evolves — "as seL4 code evolves, so must its formal proofs."[2] Deployment
  record is concrete: an earlier variant (OKL4) shipped in "over two billion
  phones," and seL4-based systems have "flown a helicopter."[1]
- **Why they're us:** our storage compartment runs on exactly this substrate,
  and the §3 store-drain theorem is the same shape of claim seL4 makes —
  property enforced by construction, not by convention.

### 1b. Verified cryptography (the Everest family)

- **HACL\* / EverCrypt (Project Everest, INRIA/Microsoft/Carnegie Mellon)** —
  a formally verified cryptographic library in F\*, deployed in Mozilla
  Firefox's NSS, the Linux kernel, mbedTLS, and the WireGuard VPN.[7][8] The
  throughline is the same as ours: the *seal* — a digest anyone can recompute —
  rather than trust in the implementer.

### 1c. Qualified / safety-critical Rust

- **Ferrocene (Ferrous Systems + AdaCore)** — the first Rust toolchain qualified
  to ISO 26262 (automotive, ASIL D) and IEC 61508 (industrial, SIL 3), with
  IEC 62304 (medical) support.[5] The same team's "Sealed Rust" program is the
  memory-safety twin of our sealed verdict — a *claim* ("this Rust is safe")
  that you can hold to a spec instead of assert.[4] AdaCore separately announced
  the first TÜV SÜD certification of a Rust compiler under ISO 26262.[10] There
  is active work bringing Rust to safety-critical *space* systems (IEEE 3S
  2024), which notes the qualification path and its limits honestly.[11]
- **Why they're us:** the "safety-qualified toolchain" is the compiler-level
  twin of our sealed verdict — a claim ("this code is safe") you can hold to an
  independent standard rather than assert.

### 1d. Formal proof as a working tool (not a toy)

- **Lean + mathlib** — an open-source proof assistant with a community-built
  library of formalized mathematics.[12][13] This is the *language* our seal
  and the Owl Semaphore's machine-checked doctrine are expressed in; a reader
  can run the proof without trusting the author.

### 1e. Tamper-evident provenance (the transparency-log family)

- **Certificate Transparency (RFC 9162)** — append-only, Merkle-tree logs of
  issued certificates; the append-only property is the *point* ("certificates
  can only be added, not deleted, modified, or retroactively inserted").[14][15]
- **Sigstore / Rekor** — a general-purpose immutable transparency ledger for
  software signing and metadata.[20][21] Together with **in-toto** and
  **SLSA**, these form the provenance stack: *who* signed, *how* it was built,
  *what* source went in — each step verifiable, not asserted.[6][20]
- **Reproducible Builds** — the effort to make "same source → bit-identical
  binary" a verifiable property at scale.[9]
- **Why they're us:** our SHA3-512 seal *is* a transparency-log entry in
  miniature — tamper-evidence you can re-derive, not a claim you must trust.

### 1f. The government "show us the proof" push (authoritative, not conspiratorial)

- **DARPA HACMS / CASE** — the High-Assurance Cyber Military Systems program
  "employed formal methods to construct high-assurance software… and generate
  machine-checkable proofs that the code was safe and secure"; applied to
  quadcopters and helicopters.[16][17]
- **CISA + NSA memory-safety** — the joint push to "publish a memory safety
  roadmap," making "owning security outcomes" and "radical transparency"
  explicit Secure-by-Design tenets.[18][19]
- **Why this matters for the framing:** this is the *authoritative* end of the
  "groups that think like us" spectrum — the same verification-first worldview
  expressed through national-infrastructure policy, not a fringe subculture.

---

## 2. The opposition vector — groups that wear the costume

Each of these is a **precise inversion of one of our principles.** Studying them
is how you learn exactly what *not* to do, because each one names the failure
mode by being its opposite.

### 2a. Velocity-over-correctness ("move fast and break things")

The mantra was, by later admission, a specific historical compromise — and the
cultural correction ("slow down and go long") is itself documented as a shift
toward stability, quality, and thoughtfulness.[22]
- **The precise failure mode:** "break things" is a cost *deferred to the user
  and the future maintainer*. It is the inversion of foundation-first — ship
  without a foundation, pay later, in someone else's bug reports.

### 2b. Vibe coding (generation without understanding)

The evidence is converging and quantified: AI-generated code "appears mostly
correct but requires disproportionate human effort" (the "70% problem," after
Addy Osmani); Veracode measured risky security flaws in ~45% of tests across
100+ LLMs; Karpathy's line is the mechanism — "the models make wrong
assumptions on your behalf and run with them without checking."[23][24]
- **The precise failure mode:** this is the *exact inversion of the Verification
  Principle*. Code that looks correct and isn't — trust without check. The
  whole instrument we are building (seal, golden test, re-derivation) exists to
  make this failure mode *unavailable*.

### 2c. "Trustless / verifiable / decentralized" as a costume (web3)

The vocabulary is ours verbatim — "trustless," "verifiable," "sovereign" — and
the field is heavily contested precisely because the *claims* outrun the
*verification*.[25]
- **The precise failure mode:** a "trustless" system that still requires trust
  in a token, a founder, an oracle, or a bridge is not trustless — it is trust
  *relocated* and *hidden*. This is the cleanest Carrier Color case on the map:
  the signal (verifiability) worn as a carrier by people who don't do the work.
  We must be able to say, and show, *why* our seal is different from a "verified"
  badge on a token.

### 2d. Security-through-obscurity / "trust us" closed source

The critique is a cliché *because it keeps being true*: security you cannot
inspect is "where snake oil comes from" — claims of rigor that resist
independent check.[26]
- **The precise failure mode:** assert-without-evidence. The opposite of our
  "publish the seal's exact preimage so anyone can re-derive it." A group that
  says "trust us, our security is good" is the direct enemy of a group that
  says "here is the exact bytes, hash them yourself."

---

## 3. The jewel in the garbage — signal that survived a hostile carrier

The aligned camps above mostly *started* as the thing no fashionable person
wanted to fund:

- seL4 was unfashionable academic verification research; it now flies
  helicopters and ships in two billion phones.[1]
- HACL\* was an F\*-based lab project at INRIA/Microsoft Research; it is now
  the crypto in Firefox, the Linux kernel, and WireGuard.[7][8]
- Lean was a proof assistant for mathematicians; mathlib is now a working
  library of formalized mathematics.[12][13]

The lesson is not "academic things win." It is: **a real signal can arrive in
a carrier that looks worthless to the market.** The Verification Principle is
the instrument that lets you tell the jewel from the grift *without* judging
the carrier first — you check the claim, not the costume. That is the precise
reason we re-derive seals and read RFCs at the byte level rather than trusting
a source's reputation.

---

## 4. What the map is for (operationally)

For each future partner, dependency, or "group we might adopt as family" (the
Carey rule — attribution and genuine adoption, not box-checking):

1. **Ask the one question:** does this group do the verification it claims, or
   wear it as a costume?
2. **If aligned, adopt with attribution** (the seL4/RIPE-Atlas "family"
   pattern).
3. **If opposition, extract the precise failure mode** — it is the inversion of
   one of our principles, and naming it is the map's real payoff.

This document is a living map, not a verdict. Add to it as the field moves; keep
every claim cited against its ledger entry.

## Sources

[1] https://sel4.systems — seL4 Microkernel (official)
[2] https://sel4.systems/Services — seL4 Commercial Support (Kry10, Proofcraft, DornerWorks, UNSW)
[3] https://sel4.systems/Foundation/Membership — seL4 Foundation Membership
[4] https://ferrous-systems.com/blog/sealed-rust-the-pitch — Ferrous Systems — Sealed Rust: The Pitch
[5] https://ferrocene.dev — Ferrocene (qualified Rust toolchain)
[6] https://slsa.dev/blog/2023/05/in-toto-and-slsa — in-toto and SLSA (official slsa.dev)
[7] https://hacl-star.github.io — HACL* / EverCrypt — verified crypto library
[8] https://github.com/hacl-star/hacl-star — HACL* GitHub (F* verified crypto, deployed in Firefox/Linux/WireGuard)
[9] https://reproducible-builds.org/reports/2026-05 — Reproducible Builds project — May 2026 report
[10] https://www.adacore.com/press/adacore-announces-the-first-qualification-of-a-rust-compiler — AdaCore — first TÜV SÜD qualification of a Rust compiler
[11] https://arxiv.org/html/2405.18135v1 — Bringing Rust to Safety-Critical Systems in Space (IEEE 3S 2024)
[12] https://lean-lang.org — Lean (programming language + proof assistant)
[13] https://lean-lang.org/use-cases/mathlib — Mathlib — formalized mathematics in Lean
[14] https://certificate.transparency.dev/howctworks — Certificate Transparency — how it works
[15] https://www.rfc-editor.org/info/rfc9162 — RFC 9162: Certificate Transparency v2.0
[16] https://www.darpa.mil/research/research-spotlights/formal-methods — DARPA — Formal Methods spotlight (HACMS/CASE)
[17] https://trustworthy.systems/projects/OLD/CASE — Trustworthy Systems — Cyber Assured Systems Engineering
[18] https://www.cisa.gov/case-memory-safe-roadmaps — CISA — The Case for Memory Safe Roadmaps
[19] https://www.cisa.gov/resources-tools/resources/memory-safe-languages-reducing-vulnerabilities-modern-software-development — CISA/NSA — Memory Safe Languages guide
[20] https://www.sigstore.dev — Sigstore (Rekor transparency log)
[21] https://github.com/sigstore/rekor — Rekor — Software Supply Chain Transparency Log
[22] https://bigthink.com/the-long-game/move-fast-and-break-things-slow-down-and-go-long — Big Think — Move fast and break things: slow down and go long
[23] https://www.softwareseni.com/the-case-against-vibe-coding-understanding-craftsmanship-and-long-term-costs — The Case Against Vibe Coding (70% Problem, Veracode 45% risk)
[24] https://arxiv.org/html/2508.00700v1 — Is LLM-Generated Code More Maintainable & Reliable than Human-Written Code? (IEEE 2025)
[25] https://news.ycombinator.com/item?id=33529097 — Is Web3 Bullshit? (HN transcript)
[26] https://securityboulevard.com/2020/09/cliche-security-through-obscurity-yet-again — Security through obscurity — where snake oil comes from
