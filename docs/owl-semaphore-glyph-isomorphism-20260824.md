# Owl Semaphore glyph encoding is a faithful geometric realization of V₄

**Date:** 2026-08-24 · **Status:** first-hand verified · **Attribution:** Carey's glyph set → proved by Claude Science (Operon) → independently re-verified by Hermes.

## The claim

The four characters `. | - +` are a **faithful encoding** of the Klein four-group
V₄ = ℤ₂×ℤ₂, when each glyph is read as its **set of strokes** and the group
operation is **symmetric difference** (XOR):

| glyph | stroke set | group element | Owl Semaphore state |
|---|---|---|---|
| `.` | ∅ (none) | `(0,0)` | I (identity) |
| `\|` | {vertical} | `(1,0)` | σᵥ (vertical reflection) |
| `-` | {horizontal} | `(0,1)` | σₕ (horizontal reflection) |
| `+` | {vertical, horizontal} | `(1,1)` | C₂ = σᵥσₕ (rotation) |

The group operation is **literally visible in the glyphs**: combining `|` and
`-` gives `+` (the two strokes union); combining `|` with `|` gives `.` (the
two vertical strokes cancel). The visual layer *is* the algebra.

## Verification (reproducible)

`scripts/verify_owl_glyph_encoding.py` asserts all three claims:

1. **All 16 products** — `glyph(a Δ b) == glyph(a) ⊕ glyph(b)` for every pair
   of the four states.
2. **7 of 16 require stroke removal** (cancellation), **9 are visually
   additive** (disjoint strokes union). The Cayley table's cancellation cells
   are exactly the ones where the two operands share a stroke.
3. **1 orbit** — the group acts transitively on the four corners of a 2×2 cell
   (a single orbit), so the encoding is not only faithful but minimal.

```
$ python3 scripts/verify_owl_glyph_encoding.py
stroke symmetric-difference == group op, all 16 products: True
visually additive (disjoint->union): 9
require stroke REMOVAL (cancel): 7
reachable corners from (0,0): 4 => transitive (1 orbit): True
```

## Why it matters

Carey's point — "mathematics abandoned the visual layer" and the owl semaphore
should "visibly match the logic underneath" — has a precise mathematical home:
the branches where *the picture is the proof* (commutative diagrams, Feynman
diagrams, Dynkin/Coxeter diagrams, knot diagrams with Reidemeister moves,
Penrose graphical notation). A faithful glyph encoding joins that tradition:
manipulating the drawing is a valid derivation, because the drawing is the
group.

This is the same argument as the seal, restated. The seal is checkable because
the preimage construction is *declared*. The glyph set is checkable because the
carrier set + operation is *declared*. **Structure-as-label** — a receiver who
reads the glyphs correctly knows what they are (Carey's pyramids-carry-no-plaque
doctrine).

## Two character hazards (surface-dependent)

1. **`|` (U+007C)** is a state glyph *and* the universal separator — markdown
   table cells, YAML block scalars, shell pipes. Fine in the TUI and in a
   monospace ASCII stream; **wrong** in markdown/YAML/llms.txt where it is
   ambiguous with the frame. A receiver cannot tell data from frame.
2. **`-` (hyphen, U+002D) vs `–` (en dash, U+2013).** The en dash is the
   Unicode class that already bit the grader (normalization false negatives).
   For a faithful ASCII floor that survives piping, logging, and monospace
   rendering, use **hyphen `-`**. (The en dash renders as a longer horizontal
   stroke and reads slightly better as σₕ in a *rich* surface, but it must
   never enter a machine-checked or ASCII stream.)

**Recommendation:** three tiers, all preserving the group structure because the
encoding *is* the group — (1) rich terminal: glyph in a colored quadrant of a
2×2 cell; (2) monochrome terminal: glyph in a corner of the cell; (3) ASCII
stream: the bare character `. | - +`.

## The type-signature preamble (decode 33% → 100%)

Claude Science's decode experiment: a bare V₄ table decodes as "Klein
four-group" in **33%** of usable model calls; adding one line —
`∘ : S × S → S where S = {., |, -, +}` — raises it to **100%**. Every symbolic
block that ships (llms.txt, docs, the site) must carry its type signature; the
block below is then self-checking, machine and human reading the same line.

## Related rulings (do not re-litigate)

- The fork over tri-state semantics (`Present` = deployment-fact vs
  constitutes-the-control) is **Carey's call** — see
  `docs/DECISION-BRIEF-open-rulings-20260824.md`.
- This glyph result is independent of the fork: it is about the *encoding* of
  V₄, not about which DNS disposition maps to which tri-state.
