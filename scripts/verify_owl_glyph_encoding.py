#!/usr/bin/env python3
"""Verify the Owl Semaphore glyph encoding is a faithful realization of V4.

Proven by Claude Science (Operon), re-verified first-hand by Hermes 2026-08-24.
See docs/owl-semaphore-glyph-isomorphism-20260824.md.

Three claims, all asserted:
  1. stroke-set symmetric difference == group operation (all 16 products)
  2. 9 products visually additive, 7 require stroke removal (cancellation)
  3. the group is transitive on the 4 corners of a 2x2 cell (1 orbit)

Exits non-zero on any failure. ASCII-only: uses hyphen (-), never en-dash.
"""
from itertools import product

# V4 = Z2 x Z2 under XOR (symmetric difference). The four owl states.
E = [(0, 0), (1, 0), (0, 1), (1, 1)]

def op(a, b):
    return (a[0] ^ b[0], a[1] ^ b[1])

# Encoding: each glyph = a SET of strokes. bit0 = vertical, bit1 = horizontal.
STROKE = {
    (0, 0): frozenset(),
    (1, 0): frozenset({"|"}),
    (0, 1): frozenset({"-"}),
    (1, 1): frozenset({"|", "-"}),
}
GLYPH = {(0, 0): ".", (1, 0): "|", (0, 1): "-", (1, 1): "+"}

# Claim 1: symmetric difference of stroke sets == group operation.
assert all(STROKE[op(a, b)] == (STROKE[a] ^ STROKE[b]) for a in E for b in E), \
    "glyph symmetric difference != group operation"
assert len(set(STROKE.values())) == 4, "encoding is not a bijection"

# Claim 2: cancellation vs additive split.
additive = sum(1 for a in E for b in E if not (STROKE[a] & STROKE[b]))
cancel = 16 - additive
assert (additive, cancel) == (9, 7), f"expected (9 additive, 7 cancel), got ({additive}, {cancel})"

# Claim 3: transitive on 4 corners (1 orbit).
reachable = {op((0, 0), c) for c in E}
assert len(reachable) == 4, "group is not transitive on the 4 corners"

print("stroke symmetric-difference == group op, all 16 products: True")
print(f"visually additive (disjoint->union): {additive}")
print(f"require stroke REMOVAL (cancel): {cancel}")
print(f"reachable corners from (0,0): {len(reachable)} => transitive (1 orbit): True")
