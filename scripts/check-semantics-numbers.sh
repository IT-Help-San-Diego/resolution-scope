#!/usr/bin/env bash
# check-semantics-numbers.sh — every number in docs/MEASUREMENT_SEMANTICS.md
# that the entry claims a shipped test asserts is re-checked against that
# test, and every tally the entry derives from its own table is recomputed.
#
# WHY THIS EXISTS. Three rounds running, the CODE was right and the
# ACCOUNTING was wrong. PR #45 shipped a cost claim that was measurably
# INVERTED on the commonest mail shape. PR #47 shipped a tally that
# contradicted the table printed three lines above it ("fewer in four" where
# the table shows three), and a scope claim that said every number in the
# table was asserted by shipped tests when two thirds are historical numbers
# no test can reproduce. Each was caught by adversarial review; each was a
# HUMAN-STYLE arithmetic or scope error in prose that no compiler reads. By
# this project's own doctrine three occurrences of one failure mode is the
# signal for a mechanical guard rather than more care.
#
# WHAT IT BINDS. The document's cost table is a delimited, tagged block —
# nothing is inferred from prose, because inference over prose is how this
# class of bug arrived. Each [row] carries an explicit [src]:
#
#   gated:<test>      that shipped test asserts this row IN THIS TREE. The
#                     gate binds the row to the test's own source text and
#                     runs the test to watch it pass.
#   testimony:<ref>   measured once at <ref>; no shipped test reproduces it.
#                     The gate does NOT check these and must not pretend to.
#
# A [row] with no [src] is an UNMARKED ROW and fails by name. A block with
# zero gated rows fails: a gate with nothing to check must go red, not pass
# vacuously. That is the defect class this whole arc keeps finding.
#
# HOW A GATED NUMBER IS BOUND TO A MEASUREMENT — and the honest limit of it.
# The cited tests emit no machine-readable count; they only assert. Editing
# them to print one is outside this change's surface. So the binding is a
# COMPOSITION of two links, each mechanical:
#
#   (1) document == assertion.  Checked here, by EXACT normalised substring
#       against the test's own source: the loop text `for <var> in
#       [<axis>]` constructed from the document's own [axis]; the [call]
#       text; and the assertion shape `count, <n>,` (for [expect const=n])
#       or `count, <var>,` (for [expect axis]). No Rust is interpreted —
#       every expected string is CONSTRUCTED from declared fields and looked
#       for verbatim, whitespace-normalised so rustfmt reflow cannot break
#       it.
#   (2) assertion == measurement.  Not checked here. It is enforced by the
#       assertion itself, which this gate RUNS: `test <name> ... ok` must
#       appear in the harness output. cargo's exit status alone is provably
#       insufficient — `cargo test --test dane_probe_cost -- --exact
#       no_such_test` prints "0 passed; 2 filtered out" and exits 0.
#
# Composed: document == measurement. WHAT THIS DOES NOT PROVE: that the
# counter counts the right packets, and that the loop body has no early
# `continue`. Those are held by the tests' own assertions and by the observed
# mutant M15 (memoisation removed kills both cost tests). A gate whose scope
# is overstated is the same defect one layer up, so the boundary is named.
#
# Exit 0 = bound and clean, with a counted success line. Exit 1 = named
# reason on stderr. Same shape and CI wiring as its siblings
# check-citation-boundary.sh and check-corpus-identity-absence.sh.

set -euo pipefail
REPO="$(git rev-parse --show-toplevel)"
DOC="$REPO/docs/MEASUREMENT_SEMANTICS.md"

if [ ! -f "$DOC" ]; then
  echo "SEMANTICS-NUMBERS: $DOC missing — the entry this gate binds is absent" >&2
  exit 1
fi

python3 - "$DOC" "$REPO" <<'PY'
import os
import re
import subprocess
import sys

DOC, REPO = sys.argv[1], sys.argv[2]

BEGIN = re.compile(r"<!--\s*cost-table begin:\s*([A-Za-z0-9_-]+)\s*-->")
END = re.compile(r"<!--\s*cost-table end\s*-->")

RE_COMMENT = re.compile(r"^\s*#(?:\s.*)?$")
RE_GATEFILE = re.compile(r"^\s*\[gatefile\s+([^\]\s]+)\]\s*$")
RE_AXIS = re.compile(r"^\s*\[axis\s+var=([A-Za-z_]\w*)\s+suffix=([A-Za-z0-9_]+)\]((?:\s+\d+)+)\s*$")
RE_SRC = re.compile(r"^\s*\[src\s+(gated|testimony):([^\]\s]+)\]\s*$")
RE_CALL = re.compile(r"^\s*\[call\s+(\S.*?)\]\s*$")
RE_EXPECT = re.compile(r"^\s*\[expect\s+(?:const=(\d+)|(axis))\]\s*$")
RE_ROW = re.compile(r"^\s*\[row\s+regime=([A-Za-z0-9_-]+)\s+series=([A-Za-z0-9_-]+)\]((?:\s+\d+)+)\s*$")
RE_DERIVED = re.compile(
    r"^\s*\[derived\s+lhs=(\S+)\s+rhs=(\S+)\s+fewer=(\d+)\s+equal=(\d+)\s+more=(\d+)\]\s*$"
)
# A line carrying three or more whitespace-separated BARE integers is a table.
# Outside the tagged block that is an untagged table: an ungated claim that
# never enters the marked region at all.
RE_BARE_INTS = re.compile(r"(?:^|\s)(\d+)(?=\s|$)")


def norm(s):
    return re.sub(r"\s+", " ", s)


def parse(text):
    """Parse the tagged block. Returns (problems, model or None)."""
    lines = text.split("\n")
    p = []
    starts = [i for i, l in enumerate(lines) if BEGIN.search(l)]
    ends = [i for i, l in enumerate(lines) if END.search(l)]
    if len(starts) != 1 or len(ends) != 1 or ends[0] < starts[0]:
        p.append(
            "the document must carry EXACTLY ONE `<!-- cost-table begin: <id> -->` … "
            "`<!-- cost-table end -->` block; found %d begin and %d end marker(s). "
            "A missing block is a failure, not a pass: the numbers it holds are the "
            "ones this gate exists to check." % (len(starts), len(ends))
        )
        return p, None
    s, e = starts[0], ends[0]

    m = {
        "id": BEGIN.search(lines[s]).group(1),
        "begin_line": s + 1,
        "end_line": e + 1,
        "gatefile": None,
        "var": None,
        "suffix": None,
        "axis": None,
        "rows": [],
        "derived": [],
    }
    pend_src = pend_call = pend_expect = None

    for k, ln in enumerate(lines[s + 1 : e]):
        n = s + 2 + k  # 1-indexed document line number
        if RE_COMMENT.match(ln) or not ln.strip():
            continue
        mo = RE_GATEFILE.match(ln)
        if mo:
            if m["gatefile"] is not None:
                p.append("line %d: a second [gatefile]; exactly one is allowed" % n)
            m["gatefile"] = mo.group(1)
            continue
        mo = RE_AXIS.match(ln)
        if mo:
            if m["axis"] is not None:
                p.append("line %d: a second [axis]; exactly one is allowed" % n)
            m["var"], m["suffix"] = mo.group(1), mo.group(2)
            m["axis"] = [int(x) for x in mo.group(3).split()]
            if len(m["axis"]) < 2:
                p.append("line %d: [axis] carries fewer than two values" % n)
            continue
        mo = RE_SRC.match(ln)
        if mo:
            if pend_src is not None:
                p.append(
                    "line %d: a second [src] before any [row] (the first was line %d) — "
                    "[src] is sticky to the NEXT [row] and only that one"
                    % (n, pend_src[2])
                )
            pend_src = (mo.group(1), mo.group(2), n)
            continue
        mo = RE_CALL.match(ln)
        if mo:
            if pend_call is not None:
                p.append("line %d: a second [call] before any [row]" % n)
            pend_call = (mo.group(1), n)
            continue
        mo = RE_EXPECT.match(ln)
        if mo:
            if pend_expect is not None:
                p.append("line %d: a second [expect] before any [row]" % n)
            pend_expect = (
                ("const", int(mo.group(1))) if mo.group(1) else ("axis", None),
                n,
            )
            continue
        mo = RE_ROW.match(ln)
        if mo:
            regime, series = mo.group(1), mo.group(2)
            vals = [int(x) for x in mo.group(3).split()]
            label = "regime=%s series=%s" % (regime, series)
            if pend_src is None:
                p.append(
                    "line %d: UNMARKED ROW %s — no [src] line precedes it. An unmarked "
                    "number is an ungated claim wearing a gated number's clothes; mark "
                    "it `[src gated:<test>]` or `[src testimony:<ref>]`." % (n, label)
                )
            if m["axis"] is not None and len(vals) != len(m["axis"]):
                p.append(
                    "line %d: row %s carries %d integers but the axis is %d wide (%s) — "
                    "a truncated or padded row is a failure, not a shrug."
                    % (n, label, len(vals), len(m["axis"]), " ".join(str(v) for v in m["axis"]))
                )
            kind = pend_src[0] if pend_src else None
            if kind == "gated":
                if pend_call is None:
                    p.append("line %d: gated row %s has no [call] line" % (n, label))
                if pend_expect is None:
                    p.append("line %d: gated row %s has no [expect] line" % (n, label))
            else:
                if pend_call is not None:
                    p.append(
                        "line %d: row %s is not gated but carries a [call] (line %d) — "
                        "source bindings belong only to gated rows"
                        % (n, label, pend_call[1])
                    )
                if pend_expect is not None:
                    p.append(
                        "line %d: row %s is not gated but carries an [expect] (line %d)"
                        % (n, label, pend_expect[1])
                    )
            m["rows"].append(
                {
                    "line": n,
                    "regime": regime,
                    "series": series,
                    "vals": vals,
                    "label": label,
                    "kind": kind,
                    "ref": pend_src[1] if pend_src else None,
                    "call": pend_call[0] if pend_call else None,
                    "expect": pend_expect[0] if pend_expect else None,
                }
            )
            pend_src = pend_call = pend_expect = None
            continue
        mo = RE_DERIVED.match(ln)
        if mo:
            m["derived"].append(
                {
                    "line": n,
                    "lhs": mo.group(1),
                    "rhs": mo.group(2),
                    "fewer": int(mo.group(3)),
                    "equal": int(mo.group(4)),
                    "more": int(mo.group(5)),
                }
            )
            continue
        p.append(
            "line %d: unparseable inside the cost-table block: %r — every line must be "
            "a `#` comment, [gatefile], [axis], [src], [call], [expect], [row] or "
            "[derived]. Nothing here is inferred." % (n, ln.strip()[:70])
        )

    for name, pend in (("[src]", pend_src), ("[call]", pend_call), ("[expect]", pend_expect)):
        if pend is not None:
            p.append(
                "line %d: dangling %s with no [row] after it before the block ends"
                % (pend[-1], name)
            )

    if m["gatefile"] is None:
        p.append("the block has no [gatefile] line")
    if m["axis"] is None:
        p.append("the block has no [axis] line — there is no column order to check against")
    if not m["rows"]:
        p.append("the block has no [row] lines — a gate with nothing to check passes vacuously")
    seen = {}
    for r in m["rows"]:
        k = (r["regime"], r["series"])
        if k in seen:
            p.append("line %d: duplicate row %s (first at line %d)" % (r["line"], r["label"], seen[k]))
        seen[k] = r["line"]
    gated = [r for r in m["rows"] if r["kind"] == "gated"]
    if not gated:
        p.append(
            "ZERO GATED ROWS: every row is testimony or unmarked. A gate that passes "
            "when it has nothing to check is the defect class this gate exists to "
            "close — at least one [src gated:<test>] row is required."
        )
    return p, m


def check_derived(m):
    """Recompute every [derived] tally from the [row] numbers. PR #47's defect."""
    p = []
    # FLOOR (reviewers, 2026-09-04): deleting every [derived] line removes the
    # arithmetic guard against #47's defect and leaves this function checking
    # nothing — a guard that passes because it was emptied. At least one.
    if not m["derived"]:
        return ["no [derived] line: the arithmetic guard against a tally that "
                "contradicts its own table has been removed"]
    for d in m["derived"]:
        lhs = {r["regime"]: r for r in m["rows"] if r["series"] == d["lhs"]}
        rhs = {r["regime"]: r for r in m["rows"] if r["series"] == d["rhs"]}
        if not lhs:
            p.append("line %d: [derived] names lhs=%s but no row has that series" % (d["line"], d["lhs"]))
            continue
        if not rhs:
            p.append("line %d: [derived] names rhs=%s but no row has that series" % (d["line"], d["rhs"]))
            continue
        if set(lhs) != set(rhs):
            p.append(
                "line %d: [derived] lhs=%s covers regimes %s but rhs=%s covers %s — a "
                "tally over unmatched regimes is not a tally"
                % (d["line"], d["lhs"], sorted(lhs), d["rhs"], sorted(rhs))
            )
            continue
        fewer = equal = more = 0
        for regime in sorted(lhs):
            a, b = lhs[regime]["vals"], rhs[regime]["vals"]
            for x, y in zip(a, b):
                if x < y:
                    fewer += 1
                elif x == y:
                    equal += 1
                else:
                    more += 1
        if (fewer, equal, more) != (d["fewer"], d["equal"], d["more"]):
            p.append(
                "line %d: DERIVED CLAIM CONTRADICTS THE TABLE ABOVE IT. "
                "`%s vs %s` is declared fewer=%d equal=%d more=%d; recomputed from the "
                "rows it is fewer=%d equal=%d more=%d. (This is PR #47's defect exactly: "
                "a tally that contradicts its own table.)"
                % (
                    d["line"], d["lhs"], d["rhs"],
                    d["fewer"], d["equal"], d["more"],
                    fewer, equal, more,
                )
            )
    return p


def fn_body(src, name):
    """The text of `fn <name>` up to the first line-start `}`. None if absent."""
    mo = re.search(r"\n(?:pub\s+)?(?:async\s+)?fn\s+" + re.escape(name) + r"\b", src)
    if not mo:
        return None
    tail = src[mo.start() :]
    end = re.search(r"\n\}", tail)
    return tail[: end.end()] if end else tail


def check_source(m, root):
    """document == assertion, by exact normalised substring. No Rust is interpreted."""
    p = []
    gated = [r for r in m["rows"] if r["kind"] == "gated"]
    if not gated:
        return p
    path = os.path.join(root, m["gatefile"]) if m["gatefile"] else None
    if not path or not os.path.isfile(path):
        p.append(
            "[gatefile] names %r but no such file exists under %s — every gated row "
            "cites a test in a file that is not there" % (m["gatefile"], root)
        )
        return p
    src = open(path, encoding="utf-8").read()
    axis = m["axis"]
    loop = "for %s in [%d%s%s]" % (
        m["var"], axis[0], m["suffix"],
        "".join(", %d" % v for v in axis[1:]),
    )
    for r in gated:
        name = r["ref"]
        body = fn_body(src, name)
        if body is None:
            p.append(
                "line %d: row %s cites gated test `%s`, but no `fn %s` exists in %s — a "
                "dangling citation (rename, deletion, or typo)"
                % (r["line"], r["label"], name, name, m["gatefile"])
            )
            continue
        nb = norm(body)
        if norm(loop) not in nb:
            p.append(
                "line %d: row %s cites `%s`, but that test does not contain the axis "
                "loop `%s` constructed from the document's own [axis] — the document's "
                "columns and the test's iteration have drifted apart"
                % (r["line"], r["label"], name, loop)
            )
        if norm(r["call"]) not in nb:
            p.append(
                "line %d: row %s declares [call %s] but `%s` does not contain it — the "
                "row's regime is not the one the test measures"
                % (r["line"], r["label"], r["call"], name)
            )
        kind, const = r["expect"]
        if kind == "const":
            want = "count, %d," % const
            bad = [
                (axis[i], v) for i, v in enumerate(r["vals"]) if v != const
            ]
            for mx, v in bad:
                p.append(
                    "line %d: GATED NUMBER DRIFT in row %s at %s=%d: the document says "
                    "%d, but the row is declared [expect const=%d] and `%s` asserts the "
                    "constant %d at every column"
                    % (r["line"], r["label"], m["var"], mx, v, const, name, const)
                )
        else:
            want = "count, %s," % m["var"]
            for i, v in enumerate(r["vals"]):
                if v != axis[i]:
                    p.append(
                        "line %d: GATED NUMBER DRIFT in row %s at %s=%d: the document "
                        "says %d, but the row is declared [expect axis] and `%s` asserts "
                        "the axis value %d"
                        % (r["line"], r["label"], m["var"], axis[i], v, name, axis[i])
                    )
        if want not in nb:
            p.append(
                "line %d: row %s declares [expect %s] so `%s` must assert `%s`, and it "
                "does not — the assertion shape the document claims is not the one the "
                "test makes"
                % (r["line"], r["label"], kind if kind == "axis" else "const=%d" % const,
                   name, want)
            )
    return p


def check_harness(m, root):
    """The cited tests must actually RUN and PASS here — not merely exist."""
    p = []
    gated = [r for r in m["rows"] if r["kind"] == "gated"]
    if not gated or not m["gatefile"]:
        return p
    mo = re.match(r"^(.+)/tests/([^/]+)\.rs$", m["gatefile"])
    if not mo:
        p.append(
            "[gatefile] %r is not of the form <crate>/tests/<target>.rs, so the test "
            "target to run cannot be derived from it" % m["gatefile"]
        )
        return p
    crate, target = mo.group(1), mo.group(2)
    cmd = ["cargo", "test", "--locked", "--test", target, "--", "--test-threads=1"]
    try:
        run = subprocess.run(
            cmd, cwd=os.path.join(root, crate),
            capture_output=True, text=True, timeout=900,
        )
    except FileNotFoundError:
        p.append("cargo not found — this gate RUNS the cited tests and cannot vouch for them without it")
        return p
    except subprocess.TimeoutExpired:
        p.append("`%s` in %s/ timed out after 900s" % (" ".join(cmd), crate))
        return p
    out = run.stdout + run.stderr
    if run.returncode != 0:
        p.append(
            "`%s` in %s/ exited %d — the tests the document cites do not pass in this "
            "tree:\n%s" % (" ".join(cmd), crate, run.returncode, out[-3000:])
        )
    for r in gated:
        if not re.search(r"^test %s \.\.\. ok$" % re.escape(r["ref"]), out, re.M):
            p.append(
                "line %d: row %s cites `%s`, but the harness never reported "
                "`test %s ... ok`. Cargo's exit status alone is not enough: "
                "`cargo test --test %s -- --exact no_such_test` prints "
                "'0 passed; N filtered out' and exits 0."
                % (r["line"], r["label"], r["ref"], r["ref"], target)
            )
    return p


def check_outside(text, m):
    """No untagged table may appear anywhere else in the document."""
    p = []
    lo, hi = (m["begin_line"], m["end_line"]) if m else (0, 0)
    for i, ln in enumerate(text.split("\n"), 1):
        if lo <= i <= hi:
            continue
        if len(RE_BARE_INTS.findall(ln)) >= 3:
            p.append(
                "line %d: three or more bare integers OUTSIDE the cost-table block: %r "
                "— an untagged table is an ungated claim that never enters the marked "
                "region. Put it in a tagged block, or state its numbers in prose."
                % (i, ln.strip()[:70])
            )
    return p


def check(text, root, run_harness):
    p, m = parse(text)
    if m is None:
        return p, None
    p += check_derived(m)
    p += check_source(m, root)
    p += check_outside(text, m)
    if run_harness and not p:
        p += check_harness(m, root)
        # COVERAGE FLOOR — REAL DOCUMENT ONLY (reviewers, 2026-09-04).
        # "at least one gated row" lets an author downgrade seven of eight
        # gated cells to testimony and still pass. Pinned here, in the
        # real-document path only: the self-test's synthetic fixtures have
        # their own smaller blocks and must not be measured against it —
        # my first attempt put this in the shared parser and the self-test
        # caught it, which is what a self-test is for.
        expected_gated_cells = 8
        n_cells = sum(len(r["vals"]) for r in m["rows"] if r.get("kind") == "gated")
        if n_cells != expected_gated_cells:
            p.append("gated coverage is %d cells, expected %d — a row was downgraded "
                     "to testimony or the axis changed; if deliberate, change "
                     "expected_gated_cells and say why in the commit"
                     % (n_cells, expected_gated_cells))
    return p, m


# ---------------------------------------------------------------------------
# PARSER SELF-TEST. A guard never watched failing is a guard that cannot fail,
# so "can it fail?" is an assertion on EVERY run, not a memory of the night it
# was written. Same intent as check-citation-boundary.sh's matcher self-test.
# The fixtures exercise structure, arithmetic and the source binding; the
# harness leg is exercised by the real run below.
# ---------------------------------------------------------------------------

FAKE_RS = """
async fn t_const() {
    for hosts in [1usize, 2, 3, 5] {
        let (count, d) = measure(hosts, true).await;
        assert_eq!(
            count, 1,
            "mx={hosts}: exactly one"
        );
    }
}

async fn t_axis() {
    for hosts in [1usize, 2, 3, 5] {
        let (count, d) = measure(hosts, false).await;
        assert_eq!(count, hosts, "mx={hosts}: one per host");
    }
}
"""

GOOD = """prose above, no bare tables here
<!-- cost-table begin: fixture -->
# a comment
[gatefile fake/tests/f.rs]
[axis var=hosts suffix=usize]          1    2    3    5
[src testimony:deadbee]
[row regime=armed series=old]          2    2    2    2
[src gated:t_const]
[call measure(hosts, true)]
[expect const=1]
[row regime=armed series=new]          1    1    1    1
[src gated:t_axis]
[call measure(hosts, false)]
[expect axis]
[row regime=unarmed series=new]        1    2    3    5
[src testimony:deadbee]
[row regime=unarmed series=old]        2    3    4    6
[derived lhs=new rhs=old fewer=8 equal=0 more=0]
<!-- cost-table end -->
prose below
"""

FIXTURES = [
    ("good block", GOOD, None),
    (
        "one gated cell falsified, tally repaired so arithmetic alone would pass",
        GOOD.replace("series=new]          1    1    1    1", "series=new]          1    1    2    1")
            .replace("fewer=8 equal=0 more=0", "fewer=7 equal=1 more=0"),
        "GATED NUMBER DRIFT",
    ),
    (
        "a [src] removed",
        GOOD.replace("[src gated:t_const]\n", ""),
        "UNMARKED ROW",
    ),
    (
        "a derived tally rewritten to PR #47's actual wording",
        GOOD.replace("fewer=8 equal=0 more=0", "fewer=4 equal=4 more=0"),
        "DERIVED CLAIM CONTRADICTS THE TABLE",
    ),
    (
        "every gated marker removed",
        GOOD.replace("gated:t_const", "testimony:x").replace("gated:t_axis", "testimony:y")
            .replace("[call measure(hosts, true)]\n", "").replace("[expect const=1]\n", "")
            .replace("[call measure(hosts, false)]\n", "").replace("[expect axis]\n", ""),
        "ZERO GATED ROWS",
    ),
    (
        "a row one column short",
        GOOD.replace("series=old]          2    2    2    2", "series=old]          2    2    2"),
        "carries 3 integers but the axis is 4 wide",
    ),
    (
        "a cited test renamed away",
        GOOD.replace("gated:t_const", "gated:t_gone"),
        "no `fn t_gone` exists",
    ),
    (
        "an unparseable line",
        GOOD.replace("# a comment", "MX hosts 1 2 3 5"),
        "unparseable inside the cost-table block",
    ),
    (
        "the whole block deleted",
        "prose only, no block at all\n",
        "EXACTLY ONE",
    ),
    (
        "an untagged table added elsewhere in the document",
        GOOD.replace("prose below", "prose below\n  other axis   7    8    9"),
        "OUTSIDE the cost-table block",
    ),
]


def selftest():
    import shutil
    import tempfile

    tmp = tempfile.mkdtemp(prefix="semnum-selftest-")
    try:
        os.makedirs(os.path.join(tmp, "fake", "tests"))
        with open(os.path.join(tmp, "fake", "tests", "f.rs"), "w") as fh:
            fh.write(FAKE_RS)
        for label, text, want in FIXTURES:
            got, _ = check(text, tmp, run_harness=False)
            if want is None:
                if got:
                    return "self-test fixture %r must PASS but reported: %s" % (label, got[0])
            else:
                if not got:
                    return (
                        "self-test fixture %r must FAIL and did not — this gate cannot "
                        "fail, so it cannot guard" % label
                    )
                if not any(want in g for g in got):
                    return (
                        "self-test fixture %r failed for the wrong reason: expected a "
                        "message containing %r, got %r" % (label, want, got[0])
                    )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return None


bad = selftest()
if bad:
    print("SEMANTICS-NUMBERS: %s" % bad, file=sys.stderr)
    sys.exit(1)

text = open(DOC, encoding="utf-8").read()
problems, model = check(text, REPO, run_harness=True)
if problems:
    for x in problems:
        print("SEMANTICS-NUMBERS: %s" % x, file=sys.stderr)
    sys.exit(1)

gated_cells = sum(len(r["vals"]) for r in model["rows"] if r["kind"] == "gated")
test_cells = sum(len(r["vals"]) for r in model["rows"] if r["kind"] == "testimony")
print(
    "SEMANTICS NUMBERS: PASSED (%d gated cells re-checked against %d cited test(s) "
    "watched passing, %d testimony cells marked and deliberately unchecked, %d derived "
    "claim(s) recomputed from the rows)"
    % (
        gated_cells,
        len({r["ref"] for r in model["rows"] if r["kind"] == "gated"}),
        test_cells,
        len(model["derived"]),
    )
)
PY
