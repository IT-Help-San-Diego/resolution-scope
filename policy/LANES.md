# LANES — the shared check-in (mechanism, not memory)

This file is the one place every lane reads at turn START and appends to at turn
END. It exists because a convention the bots *remember* keeps getting forgotten;
a file the bots *read* cannot be forgotten. Git is the transport — it survives
restarts, is version-controlled, and is the one thing all three lanes can
already reach (see transport matrix below).

## Lanes (fixed names — do not rename)

| lane | who | write access | localhost | measured how |
|---|---|---|---|---|
| `hermes` | this agent (Carey's Mac) | git read+write (push) | yes | self |
| `claude-code` | Anthropic CLI (same Mac) | git read+write (commits as Carey) | yes | hooks + MCP |
| `scispace` | SciSpace cloud assistant (remote) | **read-only** (no push path) | **no** (separate network) | SCISPACE-CAPABILITY-REPORT.md |

**"Claude Science" was a mislabel.** The remote research lane is **SCISPACE**.
Tag it `scispace` everywhere. The capability report that settles this is
`policy/SCISPACE-CAPABILITY-REPORT.md` (read it; it is the measured ground
truth, not an assertion).

## Routing invariant — the arrow never points left

A relay line has ONE shape, always left-to-right:

```
SENDER → RECIPIENT: <payload>
```

- **Arrow is always `→` (right). Never `←`.**
- **Sender is always on the LEFT. Recipient is always on the RIGHT.**
- To REPLY, you become the sender (left): Claude Code answering Hermes writes
  `CLAUDE CODE → HERMES: …`, never `HERMES ← CLAUDE CODE`. The arrow direction
  does not flip with point of view — only the names swap, and the sender is
  always the one speaking, on the left.

This is the single rule that stops the relay from mangling: a line that starts
`HERMES ← …` or ends in a left arrow is a parse error, full stop.

## Contract

1. **Read at turn start.** Before acting, `git pull` and read this file top to
   bottom. If your last line isn't the newest, someone did something you don't
   know about.
2. **Append at turn end.** One line per claim, format below. Commit + push.
3. **Speak only with a measurement or a correction.** No status theater, no
   "checking in" with nothing to say. A line that carries no new fact is noise.
4. **Carey is editor, not transport.** He pastes "okay" / "get back to work" /
   "need a decision" — never re-derives state, never relays a bot's block to
   another bot (the relay lines in chat are the fallback, not the primary).

## Mechanism per lane (how "read + append" becomes unskippable)

A remembered instruction is a convention; an executed hook is a mechanism. Each
lane's mechanism differs, and this is what decides whether it actually works:

- **hermes** — git `pre-push` hook already fires on every push (`.githooks/`).
- **claude-code** — `UserPromptSubmit` hook injects `cat LANES.md` into context
  at every turn start (cannot-not-see the ledger), and a `Stop` hook with exit
  code 2 blocks the turn from ending until the routed block is appended. These
  are *harness-executed*, not model-followed — the deterministic control the
  docs name. NOT `CLAUDE.md`, which the model can drift from.
- **scispace** — **no hook fires on its turn.** So its mechanism must be that
  the ledger is an *input it is handed*, not a file it remembers to open. In
  practice: the relay to SciSpace shrinks to a pointer — "read
  `policy/LANES.md` at `@<sha>`" — and SciSpace verifies the sha before acting,
  so a stale ledger surfaces as a mismatch rather than silent drift.

## Line format (every entry carries the sha it was written against)

```
<UTC timestamp> | <lane> | <claim or measurement> | <evidence> | @<git sha>
```

The `@<git sha>` is load-bearing: it is the commit the entry was written
against. A reader whose HEAD differs from that sha knows the ledger moved since
that entry and re-pulls before acting — the stale-measurement shape, caught at
coordination scale instead of after the fact.

Example:
```
2026-08-21T03:00Z | hermes | Arm 1 first join produced 2 disagreements (DKIM, DANE) | /api/analysis/18450 | @eeef0f0
```

## The decision surface (what the ledger answers)

A lane hitting a fork answers, in this file, one of:
- `DECISION NEEDED <id>: <the either/or, laid out>` — Carey decides.
- `BLOCKED <id>: <what I can't reach, and the one permission that would unblock>`
- `DONE <id>: <commit/run proving it>`

No bot should be paused on "what do I do next" when the ledger's newest
unanswered DECISION/ BLOCKED line names it.

## Attribution

Every commit in this repo is authored as Carey. A line's `| lane |` field is
the claim of *who reasoned*, which git cannot tell you — the only check is
reading the file against the ruling. Read it.
