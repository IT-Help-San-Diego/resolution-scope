# LANES — the shared check-in (mechanism, not memory)

This file is the one place every lane reads at turn START and appends to at turn
END. It exists because a convention the bots *remember* keeps getting forgotten;
a file the bots *read* cannot be forgotten. Git is the transport — it survives
restarts, is version-controlled, and is the one thing all three lanes can
already reach (Claude Code commits as Carey; Claude Science reads; Hermes does
both).

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

## Line format

```
<UTC timestamp> | <lane> | <claim or measurement> | <evidence: commit / run / file:line>
```

Example:
```
2026-08-21T03:00Z | hermes | Arm 1 first join produced 2 disagreements (DKIM, DANE) | /tmp/arm1-rust.jsonl + /api/analysis/18450
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
