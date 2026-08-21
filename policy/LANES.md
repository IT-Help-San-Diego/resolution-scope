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
| `claude-science` | Operon CLI sandbox bot (same Mac; its daemon serves `:8765` for a browser) | git read+write (working tree); push path unresolved (see note) | **no** (bind/connect/AF_UNIX all denied) | self-measured (see note) |
| `scispace` | SciSpace cloud assistant (remote) | **read-only** (no push path) | **no** (separate network) | SCISPACE-CAPABILITY-REPORT.md |

**`claude-science` and `scispace` are TWO different lanes, not one.** `claude-science`
is the LOCAL sandbox bot (Operon CLI, `localhost:8765`, transcript under
`~/.claude-science/`). `scispace` is the REMOTE cloud research assistant (SciSpace).
They **invert on localhost**: SciSpace's report says its sandbox can bind+connect
localhost; `claude-science` measured bind DENIED, connect DENIED, AF_UNIX DENIED
on this Mac. A mechanism built against one fails silently on the other.
`policy/SCISPACE-CAPABILITY-REPORT.md` describes **scispace only** — it is
SciSpace's self-disclosure, not a description of `claude-science`.

Open question (record, don't resolve here): the push path for `claude-science`
is unresolved — an earlier record said "no push path", its latest self-report
says "push credential present". Until a committing lane confirms, its writes are
relayed by Carey. The `:8765` in its row is the Operon daemon's own serve port
(how a browser reaches the bot), NOT a socket the agent can reach — the agent
measured all localhost bind/connect/AF_UNIX access DENIED.

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
- **claude-science** — **no hook fires on its turn.** Working-tree read+write
  confirmed (it produces rulings/edits locally); push path unresolved (see note
  above). Same pointer-and-`@sha` discipline as scispace until a committing lane
  confirms its push access.
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

2026-08-21T17:14Z | claude-code | hooks mechanism live: UserPromptSubmit injects ledger+sha at every turn start, Stop gate (exit 2) blocks left-arrow and dirty-ledger turn ends; arrow lint added to pre-push. Negative-controlled: the naive grep flagged the law quoting its own forbidden character — scoped to relay/entry lines | .claude/settings.json + .claude/hooks/ + .githooks/pre-push | @cbbc1c2

2026-08-21T18:00Z | hermes | FOURTH-LANE correction (claude-science ≠ scispace): added the claude-science row (local sandbox bot, localhost DENIED bind/connect/AF_UNIX, working-tree write, push path unresolved) + scoped SCISPACE-CAPABILITY-REPORT.md to scispace only; the two lanes INVERT on localhost. Arm 1 first join landed: example.com 6/8 agree, 2 vocabulary-class disagreements (DKIM wildcard-empty-key definition → claude-science ruling; DANE four-state NotApplicable pre-registered exclusion) | docs/arm1-20260821/README.md | @a8670dd

2026-08-21T18:30Z | hermes | DKIM ruling EXECUTED (claude-science, verified first-hand): empty p= is REVOKED (RFC 6376), not absent/broken. Added DkimDisposition::Revoked (→Absent, severity High not Critical, measured "key revoked — empty p=") + DkimDisposition::Wildcard (sentinel probe first; wildcard *._domainkey → Indet, sweep proves nothing). dkim_disposition_from_counts now emits Revoked. 111 tests pass, clippy clean. LIVE: example.com → dkim Indet/Wildcard (was Absent/KeyMismatch) | engine/src/analysis.rs + truth_chain.rs | @1ca448c

2026-08-21T19:10Z | hermes | ARM 1 FULL DIFFERENTIAL RAN (8 fixtures × 8 controls, harness scripts/arm1_differential.py, sealed arm1-join-20260821.json): 7/8 controls 100%, dkim 6/7. Two findings. FIXED: DANE SOA-suffix bug — tlsa_err_to_count used exact-equality so a leaf MX host's containing-zone NXDOMAIN (mail3.cia.gov→SOA cia.gov) read TransientError instead of measured absence; added zone_contains_host (suffix, >=2-label), DANE 5/7→7/7. RECORDED (Go coarser, not a Rust bug): google.com DKIM signs under custom selector 20230601 → Rust NotFoundDefaults/Indet honest, Go absent_confirmed over-asserts. OPEN: DnssecRequired declared-but-never-emitted (unsigned DANE → Absent where intent is Indet) needs a ruling | engine/src/analysis.rs + scripts/arm1_differential.py | @cb4bccd

2026-08-21T20:40Z | hermes | DnssecRequired RULING EXECUTED (claude-science, verified first-hand): the gate must check the MX HOST's zone, not the mail domain's apex. Specimen it-help.tech: apex DS=1 (signed) but MX smtp.google.com lives in UNSIGNED google.com — an apex gate reports Absent (a measured DANE failure attributed to the wrong party, since it CANNOT deploy DANE until Google signs google.com); a host-zone gate reports DnssecRequired. Emitted via zone_apex_of (SOA owner = zone cut) + dane_host_zone_requires_dnssec (pure gate: Unsigned|NoZone fire; SignedAndDelegated/SignedNotDelegated/BrokenChain/ChainUnverified/Unreachable pass through to the TLSA loop). DnssecRequired → Indet, severity Low, out of the denominator (already wired in truth_chain.rs:492). LIVE-VERIFIED: it-help.tech Absent→DnssecRequired, google.com DnssecRequired, cloudflare.com TlsaPublished (signed cf-emailsecurity.net passes through), nasa.gov TransientError (SERVFAIL on signed outlook.com NOT swallowed). 115 tests, clippy/fmt clean. This is the FIRST Arm-2 case firing: a shared doctrinal error invisible to N-version differential (both engines agreed 'Absent') | engine/src/analysis.rs | @f8a800c
