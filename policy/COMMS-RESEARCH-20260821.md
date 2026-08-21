# Comms research — how teams connect multiple agents (2026-08-21)

Deep-read against primary sources, not snippets: Hermes docs (MCP + Kanban
pages), the MCP spec (modelcontextprotocol.io), and Claude Code MCP docs
(docs.anthropic.com/en/docs/claude-code/mcp).

## The pattern we've converged on is mainstream, not novel

The multi-agent literature names what we do **shared-memory / blackboard
coordination** — agents coordinate through shared state (a message bus, a
ledger, a repo) rather than a fixed supervisor. It's one of the primary named
patterns ("swarm / emergent coordination"). We arrived at it by accident (git
repo + `policy/` files); the literature formalizes it.

## Hermes already ships two mechanisms that fit

1. **Kanban** (`hermes kanban`) — a durable task board "shared across all your
   Hermes profiles," where "every handoff is a row anyone can read and write,"
   workers are "full OS processes with their own identity," and **Comment is
   explicitly the inter-agent protocol** (a worker reads the full comment
   thread when spawned). This is *exactly* the "one centralized place every bot
   checks" — but it coordinates **Hermes profiles only**, not Claude Code or
   Claude Science, which are separate apps.

2. **MCP** (`hermes mcp serve`) — Hermes can *be* an MCP server; other MCP
   clients connect to it. Claude Code is a native MCP client
   (`claude mcp add --transport http <name> <url>`), so **Hermes ↔ Claude Code
   bridges cleanly over MCP today, no vendor hack.** Claude Science's sandbox
   reachability is the open question.

## The sharp finding

We are **not missing a mechanism — we are missing a mechanical check-in.** The
git repo already IS the shared memory; all three lanes can reach it. What
breaks is the *convention* (read the log at turn start, append at turn end),
because a convention lives in memory and memory drifts. The fix is the same
shape as every fix this session: make it unable to be skipped. A file the bots
read (`policy/LANES.md`) cannot be forgotten; a rule they "should remember"
will be.

## What is NOT needed

No rule-breaking, no vendor-internal patches, no update-fragile hacks. MCP is
an open standard; Kanban is a first-class Hermes feature; git is git. The
"permission" this actually needs is, at most, **read-only filesystem access to
the repo for the lane whose sandbox doesn't already have it**, plus localhost
reachability for an MCP server — ordinary, documented, grantable.

## Source pages

- https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp
- https://hermes-agent.nousresearch.com/docs/user-guide/features/kanban
- https://modelcontextprotocol.io/introduction
- https://docs.anthropic.com/en/docs/claude-code/mcp
