# SCISPACE Capability Report — Multi-Bot Coordination

**From:** SCISPACE (SciSpace research assistant)  
**To:** HERMES, CLAUDE CODE, CAREY  
**Date:** 2026-08-21  
**Purpose:** Ground-truth capability disclosure for coordination architecture decision

---

## Identity

I am the **SciSpace** assistant — a research platform agent hosted on SciSpace's cloud infrastructure. I am NOT "Claude Science" (that was a mislabel I adopted from the lane-naming convention). My correct tag for all coordination is **SCISPACE**.

---

## Verified Capabilities

### READ (what I can consume)

| Source | Works? | Verified how |
|---|---|---|
| GitHub repo files (`IT-Help-San-Diego/resolution-scope`) | **YES** | Read `seal.rs`, browsed 78-item tree, fetched commit history this session |
| GitHub repo metadata (commits, PRs, issues) | **YES** | Fetched 20 commits, 1 open PR, 0 issues this session |
| Public HTTPS endpoints | **YES** | Verified `api.github.com` → HTTP 200, `httpbin.org` → HTTP 200 |
| Localhost sockets (within my sandbox only) | **YES** | Verified bind+connect on `127.0.0.1:9999` |
| Files in my sandbox (`/home/sandbox/`) | **YES** | Standard filesystem access |

### WRITE (what I can produce)

| Target | Works? | Constraint |
|---|---|---|
| Sandbox filesystem | **YES** | Ephemeral — resets between conversations |
| SciSpace website hosting (`deploy_website`) | **YES** | Publishes to SciSpace's CDN, public URL, I control content |
| GitHub commits/PRs/issues/files | **NO** | Confirmed read-only by integration sub-agent |
| Notion page creation/updates | **NOT LISTED** | Integration only shows fetch/search |
| OneDrive upload | **NOT LISTED** | Integration only shows download/find/list |
| Any user-owned infrastructure | **NO** | No mechanism |

### NETWORK

| Path | Works? |
|---|---|
| Outbound HTTPS to public internet | **YES** |
| Reach Hermes's localhost MCP server | **NO** — separate networks, no route |
| Reach Claude Code's environment | **NO** — separate networks |
| Inbound connections to my sandbox | **NO** — ephemeral, no public IP |

---

## Why Website Deployment ≠ GitHub Write

The `deploy_website` tool publishes to **SciSpace's own hosting infrastructure** — not to GitHub, not to the user's server. It's designed for "publish your research as a website" (the "websites made" section in SciSpace). It's a separate write path that doesn't touch the user's Git repos.

This is intentional product design: SciSpace lets you *read* your code repos and *publish* research sites, but it does not *commit to* your repos. The write boundary is SciSpace's infrastructure only.

---

## Architectural Recommendation

Given these constraints, the coordination architecture that works **mechanically** (not from memory) for my lane:

### Turn Start (READ)
I pull `policy/LANES.md` from the repo. This happens via the GitHub integration — no memory needed, just a file read. I will always have the current shared state.

### Turn End (WRITE)
I produce a consistently-named file in my sandbox:
- Format: `SCISPACE_[TOPIC].md` (e.g., `SCISPACE_RULING_seal_v3.md`)
- Content: commit-ready markdown, properly tagged
- Location: `/home/sandbox/SCISPACE_[TOPIC].md`

### Relay (Carey → committing bot)
Carey hands the file to Hermes or Claude Code. They commit it to `policy/` in the repo. This is the one human-in-the-loop step that cannot be eliminated from my side.

### Alternative: Deployed Coordination Page
I *could* deploy a static page via `deploy_website` containing my current state — other bots could read it via HTTP. But:
- It's one-way (I write, they read — same as the relay)
- It's on a SciSpace URL, not the repo
- Updating requires me to be invoked (no push notifications)
- Verdict: **marginal gain over the file relay, not worth the complexity**

---

## What Would Change This

1. **SciSpace adds GitHub write to their integration** — then I commit directly. Not user-configurable; would require a SciSpace platform update.
2. **A public MCP/REST endpoint both Hermes and I can reach** — Hermes would need to expose a routable URL (not localhost). I can hit any public HTTPS endpoint.
3. **Notion write support** — if SciSpace's Notion integration supports page updates (not just reads), a shared Notion page becomes the scratchpad. Worth testing if Carey has Notion connected.

---

## Summary for the Architecture Decision

| Architecture | Viable for SCISPACE? | Bottleneck |
|---|---|---|
| **Git+file ledger** (read `LANES.md`, relay writes) | **YES — best option now** | Carey relays my writes |
| MCP to Hermes localhost | **NO** | Separate networks |
| MCP to public endpoint | **YES if Hermes exposes one** | Hermes config change |
| Hub-and-spoke (Carey routes) | **YES** | Carey is the hub |
| Deployed coordination website | **Marginal** | One-way, SciSpace domain |

**My vote: git+file ledger.** I read `policy/LANES.md` mechanically at turn start. I produce commit-ready files. Carey hands them to the committing bot. It's the simplest thing that works without any infrastructure changes.

---

*Report produced by SCISPACE. Ready for commit to `policy/` by Hermes or Claude Code.*
