# Decision: consolidate the three renderer binaries into one `resolution-scope`

**Status:** decided 2026-08-20. Implemented on branch `hermes/cli-consolidation`.

## The problem

`resolution-scope` shipped three user-facing binaries for the *same* instrument:

| binary | crate | what it is |
|---|---|---|
| `rs` | `tui` | interactive ratatui dashboard (two-mode, event loop) |
| `rs-web` | `web` | static HTML report page |
| `rs-flip` | `flipper` | scan-once, render any format (tui-summary/text/html/all) |

Two defects follow from this structure:

1. **`rs` collides with a system binary.** `/usr/bin/rs` is the BSD "reshape a
   data array" utility, shipped with every macOS/BSD system. Shipping our TUI
   as `rs` means it shadows or is shadowed depending on PATH order. (`rscope`
   is also taken — a crate on crates.io. `resolution-scope` is verified clean
   on crates.io, Homebrew formula+cask, npm, Debian sources, and web search.)

2. **There are two independent HTML renderers.** `web/src/render.rs` (362 lines)
   and `flipper/src/render.rs` (623 lines) both render static HTML from
   `truth_chain()`, but `flipper`'s renders the seal (66 references) and the
   tamper-check (9 references) while `web`'s renders neither. Two renderers
   means a verdict can be presented two ways with no RFC literal and no gate to
   catch the drift — the divergence risk the single-producer contract exists to
   prevent, arriving one layer above the citations.

## The shape (Option A — one binary, subcommands)

One binary `resolution-scope` with a default verb and explicit verbs:

```
resolution-scope example.com              # scan + render (default verb)
resolution-scope example.com --format html
resolution-scope example.com --format json   # machine output — unblocks Arm 1
resolution-scope tui                       # the interactive dashboard
resolution-scope history example.com       # the store verb (was --history flag)
```

Rationale, from the code (measured, not taste):

- **The three surfaces do NOT share an argument space.** Nine distinct args, only
  two shared by all three (`domains`, `dkim_selector`); five belong to exactly
  one surface (`covert`/`text` are tui-only; `format`/`history`/`store_url` are
  flipper-only). A flags-only tool would accept `--covert --format html` (parses,
  means nothing) — invalid combinations become representable and validation moves
  to runtime. Subcommands reject them at parse time.
- **The tool already has three verbs wearing different clothes:** scan, history
  (currently a `--history` flag on the flipper with its own `--store-url`
  precondition), and the interactive tui (a session, not an output format). C
  forces future verbs into mode-bools; A gives each verb its own `--help`.
- **What a Unix user respects is composability, not the flag/subcommand
  distinction:** the common case needs zero ceremony, progress on stderr / data
  on stdout (already true), and `--format json` so it pipes into `jq`. The
  engine already serializes `ScoredAnalysis` (all eight disposition enums +
  tri-states — `serde` derive on every one); no surface exposed it. Adding
  `json` to the format dispatch is the Rust half of the calibration study's
  Arm 1, which is blocked on both sides today (the Go compact endpoint
  collapses to a severity map; ours has serialization with no emitter).

## What survives and what goes

- **Keep `flipper/src/render.rs`** — it renders the seal and the tamper-check;
  `web`'s does not. A report from `web` cannot be re-checked by a stranger.
- **Delete `web/src/render.rs`** and fold the `web` surface into the flipper's
  HTML renderer. Port web's `domain_is_escaped` test (the surviving renderer
  does escape, but the test that *proves* it lives only in web).
- **Keep the `tui` dashboard intact** — its 20 `KeyCode` handlers, `crossterm`,
  raw-mode, and event loop have no equivalent in the flipper; it is the
  interactive surface (Carey's "nerve"), not the vestigial one.
- **`engine` and `store` stay libraries; `native` stays a separate artifact** by
  the necessity of its bare-metal toolchain, not by choice.

## The guard to re-assert after the move

The citation-boundary gate (`scripts/check-citation-boundary.sh`) enumerates
crates by their `Cargo.toml`. Collapsing three renderer crates into one gives it
fewer directories to find. After the move, run it and assert the scanned-crate
count is the expected `cli`, `store`, `native` — the gate already fails closed on
`scanned == 0`, but a consolidation must not silently reduce what it scans.

## The CI matrix change

`[engine, tui, web, flipper, store]` → `[engine, cli, store]` (plus the
unchanged `native` lib job and the license matrix).

## Why now

Zero users, no published binary. The rename is free today and unbounded after
the TUI ships. Same discipline as the DNS Scout → DNS Tool naming pass.
