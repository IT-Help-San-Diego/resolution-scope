# Resolution Scope

The verified-substrate build of the DNS Tool family — the future of the
instrument under its own name. Resolution Scope is the family's instrument
brand (resolutionscope.com); this repository is its new wing.

## What this is

The product at [dns-tool-intel](https://github.com/IT-Help-San-Diego/dns-tool-intel)
measures domain security posture and reports it honestly. This repository is the
next substrate: the same measurements built in Rust, targeting the formally
verified seL4 microkernel via the [LionsOS](https://lionsos.org) ecosystem, so
that the family's central promise — *local scans never leave the box* — becomes
a capability-enforced property of the kernel's proof instead of a policy.

## Run it

```
cd cli && cargo build --release
./target/release/resolution-scope example.com               # measure + report
./target/release/resolution-scope example.com --format html  # static page, seal included
./target/release/resolution-scope tui example.com            # interactive dashboard
./target/release/resolution-scope --help                     # every verb and flag
```

Every report carries the verdict's seal and the exact bytes that re-derive it;
`--format text` prints the engine's own minimal render (the compartment's proof
surface), `--format json` the verdict object plus seal and scores.

## Why this instrument stays on the sidewalk

Everything Resolution Scope measures is passive, public observation: DNS
answers any resolver would hand anyone who asked, records published on
purpose, behavior visible from the outside without touching the systems that
produce it.

We are fully aware that active techniques would buy more intelligence. An
Nmap script sweep, active probing of resolvers, mass scanning — any of these
would multiply what this instrument can see, and we know exactly how. We
decline them deliberately. The mathematical analysis is *better* when the
instrument does not perturb or intrude on what it measures, and the
foundation of the internet deserves observers who treat it as a commons, not
a target range. That is the whole discipline: the view from the public
sidewalk, done carefully enough that the receipts re-derive.

Contributions are welcome under the same rule. An improvement that passes
this project's reality checks cleanly (see the doctrines in `docs/` — every
claim measured at source, every receipt kept) is wanted, whatever it improves.
An "improvement" whose yield comes from going active will be declined
regardless of how much intelligence it would add — not because we don't know
what it would find, but because we do.

## License

- **AGPL-3.0** for the analyzer core: anyone may download, run, study, and
  modify it. Operating a hosted derivative service requires publishing its
  changes — the shark tax.
- **Apache-2.0** for ecosystem-facing components (LionsOS/sDDF compartments,
  reusable crates) as they land, so the contribution is integrable by the
  projects it joins.

## First deliverable

The DNSSEC chain-evaluation slice in Rust against `hickory-dns`, validated
against the family's golden fixtures with tri-state agreement
(`absent_confirmed` / `indeterminate` / `broken`) — never the happy path.
Gated on the fixture recapture in the parent repository.

## The standard

Every claim carries a measurement. Every verdict names what it did not
measure. [The Verification Principle](https://dnstool.it-help.tech/publications).
