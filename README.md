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
