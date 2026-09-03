# Measurement semantics log

What this file is: a log of the releases that change what a disposition
**means** — kept apart from ordinary changes, the way `SCORING_VERSION`
(engine/src/truth_chain.rs:966; docs/risk-weighted-score-spec-20260822.md §6)
keeps a formula change apart from the seal. A seal proves the verdict you
hold is the one that was sealed. It does not tell you whether the same
domain, measured by a later release, would have received the same verdict
for a reason that has nothing to do with the domain. This file does.

An entry is owed whenever a change moves a disposition for some class of
domains **without any change at the domain** — a stricter parser, a fetch
path that now fails where it used to succeed, a control that now resolves a
name through a different resolver. Bug fixes that make the instrument agree
with the standard belong here too: the verdict moved, and a reader comparing
two sealed reports across the release needs to know the instrument moved,
not the domain. Entries are dated by the release that ships them and name
the file and line that changed the meaning.

What does NOT belong here: copy changes, new fields printed beside the
seal, performance, anything the verdict does not depend on.

Format, one entry per change:

```
## <control> — <one-line what changed>
Release:  <version or branch/PR>          Since: <date>
Where:    <file:line of the producing code>
Before:   <what the disposition meant>
After:    <what it means now>
Moves:    <the domain class whose verdict moves, and in which direction>
Why:      <the standard or measurement reason>
```

---

## MTA-STS — a 3xx from the policy host is never followed

Release:  cc/resolver-choice (PR #40)          Since: 2026-09-03
Where:    engine/src/resolver.rs `Vantage::http_client`
          (`.redirect(reqwest::redirect::Policy::none())`);
          engine/src/analysis.rs `mta_sts_fetch_outcome`
Before:   `Enforced` / `NotEnforced` / `PolicyInvalid` were decided from the
          body reqwest returned after following up to ten redirects
          (reqwest's default policy). A policy host that answered
          `https://mta-sts.<domain>/.well-known/mta-sts.txt` with a 3xx to
          a host that served a valid policy read as **Enforced**.
After:    A 3xx is recorded in the egress ledger with its Location
          (`FetchOutcome::Redirect`) and fails the fetch through the same
          non-2xx gate as a 404: **PolicyInvalid** (hint present, policy not
          servable from the domain).
Moves:    Domains whose policy host redirects (a CDN or hosting redirect on
          the `mta-sts.` name is the common case): Enforced or NotEnforced →
          PolicyInvalid.
Why:      RFC 8461 §3.3 — "HTTP 3xx redirects MUST NOT be followed". A
          sending MTA that obeys the RFC never sees that policy; the old
          verdict described a policy no compliant sender would apply.
Controls: engine/tests/egress_ledger.rs E5 (the fetch attempt is a
          socket-layer fact); engine/src/analysis.rs
          `mta_sts_fetch_outcome_records_a_redirect_and_never_follows_it`
          (every 3xx → Redirect, result Err; deleting the branch turns a 301
          into `Status(301, 0)`).

## MTA-STS — the policy host is resolved through the validating vantage

Release:  cc/resolver-choice (PR #40)          Since: 2026-09-03
Where:    engine/src/resolver.rs `Vantage::http_client`
          (`.dns_resolver(Arc::new(VantageResolve { .. }))`) over the
          vantage's hickory resolver with `validate = true`
          (`ResolverChoice::options`)
Before:   reqwest resolved `mta-sts.<domain>` with libc `getaddrinfo` — the
          operating system's stub, whatever it was, with no DNSSEC
          validation. A policy host whose zone fails DNSSEC validation
          (bogus chain, expired signatures) still resolved through the
          system stub, and its policy could be read: **Enforced** /
          **NotEnforced** as the body said.
After:    The name is resolved by the same validating resolver every other
          control uses. A policy host whose zone fails local validation does
          not resolve; the fetch outcome is `FetchOutcome::Unresolved` and
          the disposition is **PolicyInvalid** (hint present, policy not
          reachable). Also: the lookup now leaves this machine toward the
          chosen vantage (Cloudflare by default), not the system stub, and
          appears in the wire block as a cleartext name.
Moves:    Domains whose `mta-sts.<domain>` zone (or a CNAME target's zone)
          is DNSSEC-bogus at measurement time: Enforced or NotEnforced →
          PolicyInvalid. Domains with a healthy or unsigned chain: no change.
Why:      Measure, do not derive — a policy read through an unvalidated
          lookup is a policy whose provenance the instrument did not check,
          and the instrument validates every other name it asks for. A
          validating sender would fail the same lookup.
Controls: engine/tests/egress_ledger.rs E7 (the client itself asks the
          vantage's stub, a second stub sees nothing; both `.dns_resolver`
          mutants fail it), E8 (`Unresolved` classified from the "dns error"
          stage of the source chain).

---

Not a semantics change, recorded for the reader comparing wire blocks
across the release: the fetch-failure classifier (engine/src/egress.rs
`FetchOutcome::classify`) now reads the typed source chain instead of
substrings of reqwest's `Display`. Every failure was and is
**PolicyInvalid**; what moved is the ledger's account of the failure
(TlsError vs ConnectError, and the SNI claim printed from it), not the
disposition.
