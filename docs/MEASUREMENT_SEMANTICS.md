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
not the domain. Entries are dated by the release that ships them — the
first tagged version carrying the change, with the PR as the citation;
until that tag exists the field reads "unreleased" — and name the file
and line that changed the meaning. README.md ("Run it") points here.

What does NOT belong here: copy changes, new fields printed beside the
seal, performance, anything the verdict does not depend on.

Format, one entry per change:

```
## <control> — <one-line what changed>
Release:  <first tagged version, or "unreleased — first tag after <date>" (PR #n)>   Since: <date>
Where:    <file:line of the producing code>
Before:   <what the disposition meant>
After:    <what it means now>
Moves:    <the domain class whose verdict moves, and in which direction>
Why:      <the standard or measurement reason>
```

---

## MTA-STS — a 3xx from the policy host is never followed

Release:  unreleased — first tag after 2026-09-03 (PR #40)   Since: 2026-09-03
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
          into `Status(301, 50)` in that test — the 50-byte policy body it
          passes — and into `Status(301, 0)` on the production path, which
          never reads a 3xx body).

## MTA-STS — the policy host is resolved through the validating vantage

Release:  unreleased — first tag after 2026-09-03 (PR #40)   Since: 2026-09-03
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
          PolicyInvalid. Domains with a healthy or unsigned chain move too
          whenever the vantage's answer for `mta-sts.<domain>` differs from
          the system stub's, because the address set handed to the client
          is now the vantage's (engine/src/resolver.rs, `impl reqwest::dns::Resolve for VantageResolve`:
          `resolver.lookup_ip`) and nothing else: a hosts-file entry, an
          internal or split-horizon zone the system stub serves and the
          public vantage does not, a search-domain completion, or a name
          the stub resolves and the vantage answers NXDOMAIN/SERVFAIL for
          → `FetchOutcome::Unresolved`, PolicyInvalid (and the reverse:
          a name the stub could not resolve and the vantage can → the
          policy is now read). Only a domain whose `mta-sts.` name
          resolves to the same reachable addresses at both is unchanged.
Why:      Measure, do not derive — a policy read through an unvalidated
          lookup is a policy whose provenance the instrument did not check,
          and the instrument validates every other name it asks for. A
          validating sender would fail the same lookup.
Controls: engine/tests/egress_ledger.rs E7 (the client itself asks the
          vantage's stub, a second stub sees nothing, and the connect is
          observed as an accept at the address the stub answered; both
          `.dns_resolver` mutants fail it), E8 (`Unresolved` classified
          from the "dns error" stage of the source chain).

## MTA-STS — the policy fetch ignores the environment's proxy

Release:  unreleased — first tag after 2026-09-03 (PR #40)   Since: 2026-09-03
Where:    engine/src/resolver.rs `Vantage::http_client` (`.no_proxy()`)
Before:   reqwest's default client honoured `HTTPS_PROXY` / `https_proxy`
          / `ALL_PROXY` from the environment (this build's reqwest has
          `default-features = false`, engine/Cargo.toml:70, so no OS proxy
          settings were ever read). On a machine whose only path to port
          443 ran through such a proxy,
          the policy was fetched through it: **Enforced** / **NotEnforced**
          as the body said — and the bytes left this machine toward the
          proxy, not toward `mta-sts.<domain>`, while the report named the
          policy host.
After:    The client connects directly to an address the vantage resolved,
          whatever the environment says. On that same machine the connect
          fails or times out (`FetchOutcome::ConnectError` /
          `Timeout`) and the disposition is **PolicyInvalid** (hint
          present, policy not reachable). Where a proxy also inspected or
          rewrote the response, the policy is now read from the origin.
Moves:    Domains measured from a host with no direct egress to 443
          (proxy-only networks): Enforced or NotEnforced → PolicyInvalid.
          Elsewhere: no change, unless the proxy answered differently from
          the origin.
Why:      Measure, do not derive — the wire block prints the destination
          reached (`FetchEntry.peer`, getpeername on the response socket)
          and the HTTPS line names port 443 at `mta-sts.<domain>`; a proxy
          hop would make both lines describe a socket that was never
          opened. The instrument's claim is the direct path or nothing.
Controls: engine/tests/egress_ledger.rs E5 (the accept at the policy host
          is the socket-layer fact), E7 (the connect reaches the address
          the vantage answered, not an intermediary). No test sets a proxy
          variable: the seam is reqwest's builder, and E7 is the observed
          direct connect.

## TLS-RPT — NXDOMAIN reads the SOA instead of asserting the domain is gone

Release:  unreleased — first tag after 2026-09-03 (PR #PRNUM)   Since: 2026-09-03
Where:    engine/src/analysis.rs `tls_rpt_err_to_disposition` (the NXDOMAIN
          arm, which was `let _ = domain;` — the scanned domain was received
          and discarded); engine/src/analysis.rs `err_soa_zone`,
          `zone_contains_host`
Before:   ANY NXDOMAIN for `_smtp._tls.<domain>` returned **NoZone**, which
          renders (engine/src/truth_chain.rs:790) as
          "no zone — domain does not exist" at `Severity::Ok`, with the line
          "No zone, so no TLS-RPT question applies." The disposition collapses
          to `TriState::Indet` (types/src/dispositions.rs:851), so the control
          left `Tally::denominator()` (present + absent) and contributed no
          weight to `risk_weighted_score` (both engine/src/truth_chain.rs).
After:    The SOA in the NXDOMAIN's authority section — the same packet, the
          same measurement `record_absence_verdict` and `tlsa_err_to_count`
          already make — decides it. SOA's zone contains the scanned name →
          **RecordAbsent** ("record absent — zone exists, no TLS-RPT",
          `Severity::Low`, `TriState::Absent`). Bare-TLD SOA, or no SOA at
          all → **NoZone** stands, and is still reachable for a domain that
          genuinely does not exist.
Moves:    Every domain whose zone exists and which publishes no TLS-RPT
          record: NoZone → RecordAbsent, Ok → Low, Indet → Absent. That is
          the majority of live domains. Measured 2026-09-03 against
          1.1.1.1, `_smtp._tls.<domain>` TXT: cia.gov, irs.gov, apple.com,
          amazon.com, akamai.com, wellsfargo.com, bankofamerica.com and
          nih.gov all return NXDOMAIN carrying their OWN SOA — eight of ten
          sampled; the other two (google.com, microsoft.com) answer NOERROR
          and were already `Published`. Because the control re-enters both
          score sums, the coverage percentage and the risk-weighted score
          move for every one of those domains too — a real Low-severity gap
          that used to leave the denominator now counts against it.
Why:      NXDOMAIN at `_smtp._tls.<domain>` says the queried NAME does not
          exist. It does not say the domain does not exist, and the refuting
          evidence rides in the same response: the SOA names the zone that
          answered. Reading it is measurement; assuming absence from the
          response code alone is derivation. The old verdict also made a
          sealed report contradict itself — the MTA-STS row, which DOES read
          the SOA, printed "record absent — zone exists, no MTA-STS" a few
          lines above a TLS-RPT row printing "domain does not exist" for the
          same domain in the same measurement.
Controls: engine/src/analysis.rs
          `tls_rpt_err_nxdomain_own_zone_is_record_absent` and
          `tls_rpt_err_nxdomain_containing_zone_is_record_absent`
          (positive — both fail if the NXDOMAIN arm is reverted to
          `let _ = domain; NoZone`);
          `tls_rpt_err_nxdomain_tld_zone_is_no_zone` (negative — fails, and
          alone, if the SOA read is made unconditional);
          `tls_rpt_err_nxdomain_without_soa_is_no_zone` (negative — fails,
          and alone, if a missing SOA is read as RecordAbsent);
          `tls_rpt_and_mta_sts_rows_agree_the_zone_exists` (one error shape
          through both controls' Err mappings and both renderers: the two
          rows agree the zone exists, and both are `TriState::Absent`).

## Every control — the NXDOMAIN SOA test is zone containment, not zone equality

Release:  unreleased — first tag after 2026-09-03 (PR #PRNUM)   Since: 2026-09-03
Where:    engine/src/analysis.rs `record_absence_verdict` (the NXDOMAIN arm's
          SOA test: `z.eq_ignore_ascii_case(domain)` → `zone_contains_host`)
Before:   NXDOMAIN counted as measured absence only when the SOA named the
          scanned domain EXACTLY. A scanned name that is not its own zone
          apex is answered by its parent zone's SOA, so the test was false
          and the verdict was `TriState::Indet` — which
          `spf_err_to_disposition`, `dmarc_err_to_disposition`,
          `mta_sts_err_to_disposition` and `caa_err_to_disposition` each
          collapse to their `TransientError` variant, rendered as
          "transient lookup error" (engine/src/truth_chain.rs:390, :436,
          :572, :687) — an invitation to re-run a measurement that cannot
          come out differently.
After:    The same suffix test DANE already uses (`zone_contains_host`, with
          its >=2-label guard so a bare TLD is never a containing zone): the
          SOA's zone containing the scanned name means the zone exists and
          the name does not → **Absent**. A bare-TLD SOA, or none, is still
          the domain itself missing → **Indet**.
Moves:    Scanned names below their own zone apex, for each control whose
          query returns NXDOMAIN: TransientError → the control's measured
          absence (SPF `NotConfigured`, DMARC `NotConfigured`, MTA-STS
          `RecordAbsent`, CAA `NotConfigured`, DANE `NoMx`), Indet → Absent,
          so those controls also re-enter both score sums. Measured
          2026-09-03 against 1.1.1.1: for `support.google.com` (a name that
          exists under the `google.com` zone) `_dmarc` and `_mta-sts` are
          NXDOMAIN with `google.com`'s SOA and move, while TXT and CAA at the
          name itself answer NOERROR and were already measured — they do not
          move. For a name that does NOT itself exist under the zone
          (`nosuchhost.google.com`) every one of TXT, CAA, MX and the
          underscore names is NXDOMAIN with `google.com`'s SOA, and all of
          those controls move at once. Apex scans are unaffected: the apex's
          own SOA satisfies containment exactly as it satisfied equality.
Why:      An NXDOMAIN's SOA names the closest enclosing zone, which for any
          name below the apex is the parent — never the queried name. Equality
          therefore tested something the packet does not carry. Containment
          tests what it does. Same bug class, same cure, as the DANE fix
          documented at engine/src/analysis.rs `tlsa_err_to_count`.
Controls: engine/src/analysis.rs
          `record_absence_nxdomain_containing_zone_is_absent` (positive, the
          middle case the two existing tests straddled: `support.google.com`
          with `google.com`'s SOA → Absent, and the four control mappings
          follow it out of TransientError — fails, and alone, if the test is
          reverted to exact equality);
          `record_absence_nxdomain_parent_zone_is_indet` (negative, existing:
          a bare-TLD SOA is still Indet — fails if the >=2-label guard inside
          `zone_contains_host` is dropped);
          `record_absence_nxdomain_own_zone_is_absent` and
          `record_absence_nodata_is_absent` (existing, still passing).

---

Not a semantics change, recorded for the reader comparing wire blocks
across the release: the fetch-failure classifier (engine/src/egress.rs
`FetchOutcome::classify`) now reads the typed source chain instead of
substrings of reqwest's `Display`. Every failure was and is
**PolicyInvalid**; what moved is the ledger's account of the failure
(TlsError vs ConnectError, and the SNI claim printed from it), not the
disposition.
