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

## TLS-RPT — NXDOMAIN carrying the domain's OWN SOA is record-absent, not "no zone"

Release:  unreleased — first tag after 2026-09-03 (PR #42)   Since: 2026-09-03
Where:    engine/src/analysis.rs `tls_rpt_err_to_disposition` (the NXDOMAIN
          arm, which was `let _ = domain;` — the scanned domain was received
          and discarded); engine/src/analysis.rs `err_soa_zone`
Before:   ANY NXDOMAIN for `_smtp._tls.<domain>` returned **NoZone**, which
          renders (engine/src/truth_chain.rs:790) as
          "no zone — domain does not exist" at `Severity::Ok`, with the line
          "No zone, so no TLS-RPT question applies." The disposition collapses
          to `TriState::Indet` (types/src/dispositions.rs:851), so the control
          left `Tally::denominator()` (present + absent) and contributed no
          weight to `risk_weighted_score` (both engine/src/truth_chain.rs).
After:    ONE shape changes, and only one. When the SOA in the NXDOMAIN's
          authority section names the scanned domain EXACTLY (ASCII-case
          insensitive, trailing dot trimmed) the verdict becomes
          **RecordAbsent** ("record absent — zone exists, no TLS-RPT",
          `Severity::Low`, `TriState::Absent`). The zone answered for itself,
          so the zone exists and only the leaf name is missing — an inference
          that needs nothing outside the packet. EVERY OTHER SHAPE IS
          UNCHANGED FROM BEFORE: a proper-ancestor SOA, a bare-TLD SOA, and
          an NXDOMAIN carrying no SOA all still return **NoZone**.
Moves:    Domains scanned AT THEIR APEX whose zone exists and which publish no
          TLS-RPT record: NoZone → RecordAbsent, Ok → Low, Indet → Absent.
          Measured 2026-09-03 against 1.1.1.1, `_smtp._tls.<domain>` TXT:
          cia.gov, irs.gov, apple.com, amazon.com, akamai.com, wellsfargo.com,
          bankofamerica.com and nih.gov all return NXDOMAIN carrying their OWN
          SOA — eight of ten sampled; the other two (google.com,
          microsoft.com) answer NOERROR and were already `Published`. Because
          the control re-enters both score sums, the coverage percentage and
          the risk-weighted score move for those domains too — a real
          Low-severity gap that used to leave the denominator now counts
          against it. NOT MOVED, deliberately: a scan of a name BELOW its own
          apex (`support.google.com`, whose `_smtp._tls` NXDOMAIN carries
          `google.com`'s SOA) keeps NoZone. That case is not decidable from
          this packet — see Why.
Why:      NXDOMAIN at `_smtp._tls.<domain>` says the queried NAME does not
          exist. It does not say the domain does not exist, and the refuting
          evidence rides in the same response: the SOA names the zone that
          answered. Reading it is measurement; assuming absence from the
          response code alone is derivation. The old verdict also made a
          sealed report contradict itself — the MTA-STS row, which DOES read
          the SOA, printed "record absent — zone exists, no MTA-STS" a few
          lines above a TLS-RPT row printing "domain does not exist" for the
          same domain in the same measurement.

          The exact-equality boundary is the whole point of the entry. A
          PROPER-ANCESTOR SOA is undecidable from one packet:
          `support.google.com` answered by `google.com` (zone exists, name
          absent) and `nonexistent.co.uk` answered by the `co.uk` REGISTRY
          servers (domain genuinely does not exist) are STRUCTURALLY
          IDENTICAL — the scanned name is one label below the zone that
          answered — with OPPOSITE correct answers. Separating a registry
          suffix from an ordinary parent zone requires the Public Suffix List
          or a second measurement (a lookup of the scanned domain's own SOA).
          Neither is available here, so the ancestor case is left exactly
          where it was. Say plainly what that means rather than dressing it
          as restraint: `NoZone` is NOT an abstention. It renders "no zone —
          domain does not exist", so for `support.google.com` the instrument
          still prints a FALSE claim after this change, exactly as it did
          before. This entry fixes the apex case and inherits the sub-label
          case unrepaired; the honest repair is one extra lookup of the
          scanned domain's own SOA, carried as its own board item. What this
          change does guarantee is that it adds no NEW unsupported claim.
Controls: engine/src/analysis.rs — every kill set below OBSERVED by mutating
          the source and running the suite, not predicted:
          `tls_rpt_err_nxdomain_own_zone_is_record_absent` (POSITIVE — with the
          NXDOMAIN arm reverted to `let _ = domain; NoZone`, kills TWO tests:
          this one and `tls_rpt_and_mta_sts_rows_agree_the_zone_exists`);
          `tls_rpt_err_nxdomain_ancestor_zone_is_no_zone` (NEGATIVE — widening
          the exact test to suffix containment kills this one ALONE; covers
          both `support.google.com`/`google.com` and `nonexistent.co.uk`/
          `co.uk`, the registry-suffix case that blocked the first attempt);
          `tls_rpt_err_nxdomain_tld_zone_is_no_zone` (NEGATIVE — making the SOA
          read unconditional kills THREE: this one, the ancestor test and the
          without-SOA test);
          `tls_rpt_err_nxdomain_without_soa_is_no_zone` (NEGATIVE — reading a
          missing SOA as RecordAbsent kills this one ALONE);
          `tls_rpt_err_nxdomain_own_zone_match_is_case_and_dot_insensitive`
          (NEGATIVE — added this round BECAUSE a mutant survived: replacing the
          normalised comparison with bare `z == domain` left the whole suite
          green, since every fixture was already lowercase and dotless);
          `record_absence_soa_test_is_exact_not_containment` (NEGATIVE — pins
          the revert: applying suffix containment to `record_absence_verdict`
          kills this one ALONE, on its `.co.uk` row. Without it the central
          deliverable of this round — reverting that function to main's exact
          equality — was unguarded and a later edit could re-apply containment
          silently);
          `tls_rpt_and_mta_sts_rows_agree_the_zone_exists` (one apex error
          shape through both controls' Err mappings and both renderers: the
          two rows agree the zone exists, and both are `TriState::Absent`).


---

## DANE + TLS-RPT — existence is MEASURED with a second query, never inferred from the SOA's name

Release:  unreleased — first tag after 2026-09-03 (PR #TBD)   Since: 2026-09-04
Where:    engine/src/analysis.rs `tlsa_err_to_count`,
          `tls_rpt_err_to_disposition`, `score_dane` (the tlsa_zone loop, the
          DnssecRequired gate loop and the TLSA loop), `score_tls_rpt`;
          new `name_exists_from_lookup` / `nxdomain_soa_is_not` /
          `zone_apex_and_existence` / `name_exists`;
          DELETED `zone_contains_host` and its unit test
Before:   An NXDOMAIN's verdict was decided by a STRING PROPERTY of the SOA
          name in the same packet. `zone_contains_host` graded a TLSA
          NXDOMAIN as a measured absence when the SOA zone was a label-
          boundary suffix of the host AND contained a dot — `contains('.')`
          standing in for "a real zone rather than a bare TLD". That proxy
          only holds for single-label TLDs. Measured live 2026-09-04, four
          rows, one moment, one vantage:

            _25._tcp.mail.nosuchdomain-zz9q.co.uk   NXDOMAIN SOA co.uk
              -> Some(0) "measured absence"   DEFECT: the domain does not exist
            _25._tcp.mail.nosuchdomain-zz9q.com.au  NXDOMAIN SOA com.au
              -> Some(0)                      DEFECT
            _25._tcp.mail.nosuchdomain-zz9q.com     NXDOMAIN SOA com
              -> None                         correct BY ACCIDENT ("com" has no dot)
            _25._tcp.aspmx.l.google.com             NXDOMAIN SOA l.google.com
              -> Some(0)                      CORRECT, and still correct

          TLS-RPT had the mirror of the same problem from the other side: PR
          #42 read the SOA by exact equality only, so a proper-ancestor SOA
          kept `NoZone` — which renders "no zone — domain does not exist"
          (engine/src/truth_chain.rs) over a live sub-label name. Its own
          comment named the repair and deferred it: "the honest repair is a
          second measurement, carried as its own board item."
After:    An NXDOMAIN's SOA names the CLOSEST ENCLOSING ZONE THAT EXISTS and
          is now read for exactly one thing it can support: if the SOA owner
          EQUALS the queried name, that zone answered for itself and
          demonstrably exists (no query spent). In every other shape the
          verdict comes from a MEASUREMENT — one SOA query at the name
          itself:
            resolves (NOERROR, incl. NODATA on a name that exists)
              -> the name exists  -> the record's absence is MEASURED
            NXDOMAIN
              -> the name's domain does not exist -> COULD NOT MEASURE
            SERVFAIL / Refused / timeout / not probed
              -> Option<bool>::None -> never claim
          The Public Suffix List was rejected deliberately. It is a mutable
          third-party list, so a verdict derived from it depends on which
          snapshot produced it; keeping verdicts re-derivable would then need
          a vendored pinned copy plus its identity in the receipt and in this
          log. A query has no vintage and anyone can repeat it.
Moves:    DANE — a domain whose MX names a host in a NONEXISTENT domain (a
          dangling or typo MX target) moves `NotConfigured` -> `TransientError`.
          That is `Absent` -> `Indet`, `Severity::Low` -> `Severity::Unmeasured`,
          and the control LEAVES the denominator
          (types/src/dispositions.rs), so the domain's tally and
          risk-weighted score both change. A scored regression for any such
          domain, and the intended repair.
          DANE (attribution, sealed) — the same host's `tlsa_zone` moves
          `ForeignZone` -> `ZoneUnmeasured`. `ForeignZone` was derived from the
          registry suffix that answered the NXDOMAIN and asserted the mail host
          lives in someone else's zone, when the host has no zone at all.
          DANE (latent, now closed) — for a dangling MX host whose closest
          enclosing zone is UNSIGNED, the DnssecRequired gate scored that
          enclosing zone's DNSKEY as if it were the host's own and returned
          "not applicable — MX host zone is unsigned" BEFORE the TLSA loop ran.
          Those domains move `DnssecRequired` -> `TransientError`. This path
          did not appear in the four-row repro (co.uk and com are both signed);
          a repair confined to `tlsa_err_to_count` would have left it lying.
          TLS-RPT — a NON-APEX scan whose `_smtp._tls.<name>` NXDOMAIN carries a
          proper-ancestor SOA, where the scanned name RESOLVES, moves
          `NoZone` -> `RecordAbsent`. That retires a false claim about a live
          name and moves the control from Indet into a measured Low finding, so
          it re-enters both score sums. Any prior sealed report of a subdomain
          scan will not reproduce.
          DOES NOT MOVE: apex scans whose NXDOMAIN carries their own SOA (the
          exact-equality shortcut, unchanged and unprobed); every NODATA
          outcome on any control; every SERVFAIL/timeout; DNSSEC, CSYNC, CDS
          and CDNSKEY, whose NXDOMAIN is measured at the scanned name itself
          and was already right; SPF, DKIM, DMARC, MTA-STS and CAA, which stay
          on `record_absence_verdict`'s exact equality, untouched.
          STILL WRONG, NOT AN ABSTENTION — say it plainly rather than claim a
          complete repair. When the probe itself fails (SERVFAIL, timeout,
          Refused) TLS-RPT keeps `NoZone`, and `NoZone` still renders "no zone
          — domain does not exist". For a live sub-label name whose probe did
          not answer, the instrument still prints a claim the packets cannot
          support. The class is narrowed to unmeasurable probes, not
          eliminated. Separately and knowingly unrepaired:
          `record_absence_verdict` under-claims on sub-label scans — `_dmarc`
          and `_mta-sts` NXDOMAIN under an ancestor SOA read `Indet` ("could
          not measure") for a record that is genuinely absent. That direction
          loses a measurement but never asserts a falsehood, so it is out of
          scope; the same probe would repair it, and this change makes the
          asymmetry conspicuous.
Why:      RFC 1035 §4.3.4 / RFC 2308 §2.1: the SOA in a negative answer's
          authority section is the SOA of the zone that answered — the closest
          enclosing zone that exists. Nothing in the protocol makes it a
          statement about the queried name's own domain, and no label count,
          dot count or suffix rule recovers one: `support.google.com` under SOA
          `google.com` (zone exists, name absent) and `nonexistent.co.uk` under
          SOA `co.uk` (domain does not exist) are structurally identical
          packets with opposite correct answers. Only a measurement separates
          them. RFC 7672 §3 is why the DANE direction matters: a TLSA absence
          is only a finding about a mail host that exists.
COST:     One extra wire query per NXDOMAIN leg that the packet cannot decide,
          measured as a ceiling with no resolver cache (hickory does cache,
          including negatives, so the real cost is lower; the hit rate inside
          one scan is UNVERIFIED). TLS-RPT: at most one per scan, and ZERO on
          an apex scan (pinned by `apex_scan_spends_no_probe_on_tls_rpt`).
          DANE: ZERO extra — `score_dane` already issued `lookup(host, SOA)`
          TWICE per MX host (attribution, then the DnssecRequired gate) and
          `apex_from_soa_result` threw away the response code that is the whole
          existence signal. `zone_apex_and_existence` reads both facts from one
          answer, so the two passes collapse to one and the DANE scan issues
          FEWER queries than before.
KNOWN COST, RE-DERIVABILITY: a DANE or TLS-RPT verdict now depends on a SECOND
          packet taken at a different instant, and that packet is NOT in the
          receipt — the probe deliberately bypasses `observed_lookup` to
          preserve the one-receipt-per-control census
          (engine/tests/control_enumeration_invariants.rs). A reader holding a
          sealed report can no longer re-derive these two verdicts from the
          receipt alone. That is real epistemic debt and wants a receipt-schema
          card. It also makes the verdict non-atomic: a name created or deleted
          between the two queries yields an inconsistent pair (the failure mode
          is a conservative `None`, never a fabricated absence). And a wildcard
          zone (`*.example.com`) makes any name under it answer, so the probe
          reports exists=true for a name never explicitly provisioned — the
          name does resolve and mail would route there, so the verdict is
          defensible, but it is a decision, written down here rather than
          discovered later.
Controls: every kill set below was OBSERVED by mutating the source, running
          `cargo test --locked --no-fail-fast` in engine/, and restoring —
          none is predicted. Pure mapper controls hold the PACKET constant and
          vary only the probe, so the probe is the sole variable.
          engine/src/analysis.rs:
          `tlsa_err_nxdomain_ancestor_soa_is_decided_by_the_probe` (the
          co.uk row, all three probe values);
          `tlsa_err_nxdomain_row_four_regression_pin` (aspmx.l.google.com must
          stay Some(0));
          `tlsa_err_nxdomain_own_zone_is_measured_absence_without_a_probe`;
          `tlsa_err_nodata_ignores_the_probe`;
          `tlsa_err_servfail_is_unmeasured_even_when_the_probe_says_exists`;
          `name_exists_from_lookup_table`;
          `nxdomain_soa_is_not_decides_when_to_spend_a_query`;
          `tls_rpt_err_nxdomain_ancestor_zone_is_decided_by_the_probe` (this
          assertion MOVED — it asserted NoZone before this change, and that it
          moved is the visible proof the behaviour did).
          engine/tests/nxdomain_existence_probe.rs — the WIRING controls, two
          scans per guard differing in ONE canned answer, every packet on
          127.0.0.1 (the loopback stub gained an AUTHORITY section, without
          which it could not emit NXDOMAIN-with-SOA at all):
          `dangling_mx_host_is_not_a_measured_dane_absence`;
          `tls_rpt_ancestor_soa_is_decided_by_a_second_query`;
          `apex_scan_spends_no_probe_on_tls_rpt`.
          OBSERVED KILL SETS (mutant -> tests that failed):
            M1  `Some(false) => Some(0)` in tlsa_err_to_count            -> 4
            M2  delete the exact-equality arm in tlsa_err_to_count       -> 1
            M3  TLSA call site hardcodes the probe to None               -> 1
            M4  TLSA call site hardcodes the probe to Some(true)         -> 1
            M5  invert NXDomain/NoError in name_exists_from_lookup       -> 3
            M6  remove the DnssecRequired gate's existence skip          -> 1
            M7  `Some(true) => NoZone` in tls_rpt_err_to_disposition     -> 2
            M8  remove the tlsa_zone attribution's existence skip        -> 1
            M9  nxdomain_soa_is_not always true (always spend a query)   -> 2
            M10 TLS-RPT call site stops probing                          -> 1
            M11 transient probe promoted to Some(true)                   -> 1
            M12 `if ok { return None }` in name_exists_from_lookup       -> 2
          No survivors. Suite green on restore after every one.
          DELIBERATE COVERAGE LOSS, stated so it does not read as an accident:
          `zone_contains_host` and its passing test
          `zone_contains_host_suffix_matching` are DELETED. The helper was the
          site of this defect and has no production caller after the change;
          leaving a suffix-existence heuristic in the file invites the defect
          back. The suite's test count drops by that one test and gains the
          controls above.


---

Not a semantics change, recorded for the reader comparing wire blocks
across the release: the fetch-failure classifier (engine/src/egress.rs
`FetchOutcome::classify`) now reads the typed source chain instead of
substrings of reqwest's `Display`. Every failure was and is
**PolicyInvalid**; what moved is the ledger's account of the failure
(TlsError vs ConnectError, and the SNI claim printed from it), not the
disposition.
