# Security policy

Resolution Scope is a measurement instrument: it reads public DNS and
reports domain security posture. Its own worst failure mode is a confident
wrong verdict — so correctness bugs in verdict logic are in scope here, not
just classic vulnerabilities.

## Reporting

Use GitHub's private vulnerability reporting for this repository
(Security tab → "Report a vulnerability"). It is enabled and reaches the
maintainer directly. Email works too: carey.balboa@it-help.tech.

Please include the measurement: the domain or crafted DNS response, the
command run, the verdict produced, and the verdict you believe correct —
with the RFC or record data that shows it.

## In scope

- Any input that makes the engine assert more than it measured (a false
  `Present`/`Absent` where the truth is `Indeterminate`, seal verification
  that passes on tampered bytes, tri-state collapse errors).
- Memory safety or panic-to-DoS in parsing untrusted DNS data.
- The store's sealed-history contract (tamper detection, cross-version
  verification).
- Dependency advisories affecting the above.

## Out of scope

- Vulnerabilities in domains the tool measures (report those to the domain
  owner).
- The hosted DNS Tool service (separate codebase: dns-tool-intel; report
  there or via its site).
- Findings requiring a compromised local machine.

## What we commit to

Acknowledgment, a fix or a stated reason there won't be one, and credit in
the advisory if you want it. No bug bounty exists; no response-time SLA is
promised — this is a small project and the policy does not claim otherwise.

Coordinated disclosure: give us a chance to ship a fix before publishing;
we will not sit on a report to delay you indefinitely.
