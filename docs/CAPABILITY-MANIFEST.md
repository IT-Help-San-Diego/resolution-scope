# Capability Manifest — Resolution Scope

**Status:** GENERATED ARTIFACT — do not hand-edit the tables. Re-run the grep
below and diff. A hand-written manifest drifts the moment someone adds a
secret; a generated one is checkable in CI (single-producer rule).

**Producing command** (run from `dns-tool-intel/go-server`):

```sh
# vars read
grep -rh "os\.Getenv(\|os\.LookupEnv(" --include="*.go" . \
  | grep -v "_test.go" | grep -oE '"[A-Z_]+"' | sort -u
# consumer package per var
for v in $VAR; do
  grep -rl "os\.Getenv(\"$v\"\|os\.LookupEnv(\"$v\"" --include="*.go" . \
    | grep -v _test | sed 's|^\./internal/||;s|^\./cmd/|cmd/|;s|/[^/]*\.go$||' | sort -u
done
```

## Measured facts (2026-08-17, dns-tool-intel main @ 74d2f5845)

- The Go parent reads **34 distinct environment variables** (secrets and config
  mixed). The "20 secrets" figure in early drafts was a proxy — this manifest
  derives from the tree, not the estimate.
- **Every read funnels through `internal/config`.** No other package calls
  `os.Getenv`/`os.LookupEnv` outside tests.
- Consumer packages holding secret *values* after config hands them out:
  `analyzer`, `config`, `db`, `handlers`.

## The seam this exposes

`config` reads EVERYTHING, so **`config` is the compartment boundary
violation**, not the four consumers. A compartment boundary drawn around
`config` as it stands grants every compartment every secret — the
monolith-inside-a-verified-kernel failure in its exact form
(ARCHITECTURE.md §3). The fix is to split `config` so each compartment
receives only the secrets its interface requires, and is fixable today on
ordinary Linux ahead of any seL4 work.

## Secret inventory → consumer packages

| Secret | Read by | Flows to | Compartment need (target) |
|---|---|---|---|
| `DATABASE_URL` (+`_OVERRIDE`) | config | `db` | **store only — no network** |
| `PROBE_API_KEY` / `PROBE_API_URL` / `PROBE_KEY` / `PROBE_LABEL` / `PROBE_PORT` / `SMTP_PROBE_MODE` | config | `analyzer` | **scanner: network + probe creds** |
| `PROBE_SSH_HOST` / `_HOST_KEY` / `_PRIVATE_KEY` / `_USER` | config | `analyzer`/probe admin | scanner admin lane |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | config | `handlers` | web auth compartment only |
| `SESSION_SECRET` | config | `handlers` | web session compartment only |
| `DISCORD_WEBHOOK_URL` | config | `handlers` | notifications compartment only |
| `SECURITYTRAILS_API_KEY` | config | `analyzer` | scanner (optional intel source) |

## Non-secret config (read but not compartment secrets)

`ANALYTICS_EXCLUDE_IPS`, `BASE_URL`, `CLOUD_DEPLOYMENT`, `INITIAL_ADMIN_EMAIL`,
`LOG_DIR`, `MAINTENANCE_NOTE`, `ORIGIN_TRIAL_TOKEN`, `PATH`, `PORT`,
`REPLIT_DEPLOYMENT`, `REPLIT_DEV_BANNER`, `REPLIT_DEV_DOMAIN`,
`REQUIRE_PDF_AUDIT`, `SECTION_TUNING`, `TRUSTED_PROXIES`,
`UD_TLD_PRODUCER_CHECK`, `YOUTUBE_VIDEO_IDS`.

## Target decomposition (from ARCHITECTURE.md §4)

| Compartment | Receives | Must NOT hold |
|---|---|---|
| scanner | network, `PROBE_*`, `SECURITYTRAILS_API_KEY` | `DATABASE_URL`, session/oauth secrets |
| filter | network + storage handle | probe creds, oauth secrets |
| store | `DATABASE_URL` only | network access, probe creds |
| web/auth | `GOOGLE_CLIENT_*`, `SESSION_SECRET` | `DATABASE_URL`, probe creds |
| notify | `DISCORD_WEBHOOK_URL` only | everything else |

## CI check (standing)

Fail the build if a new `os.Getenv`/`os.LookupEnv` call site appears outside
`internal/config`, or if this file's measured counts drift without a recorded
decision. (Gate to be wired with the first CI run of the repo.)
