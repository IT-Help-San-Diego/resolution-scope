# Calibration Study — Task Zero: the Go verdict surface (RESOLVED)

**Status:** resolved 2026-08-20, identified at source by the dns-tool-intel lane
(not guessed at URLs). This is a companion to `CALIBRATION-STUDY-SPEC.md` §
"Prerequisite for Arm 1"; the spec file itself is left byte-identical to its
checksummed hand-off (`c7bf5783905fd649…`), so this resolution lives here.

## Why the three guesses 404'd

`/api/analyze`, `/api/v1/analyze`, `/analyze.json` do not exist because the Go
tool's API is **analysis-by-id, not analyze-by-domain**: a scan is *triggered*
on one route and its machine-readable result is *retrieved* on another.

## The actual surface (all verified in `dns-tool-intel/go-server` source)

| step | route | source |
|---|---|---|
| trigger a scan | `GET`/`POST /analyze` (POST is rate-limited) | `cmd/server/main.go:612,617` → `Analyze`, `internal/handlers/analysis_scanflow.go:169` |
| watch progress | `GET /api/scan/progress/:token` | `cmd/server/main.go` route table |
| **machine-readable verdicts** | **`GET /api/analysis/:id`** | `APIAnalysis`, `internal/handlers/analysis_api.go:314` |
| content-address the result | `X-SHA3-512` response header on the same call; also `GET /api/analysis/:id/checksum` | `analysis_api.go` (`buildAnalysisJSON` returns bytes + hash) |
| re-serve a stored analysis | `GET /api/replay/:id` | route table |

`?download=1` (strictly validated: empty or `"1"` only) serves the same bytes as
an attachment.

## Payload shape (what Arm 1 consumes)

`buildAnalysisJSON` (`analysis_api.go:166`) emits a JSON object whose
`full_results` member is the complete per-control analysis map — the same
schema the golden fixtures carry and the existing differential already parses:
per-control `*_analysis` objects with `*_state` values `present` /
`absent_confirmed` / other→indeterminate (see `go_to_tri` in
`scripts/full_arm_differential.py`). Top-level convenience fields
(`spf_status`, `dmarc_status`, `dkim_status`), `provenance` (tool version,
hash algorithm, timestamps), and `citation_manifest` ride alongside.

## Two consequences for the study, both favorable

1. **Constraint #2 (reference-uncertainty) is satisfiable, not a trap here:**
   the Go reference is itself tri-state (`absent_confirmed` is distinct from
   an unmeasured state), so the honest-instrument penalty the spec warns about
   does not apply to this pairing. No rows need excluding on that ground.
2. **Constraint #4 (frozen, content-addressed corpus) has native support:**
   every `GET /api/analysis/:id` response carries its own SHA3-512, so corpus
   freezing is "store the bytes + the header value," not new tooling.

## Prior art already in this repo

`scripts/full_arm_differential.py` and the golden fixtures are a working
consumer of exactly this schema (the 5-arm live differential and the DNSSEC
fixture differential both ran on it). Arm 1 is an extension of a proven
pipeline, not a first integration.
