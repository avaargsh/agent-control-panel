# Offline safety report review

The existing `acp-evidence-verify` command supports an explicit `safety-report` subcommand. It verifies offline report consistency only; it does not run scenarios, grant a Permit, approve a release, or prove physical isolation.

## Build and review

From the repository root with the Go toolchain pinned by CI (1.27.4):

```sh
go build -o bin/acp-evidence-verify ./cmd/acp-evidence-verify
./bin/acp-evidence-verify safety-report --trust independent-trust.json --submission signed-submission.json
```

The trust file must be obtained independently from an authenticated operator-controlled source, never generated from the submitted report. Keep these files outside Agent-controlled writable directories. The command has no signing or scenario execution mode.

- Trust file: `Policy` (original policy bytes), `Infrastructure` and `Behavioral` (each contains `Plan`, `Window` and `Key`).
- Submission file: `Infrastructure` and `Behavioral` (each contains `Raw`, `Signature` and `Evidence`).
- The exact Go structures are defined in [safety_report.go](safety_report.go) and [internal/evidencepackage](../../internal/evidencepackage). The v1 format uses Go's compact JSON marshal representation, including its field names, field order and standard base64 encoding of byte slices; do not reformat signed bytes or add a trailing newline to either input file.
- Policy digest, required scenario order, verifier run ID, report digest and validity window must match trusted inputs. The command uses the current UTC clock, not a submission-supplied timestamp.
- Limits: trust file 4 MiB, submission file 52 MiB, policy/report bytes 2 MiB each, evidence item 64 KiB, evidence per dimension 16 MiB. These are provisional bounds, not a capacity guarantee.

Example summary for a complete verified fixture:

```json
{"Infrastructure":"PASS","Behavioral":"PASS","Overall":"PASS"}
```

Exit 0 means both dimensions pass the offline consistency checks. Exit 1 means a FAIL, HOLD, malformed input, I/O error or help invocation; a parsed nonpassing result may emit a JSON summary before the error on stderr. Invalid inputs can produce no JSON. Treat missing output and nonzero exit as blocked. `safety-report --help` and `-h` print usage on stderr and remain nonzero so help cannot be mistaken for verification. Existing lifecycle evidence verification remains a separate mode.

## Reproducible non-production acceptance

```sh
go test -race -count=1 -v -run '^TestSafetyReportBinary$' ./cmd/acp-evidence-verify
go test -race -count=1 ./internal/evidencepackage ./cmd/acp-evidence-verify
```

The binary test builds the actual command and uses temporary synthetic files and test-only signing keys to exercise PASS, FAIL, missing evidence and expired review windows. It checks process exit status, JSON output and stderr behavior. These fixtures are not production evidence; they do not establish verifier independence, real-world observation freshness, revocation, durable replay prevention, sandbox effectiveness or Agent behavioral safety. No output of this CLI replaces an owner-side execution or release gate.

## Audit correlation summary

Add `--audit-summary` to emit the ordinary three verdict fields plus the schema
`acp.safety-review-summary/v1`, `ReviewedAt` (UTC), `TrustDigest` and
`SubmissionDigest` (SHA-256 of the exact canonical input file bytes).
Without this flag, the original three-field output remains unchanged.

Keep the original input files and the summary in an operator-controlled
archive outside Agent-writable directories. The summary is unsigned
correlation metadata, not an immutable archive, independently attested
timestamp, receipt of source observation, or proof of historical acceptance.
It contains no original evidence bytes. No historical time override is
provided: a later invocation always applies the current UTC review window.

A nonpassing parsed report still exits 1, including when audit output is
present. Invalid inputs may emit no summary. An independent archival issuer
and durable storage with provenance controls are separate prerequisites for
authenticated historical replay.

```sh
./bin/acp-evidence-verify safety-report --trust independent-trust.json --submission signed-submission.json --audit-summary
go test -race -count=1 -v -run '^TestSafetyReportAuditSummary$' ./cmd/acp-evidence-verify
```
