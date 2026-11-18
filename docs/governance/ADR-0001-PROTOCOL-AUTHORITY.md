# ADR-0001: One authority per contract and separate Decision protocols

Status: **PROPOSED**, awaiting cross-service agreement. Date: 2026-11-02.
Tracking: https://github.com/avaargsh/agent-control-panel/issues/3 and https://github.com/avaargsh/agent-decision/issues/9.

## Context

Three incompatible Decision surfaces exist under similar v0.1 labels:
- ACP PR #1: DecisionTurn with tenant field, inline context, FinalResponse/ActionProposals.
- Agent Decision PR #1/#2: Python plugin with context refs, three result kinds, per-invocation response ledger.
- Agent Decision PR #8: Go-first SRE Decision Core with /v1/decisions, PROPOSED/ABSTAINED and immutable DecisionRecord.

Each validates independently, but no single client can assume wire compatibility.

## Proposed decision

1. Go-first Decision Core remains the authoritative DecisionRecord writer in agent-decision.
2. Framework adapter is a distinct interface and protocol, only for bounded reasoning; an implementation may be in Python or TypeScript.
3. Each wire contract belongs to its endpoint owner. Schema, OpenAPI, fixtures and semantic validator must be version-pinned and consumers consume these **without copying**.
4. Platform governance pins immutable source revisions and compatibility records; it is not a replacement protocol publisher.
5. No implicit conversion of needs_input into FinalResponse, no silent dropping of tenant/context fields, no reinterpretation of PROPOSED as an executable Action.
6. Runtime creates the Run ID; Decision inputs reference that ID and trusted principal binding; Decision does not create Run IDs.
7. Versioning includes URI/operation name, request shape, response discriminators and error envelope. Two incompatible shapes must not both claim to be a single v0.1.

## Alternatives

- Central shared canonical Schema in agent-control-panel: simpler location, but duplicates service ownership and creates conflicting sources of truth.
- Go service and Python plugin both publish DecisionRecord: duplicates immutable ledger, replay behavior, and domain authority.
- Rewrite all inference frameworks in Go: unnecessary duplicated framework work.

## Required signoff and tests

- ACP: domain and RunIntent ownership
- Runtime: Go clients, Temporal retries, bounded adapter contract
- Decision: Go Core and plugin adapter API owners
- EngageGuard: no action authorization in Decision response
- Fixture tests: Go, Python, TS accept/reject the exact same protocol version and ID/tenant/response edge cases

This ADR is **not** approved or a live protocol migration. Implementations remain Draft until agreement.
