# Cross-Service Identifier Lifecycle — v0.2

Status: **Proposed candidate; cross-service protocol gates remain blocked.** Read with [ADR-003](ADR-003-IDENTITY-AND-RETRY-OWNERSHIP.md) and [Cross-Service Contracts](CROSS-SERVICE-CONTRACTS.md). G03 Action operation identity and ActionHash details are not ratified.

## Candidate identifier creators and owners

| Identifier | Created by | Authoritative owner | Stability |
|---|---|---|---|
| `tenant_id`, `project_id` | Agent Control Plane | Agent Control Plane | Stable scope identities |
| `agent_id`, `bundle_digest`, `release_id` | Agent Control Plane | Agent Control Plane | Release binds an immutable bundle digest |
| `session_id` | Agent Control Plane | Agent Control Plane | Stable across multiple Runs |
| `run_intent_id` | Agent Control Plane | Agent Control Plane | Stable idempotent request to start one logical Run |
| `run_id` | Agent Runtime | Agent Runtime | Created once per accepted RunIntent; stable across retries/recovery |
| `workflow_id` | Agent Runtime | Agent Runtime defines mapping; Temporal owns history | Deterministic from `run_id`; never regenerated per attempt |
| `run_attempt_id` | Agent Runtime | Agent Runtime | One durable Runtime attempt; not a Temporal Activity retry |
| `invocation_id` | Agent Runtime | agent-decision owns invocation ledger/result | Stable across retries of one logical Decision Turn |
| `proposal_id` | agent-decision | agent-decision | Stable in the persisted/replayed invocation result |
| `guard_submission_key` (HTTP `Idempotency-Key`) | Agent Runtime | EngageGuard idempotency index | Created once per ActionProposal; reused on every submission/retry |
| `operation_id` | EngageGuard | EngageGuard Action Operation | Server-generated on first accepted submission; returned to Runtime; never supplied by Runtime |
| `action_hash`, `permit_id` | EngageGuard | EngageGuard | Hash after trusted canonicalization; Permit bound to exact action/operation/audience |
| `executor_attempt_id` | Trusted executor / EngageGuard | EngageGuard Receipt | One concrete executor attempt; not a Run or Temporal attempt |
| `workload_id`, `allocation_id` | Compute Control Plane | Compute Control Plane | Stable logical compute resources |
| `compute_operation_id` | Compute Control Plane | Compute Control Plane | Stable for one provider mutation intent |
| `provider_resource_id` / UID | Provider / Kubernetes | Provider / Kubernetes | Native reference, never canonical platform identity |
| `event_id` | Event producer | Event producer | Immutable event envelope identity |
| `correlation_id` | Request origin / gateway | Request origin | End-to-end correlation, not authorization |
| `evidence_digest` | Evidence producer | Producing service | Digest of that producer's immutable evidence payload |

## Run and Workflow identity

1. Control Plane creates `run_intent_id` and stores tenant/principal-scoped idempotency key plus canonical request digest.
2. Runtime consumes the RunIntent and creates `run_id` in the same local transaction as its unique mapping from `run_intent_id` + request digest.
3. Duplicate delivery or StartRun with the same intent/digest returns the existing `run_id`; a different digest for the same intent conflicts.
4. Runtime derives the only Temporal Workflow ID using:

   ```text
   workflow_id = "agent-run/v1/" + run_id
   ```

5. Control Plane stores Runtime's matching `run_id` and `workflow_id` only after validating the receipt's `run_intent_id`, digest, tenant and identifiers.
6. Runtime uses Temporal's explicit Workflow ID conflict/reuse policy. Duplicate start inspects/returns the existing execution; it never silently chooses a new Workflow ID.

The Runtime-generated `run_id` must be globally unique (UUIDv7 or another collision-resistant opaque ID). Tenant authorization comes from verified identity and persisted ownership, never from the ID or caller-supplied tenant field.

## Attempt namespaces

- `run_attempt_id`: Runtime-owned durable execution attempt. It changes only when Runtime deliberately creates a new business attempt under Run policy.
- Temporal Workflow/Activity attempt counters: Temporal-native metadata; do not serialize them as `run_attempt_id`.
- `executor_attempt_id`: concrete EngageGuard trusted-executor attempt, included in Receipt.
- Provider mutation retries retain the same `compute_operation_id` and generation; they do not create a new logical Allocation.

## Decision invocation

1. Runtime assigns `invocation_id` before the first Decision request and reuses it across Temporal Activity retries.
2. Decision owns the invocation ledger, request digest and exact result.
3. Same invocation ID + same digest replays the exact result; same ID + different digest conflicts.
4. `proposal_id` is created by Decision and is stable in the persisted result. It is not an operation ID and conveys no authorization.

## Action operation and hash chain

1. Decision returns an untrusted ActionProposal. It does not choose an authorization result, Permit, operation ID or ActionHash.
2. Runtime persists the accepted proposal and assigns one `guard_submission_key` before first EngageGuard submission.
3. Runtime reuses the same `guard_submission_key` and semantically identical request on every retry. The `operation_id` wire contract remains blocked until EngageGuard/Runtime resolve whether it is client-issued or server-generated.
4. EngageGuard derives subject/tenant/workload from authenticated context, resolves trusted capability binding, validates and normalizes the action, then computes ActionHash.
5. The exact ActionHash domain separator and preimage are unresolved across current drafts; no value in this repository is normative until EngageGuard and Runtime ratify one versioned contract (G03).
6. The ACP-local `contracts/engageguard/action-hash/v0.1/workspace-write-vectors.json` remains a historical comparison fixture only; it must not be used as a production authorization contract.
7. EngageGuard binds AuthorizationDecision, Approval, one-time Permit, Action Operation Journal and Receipt to the same operation ID and hash.
8. Reusing an Action operation ID with a different canonical action/hash is a conflict and fails closed. Runtime records only a verified Receipt.

## Compute operation namespace

An Agent-originated protected compute request is authorized by EngageGuard at the action boundary. Compute Control Plane creates a distinct `compute_operation_id` and owns Workload, Allocation, provider operation journal and provider reconciliation. Action and Compute operations are linked by references/correlation, never by sharing one ID or state machine.

Internal Compute controller operations use Compute workload identity and its domain authorization policy. Compute remains authoritative for Kubernetes/Kueue/provider observations.

## Required local database constraints

- Control Plane: unique tenant/principal/idempotency key; persist canonical request digest.
- Runtime: UNIQUE(`run_intent_id`), UNIQUE(`run_id`), UNIQUE(`workflow_id`).
- Decision: UNIQUE(`invocation_id`); persist request digest and exact result.
- EngageGuard: UNIQUE(tenant_id, guard_submission_key); unique server-generated operation_id; immutable canonical ActionHash once claimed.
- Compute: UNIQUE(`compute_operation_id`); generation/version fencing.
- Evidence: immutable digest plus producer identity and schema version.

These are local constraints in each owning service; no cross-service database transaction is implied.
