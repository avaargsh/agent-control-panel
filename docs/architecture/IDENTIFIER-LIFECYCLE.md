# Cross-Service Identifier Lifecycle — v0.1

Status: Proposed contract; freeze together with Cross-Service Contracts v0.1.

## Canonical identifiers and owners

| Identifier | Created by | Authoritative owner | Stability |
|---|---|---|---|
| `run_intent_id` | agent-control-panel | agent-control-panel | Stable for one accepted client intent |
| `run_id` | agent-runtime | agent-runtime | Created once per accepted `run_intent_id`; stable across retries/recovery |
| `workflow_id` | agent-runtime | agent-runtime defines mapping; Temporal owns history | Deterministic from `run_id`; never regenerated per attempt |
| `run_attempt_id` | agent-runtime | agent-runtime | One durable Runtime execution attempt; not a Temporal Activity retry |
| `invocation_id` | agent-runtime | agent-decision owns DecisionRecord | Stable across retries of one logical Decision Turn |
| `proposal_id` | agent-decision | agent-decision | Stable in the persisted/replayed invocation result |
| `action_operation_id` | agent-runtime | EngageGuard owns the Action Operation record | Created once when Runtime accepts a proposal; reused on every submission/retry |
| `action_hash` | EngageGuard | EngageGuard | Computed after trusted canonicalization; never accepted from the plugin |
| `executor_attempt_id` | EngageGuard / trusted executor | EngageGuard receipt | One concrete executor attempt; not a Run or Temporal attempt |
| `compute_operation_id` | compute-control-panel | compute-control-panel | Stable for one provider mutation intent |
| `allocation_id` | compute-control-panel | compute-control-panel | Stable logical Allocation identity |
| `provider_resource_id` | Provider | Provider; stored as a reference by Compute | Provider-native and non-canonical |
| `evidence_digest` | Evidence producer | Producing service | Digest of that producer's immutable evidence payload |

## Run and Workflow identity

1. The Control Plane creates and owns `run_intent_id` when it accepts an idempotent RunIntent.
2. Runtime consumes the RunIntent and creates `run_id` in the same local transaction as its unique mapping from `run_intent_id` to `run_id`.
3. A duplicate delivery or StartRun request for the same `run_intent_id` returns the existing `run_id`; it must not create a second logical Run.
4. Runtime derives the sole Temporal Workflow ID using:

   ```text
   workflow_id = "agent-run/v1/" + run_id
   ```

5. Control Plane stores the returned `run_id` and `workflow_id` as references/projection fields. It does not independently generate either value.
6. Runtime must use Temporal's explicit Workflow ID conflict/reuse policy. A duplicate start must inspect/return the existing execution, never silently choose a new Workflow ID.

The `run_id` is globally unique (UUIDv7 or another collision-resistant opaque identifier). Tenant authorization is always derived from authenticated identity and persisted ownership, never from the identifier or caller-supplied tenant field.

## Attempt namespaces

- `run_attempt_id`: Runtime-owned durable attempt record. It changes only when Runtime deliberately creates a new business execution attempt under the Run policy.
- Temporal Workflow/Activity attempt counters: Temporal-native execution metadata. Do not serialize these as the platform `attempt_id`.
- `executor_attempt_id`: identifies a concrete EngageGuard trusted-executor attempt and appears in the Receipt.
- Provider mutation retries are represented by the same `compute_operation_id` plus provider observation/version; they do not create a new logical Allocation.

## Action operation and hash chain

1. Decision returns an untrusted `ActionProposal` with a stable `proposal_id`; it does not choose an authorization result, Permit, `operation_id`, or `action_hash`.
2. Runtime persists the accepted proposal and assigns one `action_operation_id` before the first EngageGuard submission.
3. Runtime sends the same `action_operation_id` and semantically identical proposal on every retry.
4. EngageGuard derives subject/tenant/workload identity from authenticated context, resolves trusted capability binding, validates and normalizes the action, then computes `action_hash`.
5. Hash preimage uses RFC 8785 JSON Canonicalization Scheme (JCS), UTF-8, a versioned domain separator, and SHA-256. The digest is 64 lowercase hexadecimal characters. Go `json.Marshal` output alone is not the cross-language canonicalization contract.
6. EngageGuard binds AuthorizationDecision, Approval, one-time Permit, Operation Journal and Receipt to the same `action_operation_id` and `action_hash`.
7. Reuse of one `action_operation_id` with a different canonical action/hash is a conflict and must fail closed.
8. Runtime records the verified Receipt; it never treats a plugin proposal or HTTP acknowledgement as proof of execution.

## Compute operation namespace

A protected Agent request to create compute capacity is authorized by EngageGuard at the action boundary. The Compute Control Plane then owns its own `compute_operation_id`, Workload, Allocation and provider reconciliation. The action operation and compute operation are linked by references/correlation, never by sharing one identifier or one state machine.

The Compute Control Plane is the enforcement point for its provider operations. EngageGuard authorizes an Agent-originated request; it does not become a second writer for Kubernetes/Kueue/provider state. Internal controller maintenance operations use Compute service identity and Compute's own authorization policy.

## Required database constraints

At minimum, the owning service enforces:

- Runtime: UNIQUE(`run_intent_id`), UNIQUE(`run_id`), UNIQUE(`workflow_id`).
- Decision: UNIQUE(`invocation_id`); persist request digest and exact result for replay.
- EngageGuard: UNIQUE(`action_operation_id`); immutable canonical action digest once claimed.
- Compute: UNIQUE(`compute_operation_id`); generation/version fencing for provider mutations.
- Evidence: immutable content digest plus producer identity and schema version.

These are local constraints in the owning service database; no cross-service database transaction is implied.
