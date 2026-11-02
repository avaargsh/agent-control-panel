# P0 Golden Path — Cross-Service Acceptance Contract

Status: **implementation gate**  
Target: Open Agent Infrastructure v0.1

## Outcome

A clean deployment accepts a versioned AgentBundle, creates an AgentRelease and stable Agent/Session/RunIntent identities, starts exactly one logical Runtime Run through Temporal, invokes a schema-conformant bounded Decision plugin, routes protected proposals through EngageGuard, and records verified evidence. Compute allocation is a separate service-owned flow with its own Workload, Allocation and provider operation identity.

## Ownership invariants

- Control Plane owns Agent/Bundle/Release/SessionIdentity/RunIntent and desired state. It does not own Run/Task/Attempt execution lifecycle.
- Runtime owns Run/Task/RunAttempt and the stable Workflow ID mapping.
- Temporal owns durable Workflow history, timers, replay and native Activity attempts.
- Decision owns invocation records, exact result replay and DecisionRecord.
- EngageGuard owns ActionHash, authorization, approval, Permit, Action Operation Journal and Receipt.
- Compute Control Plane owns Workload, Allocation, Compute Operation Journal and provider observations.
- Kubernetes/Kueue/provider own actual admission, scheduling and resource execution.

## Golden Path A — ordinary Run

1. Client submits AgentBundle; Control Plane validates schema and stores immutable digest.
2. Control Plane creates AgentRelease referencing the exact bundle digest.
3. Control Plane validates tenant/Agent/Session scope and authorization.
4. Control Plane accepts RunIntent with a client idempotency key and atomically persists the intent + outbox event.
5. Runtime consumes the RunIntent and atomically creates one `run_id` for that `run_intent_id`. A duplicate event or StartRun request returns the same Run.
6. Runtime derives `workflow_id = "agent-run/v1/" + run_id` and starts/inspects that exact Temporal Workflow ID.
7. Temporal Workflow invokes a bounded Decision Activity with the canonical v0.1 request schema and stable `invocation_id`.
8. Decision validates the request and returns exactly one canonical response variant. Same invocation ID and request digest replays the exact result.
9. Runtime validates the response, updates its Run projection and emits status/evidence references. Control Plane consumes a versioned event and updates only its RunIntent/read projection.

## Golden Path B — protected action

1. Decision returns an untrusted ActionProposal; it cannot execute tools or claim authorization.
2. Runtime persists the accepted proposal and assigns one stable `action_operation_id` before first submission.
3. Runtime submits the action to EngageGuard with authenticated workload identity.
4. EngageGuard resolves trusted subject/tenant/capability binding, canonicalizes the action using RFC 8785 JCS and calculates ActionHash.
5. Policy returns ALLOW, DENY or REQUIRE_APPROVAL. Approval never overrides DENY and is bound to the exact ActionHash.
6. EngageGuard issues a one-time, short-lived, audience- and operation-bound Permit only after all required checks pass.
7. Trusted enforcement point validates Permit, ActionHash, binding, expiry and one-time claim before the side effect.
8. EngageGuard records the Operation Journal and verified Receipt. Receipt includes the same ActionHash and `executor_attempt_id`.
9. Runtime records the Receipt and advances the Run only from verified operation evidence.

## Golden Path C — compute allocation

1. An Agent-originated compute request is authorized by EngageGuard at the action boundary; internal controller operations use Compute service identity and policy.
2. Compute Control Plane validates the caller/delegated authorization and creates a Workload plus distinct `compute_operation_id`.
3. Compute persists desired state, operation record and outbox atomically.
4. Reconciler creates the Kubernetes Job/Workload through the selected adapter.
5. Kueue owns admission/queue semantics; Kubernetes/provider owns actual scheduling and execution.
6. Compute records Allocation and provider observations with generation/version fencing.
7. Delete is not final on API ACK alone; exact-generation provider absence must be observed before Allocation release is terminal.
8. EngageGuard Action Operation and Compute Operation remain separate records linked by references.

## State and identity requirements

- Control Plane RunIntent status is dispatch coordination only: `PENDING → DISPATCHING → DISPATCHED | UNKNOWN | CANCEL_REQUESTED`.
- Runtime Run lifecycle is `PENDING → RUNNING ↔ WAITING → SUCCEEDED | FAILED | CANCELLED`, subject to validated transitions and evidence. A provider/action UNKNOWN is not silently converted into Run FAILED.
- Runtime creates `run_id` once per `run_intent_id`; Runtime derives one stable Workflow ID. No service generates a second Workflow ID for the same Run.
- Runtime, Temporal, executor and provider attempts are separate namespaces.
- `action_operation_id` and `compute_operation_id` are distinct. Each is stable across retries and unique in its owning service.
- No cross-service direct database writes or shared writable schemas.

## Failure and recovery acceptance

- Duplicate client submission with same idempotency key/payload returns the same RunIntent.
- Same key with a different payload returns 409.
- Duplicate RunIntent delivery maps to the same Run and Workflow ID.
- Lost Workflow start ACK becomes UNKNOWN; Runtime inspects the exact Workflow ID before any new start decision.
- Same Decision invocation ID + same request digest replays the exact result; changed digest conflicts.
- Duplicate Action submission with same operation ID returns existing status/Receipt; changed canonical action conflicts.
- Lost action ACK remains UNKNOWN until EngageGuard reconciles the exact operation; Runtime does not replay the side effect.
- Duplicate/out-of-order events do not reapply projections; aggregate-version gaps are durably deferred and recovered.
- Stale provider generation cannot overwrite current state.
- Compute delete is not complete until exact-generation absence is observed.
- Restart API, Runtime worker, Decision plugin and reconciler during critical windows; persisted state resumes without duplicate logical Run or blind external replay.
- Tenant isolation, revoked workload identity, secret hygiene, Permit replay, concurrent claim and path/symlink attacks are tested.

## Out of scope for P0

- UI feature completeness and multi-region federation.
- Custom Agent framework, workflow engine, sandbox runtime, IAM, policy language or GPU scheduler.
- Broad legacy code port without ownership map and regression evidence.
- Production-readiness claims without real PostgreSQL, Temporal and Kubernetes/Kueue integration evidence.

## Exit gate

P0 passes only when all three Golden Paths and the failure/recovery matrix pass in a clean environment with fresh CI and integration evidence. Unit tests, documentation or a happy-path demo alone are insufficient.
