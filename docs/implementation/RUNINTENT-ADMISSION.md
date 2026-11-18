# RunIntent admission boundary (development only)

Tracks [ACP #10](https://github.com/avaargsh/agent-control-panel/issues/10) and [Runtime #20](https://github.com/avaargsh/agent-runtime/issues/20).

## Implemented internal contract

`internal/admission.Service.Admit(ctx, request)` accepts only resource selectors (Tenant/Project/Agent/Release/Session), an idempotency key and a proposed request digest. It has no caller-controlled principal, policy, configuration snapshot or Runtime identity fields. The host must inject a trusted Resolver and PostgreSQL repository. No default resolver or HTTP endpoint is provided.

1. Validate request shape before consulting the resolver.
2. Resolve the authenticated principal, effective subject/actor, policy revision, canonical request digest and immutable configuration from trusted sources. Resolver errors deny admission. An assertion with a different target or digest is rejected.
3. Validate the nonzero principal snapshot and immutable identity. Generate only ACP-owned UUIDs (RunIntent and Outbox event), not Run/Workflow IDs.
4. Use the existing Repository.Create transaction to commit the PENDING RunIntent, snapshot and creation event together.
5. Re-resolve authorization on every replay. A denied replay writes nothing; a changed immutable snapshot with the same tenant/principal/idempotency key is an idempotency conflict. The repository returns the original identity on an exact replay.

The Outbox payload contains only the RunIntent ID, not raw prompts, credentials, or claims. The digest must be independently computed/verified by the trusted Resolver; merely echoing client input is not a valid implementation. A successful admission is neither Runtime acceptance nor protected-action authorization.

## Tests and evidence

The regression suite covers positive admission/event correlation, malformed selector rejection before resolution, each target mismatch, digest mismatch, missing/invalid principal snapshot, and denial without persistence. The real PostgreSQL test covers exact replay, policy revocation on replay, changed policy revision conflict and one durable intent/Outbox event.

Do not infer any passing test status from this document. Inspect the exact PR head's CI results, including the PGTEST_DSN-enabled suite.

## Remaining release gates

- Implement and independently review the actual authenticated principal/policy resolver with issuer/audience, credential lifetime, actor delegation, tenant/project, release and immutable request/config authority.
- Persist and retrieve the immutable execution input/reference according to the owner-ratified ACP/Runtime contract; this slice stores only the digest, not input bytes.
- Ratify the service-owned wire schema and implement the authenticated StartRun adapter plus joint PostgreSQL/Temporal lost-ACK and restart tests.
- No public mutating API, production dispatch, G01/G05 promotion, Guard Permit issuance, or provider release is enabled by this change.
