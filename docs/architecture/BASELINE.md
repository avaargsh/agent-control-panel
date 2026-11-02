# Superseded Architecture Baseline

This document is retained only as historical context.

The authoritative architecture baseline is now:
- [PLATFORM-BASELINE.md](PLATFORM-BASELINE.md)
- [DOMAIN-OWNERSHIP.md](DOMAIN-OWNERSHIP.md)
- [CROSS-SERVICE-CONTRACTS.md](CROSS-SERVICE-CONTRACTS.md)
- [ADR-003: Identity, idempotency and retry ownership](ADR-003-IDENTITY-AND-RETRY-OWNERSHIP.md)
- [ADR-004: Compute and Sandbox boundary](ADR-004-COMPUTE-AND-SANDBOX-BOUNDARY.md)

Do not use this historical proposal to implement APIs or state machines. The Control Plane owns RunIntent; Agent Runtime owns Run/Task/Attempt execution lifecycle. Runtime-generated Run and Workflow identifiers are only projected here.
