package runintent

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func fixture() Intent {
	return Intent{
		ID: "intent-1", TenantID: "tenant-1", PrincipalID: "svc-runtime",
		ProjectID: "project-1", AgentID: "agent-1", ReleaseID: "release-1",
		SessionID: "session-1", IdempotencyKey: "client-key-1",
		RequestDigest: "sha256:" + strings.Repeat("a", 64),
		PrincipalSnapshot: PrincipalSnapshot{
			Version: PrincipalSnapshotVersion, ProjectID: "project-1",
			SubjectID: "subject-1", ActorID: "actor-1",
			PolicyRevision: "policy-1", ConfigDigest: "sha256:" + strings.Repeat("b", 64),
		},
		Version: 1, Status: Pending,
	}
}

func TestDispatchAcceptanceUsesRuntimeOwnedRunIdentity(t *testing.T) {
func TestDispatchFailsClosedWithoutPersistedPrincipalSnapshot(t *testing.T) {
	intent := fixture()
	intent.PrincipalSnapshot = PrincipalSnapshot{}
	_, err := intent.ClaimDispatch(1, "dispatcher-1", time.Unix(100, 0).UTC(), time.Minute)
	if !errors.Is(err, ErrPrincipalSnapshotUnavailable) {
		t.Fatalf("legacy/unverified RunIntent was dispatchable: %v", err)
	}
}

func TestPrincipalSnapshotMustBeCompleteAndProjectBound(t *testing.T) {
	valid := fixture().PrincipalSnapshot
	cases := []struct {
		name string
		snapshot PrincipalSnapshot
	}{
		{name: "wrong version", snapshot: PrincipalSnapshot{Version: "acp-principal/v2", ProjectID: "project-1", SubjectID: "subject-1", ActorID: "actor-1", PolicyRevision: "policy-1", ConfigDigest: valid.ConfigDigest}},
		{name: "wrong project", snapshot: PrincipalSnapshot{Version: PrincipalSnapshotVersion, ProjectID: "project-2", SubjectID: "subject-1", ActorID: "actor-1", PolicyRevision: "policy-1", ConfigDigest: valid.ConfigDigest}},
		{name: "missing subject", snapshot: PrincipalSnapshot{Version: PrincipalSnapshotVersion, ProjectID: "project-1", ActorID: "actor-1", PolicyRevision: "policy-1", ConfigDigest: valid.ConfigDigest}},
		{name: "missing effective actor", snapshot: PrincipalSnapshot{Version: PrincipalSnapshotVersion, ProjectID: "project-1", SubjectID: "subject-1", PolicyRevision: "policy-1", ConfigDigest: valid.ConfigDigest}},
		{name: "missing policy revision", snapshot: PrincipalSnapshot{Version: PrincipalSnapshotVersion, ProjectID: "project-1", SubjectID: "subject-1", ActorID: "actor-1", ConfigDigest: valid.ConfigDigest}},
		{name: "invalid config digest", snapshot: PrincipalSnapshot{Version: PrincipalSnapshotVersion, ProjectID: "project-1", SubjectID: "subject-1", ActorID: "actor-1", PolicyRevision: "policy-1", ConfigDigest: "sha256:bad"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			intent := fixture()
			intent.PrincipalSnapshot = tc.snapshot
			if err := intent.Validate(); !errors.Is(err, ErrPrincipalSnapshotInvalid) {
				t.Fatalf("invalid principal snapshot accepted: %v", err)
			}
		})
	}
}


	now := time.Unix(100, 0).UTC()
	intent, err := fixture().ClaimDispatch(1, "dispatcher-1", now, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if intent.Status != Dispatching || intent.FenceToken != 1 || intent.Version != 2 {
		t.Fatalf("unexpected claim: %+v", intent)
	}

	accepted, err := intent.RecordDispatchOutcome(2, "dispatcher-1", 1, now.Add(time.Second), DispatchOutcome{
		TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest, Kind: DispatchAccepted,
		RunID: "runtime-run-1", WorkflowID: "agent-run/v1/runtime-run-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Status != Accepted || accepted.RunID != "runtime-run-1" ||
		accepted.WorkflowID != "agent-run/v1/runtime-run-1" || accepted.Version != 3 {
		t.Fatalf("runtime receipt not projected: %+v", accepted)
	}
	if accepted.LeaseOwner != "" || !accepted.LeaseExpiresAt.IsZero() {
		t.Fatalf("lease not cleared: %+v", accepted)
	}
}

func TestUnknownMustReconcileBeforeSameKeyRetry(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	intent, _ := fixture().ClaimDispatch(1, "dispatcher-1", now, time.Minute)
	intent, err := intent.RecordDispatchOutcome(2, "dispatcher-1", 1, now.Add(time.Second), DispatchOutcome{
		TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest, Kind: DispatchAmbiguous,
	})
	if err != nil || intent.Status != Unknown {
		t.Fatalf("ambiguous ACK: %+v %v", intent, err)
	}
	if _, err := intent.ClaimDispatch(3, "dispatcher-2", now.Add(2*time.Second), time.Minute); !errors.Is(err, ErrTransition) {
		t.Fatalf("UNKNOWN was blindly dispatched: %v", err)
	}

	intent, err = intent.BeginReconciliation(3, "reconciler-1", now.Add(2*time.Second), time.Minute)
	if err != nil || intent.Status != Reconciling {
		t.Fatalf("begin reconcile: %+v %v", intent, err)
	}
	intent, err = intent.ApplyReconciliationResult(4, "reconciler-1", intent.FenceToken, now.Add(3*time.Second), ReconciliationResult{
		TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest, Kind: RuntimeNotFoundFinal,
	})
	if err != nil || intent.Status != Pending {
		t.Fatalf("authoritative not-found: %+v %v", intent, err)
	}
	if intent.IdempotencyKey != "client-key-1" || intent.RequestDigest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatal("retry changed idempotency identity")
	}
	intent, err = intent.ClaimDispatch(intent.Version, "dispatcher-2", now.Add(4*time.Second), time.Minute)
	if err != nil || intent.Status != Dispatching {
		t.Fatalf("same-key retry: %+v %v", intent, err)
	}
}

func TestFoundReconciliationAndConflictingReceipt(t *testing.T) {
	now := time.Unix(300, 0).UTC()
	intent, _ := fixture().ClaimDispatch(1, "dispatcher-1", now, time.Minute)
	intent, _ = intent.RecordDispatchOutcome(2, "dispatcher-1", 1, now.Add(time.Second), DispatchOutcome{
		TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest, Kind: DispatchAmbiguous,
	})
	intent, _ = intent.BeginReconciliation(3, "reconciler-1", now.Add(2*time.Second), time.Minute)
	found, err := intent.ApplyReconciliationResult(4, "reconciler-1", intent.FenceToken, now.Add(3*time.Second), ReconciliationResult{
		TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest, Kind: RuntimeFound,
		RunID: "runtime-run-2", WorkflowID: "agent-run/v1/runtime-run-2",
	})
	if err != nil || found.Status != Accepted {
		t.Fatalf("found result: %+v %v", found, err)
	}

	intent, _ = fixture().ClaimDispatch(1, "dispatcher-1", now, time.Minute)
	mismatch, err := intent.RecordDispatchOutcome(2, "dispatcher-1", 1, now.Add(time.Second), DispatchOutcome{
		TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: "sha256:" + strings.Repeat("b", 64),
		Kind: DispatchAccepted, RunID: "foreign-run", WorkflowID: "agent-run/v1/foreign-run",
	})
	if err != nil || mismatch.Status != ManualReview || mismatch.ManualReviewCode != "RUNTIME_RECEIPT_MISMATCH" {
		t.Fatalf("mismatched receipt not quarantined: %+v %v", mismatch, err)
	}
}

func TestLeaseExpiryFencesStaleWorker(t *testing.T) {
	now := time.Unix(400, 0).UTC()
	intent, _ := fixture().ClaimDispatch(1, "dispatcher-1", now, time.Second)
	if _, err := intent.RecordDispatchOutcome(2, "dispatcher-1", 1, now.Add(2*time.Second), DispatchOutcome{
		TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest, Kind: DispatchAccepted,
		RunID: "late-run", WorkflowID: "agent-run/v1/late-run",
	}); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired worker committed: %v", err)
	}
	expired, err := intent.ExpireLease(2, now.Add(2*time.Second))
	if err != nil || expired.Status != Unknown {
		t.Fatalf("lease expiry: %+v %v", expired, err)
	}
	if _, err := expired.RecordDispatchOutcome(2, "dispatcher-1", 1, now.Add(3*time.Second), DispatchOutcome{
		TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest, Kind: DispatchAccepted,
		RunID: "late-run", WorkflowID: "agent-run/v1/late-run",
	}); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("stale version accepted: %v", err)
	}
}

func TestAcceptedValidationRequiresCanonicalRuntimeIdentity(t *testing.T) {
	intent := fixture()
	intent.Status = Accepted
	intent.RunID = "run-1"
	intent.WorkflowID = "agent-run/v1/different-run"
	if !errors.Is(intent.Validate(), ErrInvalid) {
		t.Fatalf("mismatched Runtime identity accepted: %+v", intent)
	}
}

func TestLeaseExpiryAdvancesFenceAndRejectsExpiredToken(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	intent, err := fixture().ClaimDispatch(1, "dispatcher-1", now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := intent.ExpireLease(intent.Version, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if expired.FenceToken != intent.FenceToken+1 {
		t.Fatalf("fencing token did not advance on lease expiry: before=%d after=%d", intent.FenceToken, expired.FenceToken)
	}

	next, err := expired.BeginReconciliation(expired.Version, "reconciler-2", now.Add(3*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if next.FenceToken <= intent.FenceToken {
		t.Fatalf("new lease did not receive a newer fencing token: old=%d new=%d", intent.FenceToken, next.FenceToken)
	}
	_, err = next.ApplyReconciliationResult(next.Version, "reconciler-2", intent.FenceToken, now.Add(4*time.Second), ReconciliationResult{
		TenantID: next.TenantID, RunIntentID: next.ID, RequestDigest: next.RequestDigest, Kind: RuntimeIndeterminate,
	})
	if !errors.Is(err, ErrStaleLease) {
		t.Fatalf("expired lease token was accepted by newer lease: %v", err)
	}
}

func TestOpaqueIdentifiersRejectControlWhitespace(t *testing.T) {
	for _, value := range []string{"tenant\tbad", "tenant\rbad", "tenant\nbad", "tenant\x00bad"} {
		if validOpaqueID(value) {
			t.Errorf("control whitespace accepted in opaque ID %q", value)
		}
	}
}

func TestValidationRejectsRuntimeOwnedStateAndPrematureRunID(t *testing.T) {
	intent := fixture()
	intent.TenantID = ""
	if !errors.Is(intent.Validate(), ErrInvalid) {
		t.Fatal("missing tenant accepted")
	}
	intent = fixture()
	intent.Status = Status("RUNNING")
	if !errors.Is(intent.Validate(), ErrInvalid) {
		t.Fatal("Runtime Run state accepted")
	}
	intent = fixture()
	intent.RunID = "run-1"
	if !errors.Is(intent.Validate(), ErrInvalid) {
		t.Fatal("Control Plane accepted a Run ID before Runtime receipt")
	}
}

func TestDefinitiveRuntimeRejection(t *testing.T) {
	now := time.Unix(500, 0).UTC()
	intent, _ := fixture().ClaimDispatch(1, "dispatcher-1", now, time.Minute)
	rejected, err := intent.RecordDispatchOutcome(2, "dispatcher-1", 1, now.Add(time.Second), DispatchOutcome{
		TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest, Kind: DispatchRejected,
		RejectionCode: "RELEASE_NOT_READY",
	})
	if err != nil || rejected.Status != Rejected || rejected.RejectionCode != "RELEASE_NOT_READY" {
		t.Fatalf("rejection: %+v %v", rejected, err)
	}
}

func TestRuntimeReceiptRequiresCanonicalWorkflowIDAndTenant(t *testing.T) {
	now := time.Unix(600, 0).UTC()
	for _, tc := range []struct {
		name       string
		tenant     string
		workflowID string
	}{
		{name: "wrong workflow mapping", tenant: "tenant-1", workflowID: "run/run-1"},
		{name: "wrong tenant", tenant: "tenant-2", workflowID: "agent-run/v1/run-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent, err := fixture().ClaimDispatch(1, "dispatcher-1", now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			got, err := intent.RecordDispatchOutcome(2, "dispatcher-1", 1, now.Add(time.Second), DispatchOutcome{
				TenantID: tc.tenant, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest,
				Kind: DispatchAccepted, RunID: "run-1", WorkflowID: tc.workflowID,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != ManualReview {
				t.Fatalf("mismatched Runtime identity was accepted: %+v", got)
			}
		})
	}
}
