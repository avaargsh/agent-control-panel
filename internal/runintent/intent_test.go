package runintent

import (
    "errors"
    "testing"
)
func fixture() Intent {
    return Intent{ID:"run-intent-1",TenantID:"tenant-1",SessionID:"session-1",
      ReleaseID:"release-1",WorkflowID:"run/run-intent-1",Version:1,Status:Pending}
}
func TestTransitionsAndUnknownRecovery(t *testing.T) {
    i:=fixture()
    if _,err:=i.Advance(0,Dispatching,false); !errors.Is(err,ErrStaleVersion) {t.Fatalf("stale: %v",err)}
    if _,err:=i.Advance(1,Dispatched,true); !errors.Is(err,ErrTransition) {t.Fatalf("skipped dispatch: %v",err)}
    i,_=i.Advance(1,Dispatching,false)
    i,_=i.Advance(2,Unknown,false)
    if _,err:=i.Advance(3,Dispatching,false); !errors.Is(err,ErrTransition) {t.Fatalf("blind retry: %v",err)}
    if _,err:=i.Advance(3,Dispatched,false); !errors.Is(err,ErrTransition) {t.Fatalf("unverified: %v",err)}
    var err error
    i,err=i.Advance(3,Dispatched,true)
    if err!=nil||i.Version!=4 {t.Fatalf("verified dispatch: %+v %v",i,err)}
    i,err=i.Advance(4,CancelRequested,false)
    if err!=nil {t.Fatal(err)}
    if _,err=i.Advance(5,Pending,false); !errors.Is(err,ErrTransition) {t.Fatalf("reopened: %v",err)}
}
func TestIdentityRequired(t *testing.T) {
    i:=fixture()
    i.TenantID=""
    if !errors.Is(i.Validate(),ErrInvalid) {t.Fatal("missing tenant accepted")}
    i=fixture()
    i.Status="RUNNING"
    if !errors.Is(i.Validate(),ErrInvalid) {t.Fatal("runtime state accepted")}
}
