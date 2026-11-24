package authoritycutover

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestOrderedCutover(t *testing.T) {
	change := Change{ID: "change-a", ManifestDigest: "sha256:" + strings.Repeat("a", 64), Operator: "operator-a"}
	current := Record{Generation: 1, Revision: 1, Phase: Open}
	for _, step := range []struct {
		action     Action
		phase      Phase
		generation int64
	}{
		{Begin, Draining, 1}, {MarkDrained, Closed, 1}, {ObserveApplied, Verifying, 2}, {Reopen, Open, 2},
	} {
		next, err := Advance(current, current, step.action, change)
		if err != nil || next.Phase != step.phase || next.Generation != step.generation || next.Revision != current.Revision+1 || next.Change != change {
			t.Fatalf("transition %s: got %+v, err=%v", step.action, next, err)
		}
		current = next
	}
}

func TestRejectUnsafeCutoverTransitions(t *testing.T) {
	change := Change{ID: "change-a", ManifestDigest: "sha256:" + strings.Repeat("a", 64), Operator: "operator-a"}
	foreign := change
	foreign.ManifestDigest = "sha256:" + strings.Repeat("b", 64)
	open := Record{Generation: 1, Revision: 1, Phase: Open}
	draining := Record{Generation: 1, Revision: 2, Phase: Draining, Change: change}
	closed := Record{Generation: 1, Revision: 3, Phase: Closed, Change: change}
	verifying := Record{Generation: 2, Revision: 4, Phase: Verifying, Change: change}
	for _, tc := range []struct {
		name              string
		current, expected Record
		action            Action
		change            Change
		want              error
	}{
		{"stale CAS", draining, open, Begin, change, ErrConflict},
		{"skip drain", draining, draining, ObserveApplied, change, ErrInvalid},
		{"reopen before observation", closed, closed, Reopen, change, ErrInvalid},
		{"wrong manifest", verifying, verifying, Reopen, foreign, ErrConflict},
		{"unknown phase", Record{}, Record{}, Begin, change, ErrInvalid},
		{"missing identity", open, open, Begin, Change{}, ErrInvalid},
		{"generation overflow", Record{Generation: math.MaxInt64, Revision: 3, Phase: Closed, Change: change}, Record{Generation: math.MaxInt64, Revision: 3, Phase: Closed, Change: change}, ObserveApplied, change, ErrInvalid},
		{"revision overflow", Record{Generation: 1, Revision: math.MaxInt64, Phase: Closed, Change: change}, Record{Generation: 1, Revision: math.MaxInt64, Phase: Closed, Change: change}, ObserveApplied, change, ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Advance(tc.current, tc.expected, tc.action, tc.change)
			if !errors.Is(err, tc.want) || got != tc.current {
				t.Fatalf("unsafe transition: got %+v err=%v want %v", got, err, tc.want)
			}
		})
	}
}
