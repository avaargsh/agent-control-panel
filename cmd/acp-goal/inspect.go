package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

const PublicGoalInspectionVersion = "acp.public-goal-inspection/v1"

type baselineReader interface {
	InspectBaselines(context.Context, string, string, string, string) (issuegoal.PublicBaselineInspection, error)
}

// inspect reports only a current PUBLIC source observation. It is never an
// authenticated GoalSubmit, an authority claim or evidence of execution.
func inspect(args []string, stdin io.Reader, stdout, stderr io.Writer, reader issueReader, baselines baselineReader) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("file", "", "Issue Goal manifest path; - reads stdin")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *path == "" || flags.NArg() != 0 || reader == nil || baselines == nil {
		return errors.New("inspect requires exactly one --file path and a configured public source reader")
	}
	var source io.Reader = stdin
	if *path != "-" {
		file, err := os.Open(*path)
		if err != nil {
			return err
		}
		defer file.Close()
		source = file
	}
	raw, err := io.ReadAll(io.LimitReader(source, 32*1024+1))
	if err != nil {
		return err
	}
	prepared, err := issuegoal.Prepare(raw)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(prepared)
	if err != nil {
		return err
	}
	_, input, _, err := issuegoal.DecodePrepared(wire)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	snapshot, err := reader.Read(ctx, input.IssueURL)
	if err != nil {
		return err
	}
	if snapshot.Schema != issuegoal.IssueSnapshotVersion || snapshot.IssueURL != input.IssueURL ||
		snapshot.Digest != input.IssueSnapshotDigest {
		return issuegoal.ErrIssueSnapshotMismatch
	}
	observation, err := baselines.InspectBaselines(ctx, input.IssueURL, input.TargetBranch,
		input.ExperimentBaselineSHA, input.IntegrationBaselineSHA)
	if err != nil {
		return err
	}
	if observation.Schema != issuegoal.PublicBaselineInspectionVersion || observation.IssueURL != input.IssueURL ||
		observation.TargetBranch != input.TargetBranch || observation.ExperimentBaselineSHA != input.ExperimentBaselineSHA ||
		observation.IntegrationBaselineSHA != input.IntegrationBaselineSHA ||
		observation.ObservedBranchHeadSHA != input.IntegrationBaselineSHA {
		return issuegoal.ErrBaselineMismatch
	}
	return json.NewEncoder(stdout).Encode(struct {
		Schema                 string `json:"schema"`
		Status                 string `json:"status"`
		IssueURL               string `json:"issue_url"`
		IssueSnapshotDigest    string `json:"issue_snapshot_digest"`
		ExperimentBaselineSHA  string `json:"experiment_baseline_sha"`
		IntegrationBaselineSHA string `json:"integration_baseline_sha"`
		ObservedBranchHeadSHA  string `json:"observed_branch_head_sha"`
		BranchProtected        bool   `json:"branch_protected"`
		RequestDigest          string `json:"request_digest"`
	}{
		Schema: PublicGoalInspectionVersion, Status: "public-source-observed-only",
		IssueURL: input.IssueURL, IssueSnapshotDigest: input.IssueSnapshotDigest,
		ExperimentBaselineSHA:  observation.ExperimentBaselineSHA,
		IntegrationBaselineSHA: observation.IntegrationBaselineSHA,
		ObservedBranchHeadSHA:  observation.ObservedBranchHeadSHA,
		BranchProtected:        observation.BranchProtected,
		RequestDigest:          prepared.RequestDigest,
	})
}
