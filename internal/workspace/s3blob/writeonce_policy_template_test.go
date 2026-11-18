package s3blob

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These are ONLY static regression checks for a disposable AWS bucket-policy
// TEMPLATE. They never establish that a provider actually installed or
// enforces the policy. The real provider must additionally deny a properly
// signed raw unconditional PUT to an existing AND a never-created digest key.
const approvedS3DenyResource = "arn:aws:s3:::acp-writeonce-probe-REPLACE/v1/tenant/tenant-security-probe/workspace/workspace-writeonce-probe/sha256/*"

func checkAWSWriteOnceDenyTemplate(data []byte) error {
	var policy struct {
		Version   string
		Statement []struct {
			Sid       string
			Effect    string
			Principal string
			Action    string
			Resource  string
			Condition map[string]map[string]string
		}
	}
	if err := json.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("parse conditional-write policy: %w", err)
	}
	if policy.Version != "2012-10-17" || len(policy.Statement) != 1 {
		return errors.New("unexpected policy version or statement count")
	}
	statement := policy.Statement[0]
	if statement.Sid != "DenyObjectCreationWithoutIfNoneMatchInDisposableWorkspacePrefix" ||
		statement.Effect != "Deny" || statement.Principal != "*" ||
		statement.Action != "s3:PutObject" || statement.Resource != approvedS3DenyResource {
		return errors.New("conditional-write deny scope, principal, action or effect was widened")
	}
	if len(statement.Condition) != 1 || len(statement.Condition["Null"]) != 1 ||
		statement.Condition["Null"]["s3:if-none-match"] != "true" {
		return errors.New("server-side missing-if-none-match deny was relaxed")
	}
	return nil
}

func TestAWSWriteOncePolicyTemplateRejectsMissingCondition(t *testing.T) {
	file := filepath.Join("..", "..", "..", ".github", "fixtures", "aws-s3",
		"writeonce-bucket-policy.template.json")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkAWSWriteOnceDenyTemplate(data); err != nil {
		t.Fatalf("AWS conditional-write DENY template drifted: %v", err)
	}
	for _, tc := range []struct {
		name, before, after string
	}{
		{"allow-instead-of-deny", `"Effect": "Deny"`, `"Effect": "Allow"`},
		{"wildcard-principal-dropped", `"Principal": "*"`, `"Principal": "limited"`},
		{"broad-action", `"Action": "s3:PutObject"`, `"Action": "s3:*"`},
		{"wrong-condition-key", `"s3:if-none-match": "true"`, `"s3:if-match": "true"`},
		{"missing-header-allowed", `"s3:if-none-match": "true"`, `"s3:if-none-match": "false"`},
		{"widened-tenant-scope", `tenant-security-probe/workspace/workspace-writeonce-probe/sha256/*`, `tenant-*/workspace/*`},
		{"different-template-bucket", `acp-writeonce-probe-REPLACE`, `unreviewed-s3-bucket`},
		{"wrong-sid", `DenyObjectCreationWithoutIfNoneMatchInDisposableWorkspacePrefix`, `OtherStatement`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.Replace(string(data), tc.before, tc.after, 1)
			if mutated == string(data) {
				t.Fatalf("fixture mutation did not apply for %s", tc.name)
			}
			if err := checkAWSWriteOnceDenyTemplate([]byte(mutated)); err == nil {
				t.Fatalf("weakened template was accepted for %s", tc.name)
			}
		})
	}
	t.Log("AWS policy template denies missing If-None-Match for exact canary prefix; real provider enforcement NOT YET PROVEN")
}
