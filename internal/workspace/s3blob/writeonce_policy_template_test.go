package s3blob

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This checks a TEMPLATE's fail-closed shape only. It is NOT evidence that
// MinIO accepts the policy key or that AWS has applied the bucket policy.
// Actual provider enforcement is tested separately via an unconditioned
// SigV4 PUT in TestApprovedS3WriteOnceSecurityGate.
func TestAWSWriteOncePolicyTemplateRejectsMissingCondition(t *testing.T) {
	file := filepath.Join("..", "..", "..", ".github", "fixtures", "aws-s3",
		"writeonce-bucket-policy.template.json")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Version string
		Statement []struct {
			Sid string
			Effect string
			Principal string
			Action string
			Resource string
			Condition map[string]map[string]string
		}
	}
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatalf("invalid AWS bucket-policy template: %v", err)
	}
	if policy.Version != "2012-10-17" || len(policy.Statement) != 1 {
		t.Fatal("template must contain exactly one explicit condition-based DENY statement")
	}
	s := policy.Statement[0]
	if s.Effect != "Deny" || s.Principal != "*" || s.Action != "s3:PutObject" ||
		s.Condition["Null"]["s3:if-none-match"] != "true" ||
		!strings.Contains(s.Resource, "acp-writeonce-probe-REPLACE/v1/tenant/tenant-security-probe/workspace/workspace-writeonce-probe/sha256/*") {
		t.Fatalf("template unexpectedly broadens or loses provider-side conditional-put denial: %+v", s)
	}
	for key, values := range s.Condition {
		if key != "Null" || len(values) != 1 {
			t.Fatalf("unexpected IAM condition %q: %+v", key, values)
		}
	}
	t.Log("AWS policy template DENY-on-missing-if-none-match is structurally pinned; provider execution remains unverified")
}
