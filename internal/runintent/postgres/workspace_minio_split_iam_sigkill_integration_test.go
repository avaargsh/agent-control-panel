package postgres

import (
	"os"
	"testing"
)

// TestWorkspaceRealMinIOSplitIAMProcessSIGKILLRecovery uses the existing four
// real SIGKILL phases with independently persisted PG16/MinIO, but requires
// strict non-root service identities for each child OS process. The crash
// child may have scoped PUT+GET, the post-PUT recovery and read-only reopen
// children must not inherit the writer identity, and before-PUT recovery may
// explicitly create a new trusted writer attempt. All bytes remain verified
// by a separate reader identity.
func TestWorkspaceRealMinIOSplitIAMProcessSIGKILLRecovery(t *testing.T) {
	if os.Getenv("S3BLOB_MINIO_TEST_ENDPOINT") == "" || os.Getenv("PGTEST_DSN") == "" {
		t.Skip("requires real MinIO IAM principals and PostgreSQL 16")
	}
	for _, role := range []string{"WRITER", "READER"} {
		if os.Getenv("S3BLOB_IAM_"+role+"_ACCESS_KEY") == "" ||
			os.Getenv("S3BLOB_IAM_"+role+"_SECRET_KEY") == "" {
			t.Fatalf("missing separate %s service credentials", role)
		}
	}
	if os.Getenv("S3BLOB_MINIO_TEST_ACCESS_KEY") != "" ||
		os.Getenv("S3BLOB_MINIO_TEST_SECRET_KEY") != "" ||
		os.Getenv("MINIO_ROOT_USER") != "" ||
		os.Getenv("MINIO_ROOT_PASSWORD") != "" {
		t.Fatal("split identity process test must never inherit MinIO fixture bootstrap credentials")
	}
	t.Setenv("ACP_MINIO_PROCESS_MODE", "split")
	TestWorkspaceRealMinIOProcessSIGKILLRecovery(t)
	t.Log("real MinIO + PG16 four SIGKILL phases passed using separate writer/reader service identities and credential-redacted read-only recovery workers")
}
