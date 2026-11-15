package postgres

import (
	"os"
	"strings"
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

func TestMinioChildCredentialEnvironmentIsLeastPrivileged(t *testing.T) {
	t.Setenv("ACP_MINIO_PROCESS_MODE", "split")
	t.Setenv("S3BLOB_MINIO_TEST_ACCESS_KEY", "fixture-root")
	t.Setenv("S3BLOB_MINIO_TEST_SECRET_KEY", "fixture-root-secret")
	t.Setenv("MINIO_ROOT_USER", "legacy-root")
	t.Setenv("MINIO_ROOT_PASSWORD", "legacy-root-password")
	t.Setenv("S3BLOB_IAM_OTHER_ACCESS_KEY", "foreign-tenant")
	t.Setenv("S3BLOB_IAM_OTHER_SECRET_KEY", "foreign-tenant-secret")
	t.Setenv("S3BLOB_IAM_DENIED_ACCESS_KEY", "blocked-user")
	t.Setenv("S3BLOB_IAM_DENIED_SECRET_KEY", "blocked-secret")
	t.Setenv("S3BLOB_IAM_WRITER_ACCESS_KEY", "iam-writer")
	t.Setenv("S3BLOB_IAM_WRITER_SECRET_KEY", "iam-writer-secret")
	t.Setenv("S3BLOB_IAM_READER_ACCESS_KEY", "iam-reader")
	t.Setenv("S3BLOB_IAM_READER_SECRET_KEY", "iam-reader-secret")
	t.Setenv("AWS_ACCESS_KEY_ID", "not-for-worker")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "not-for-worker-secret")
	for _, tc := range []struct {
		name, action, phase string
		writerAllowed bool
	}{
		{"crash-before-put", "crash", "before-put", true},
		{"crash-after-put", "crash", "after-put", true},
		{"explicit-retry-before-put", "recover", "before-put", true},
		{"read-only-reconcile-after-put", "recover", "after-put", false},
		{"read-only-reconcile-after-stage", "recover", "after-stage", false},
		{"read-only-reconcile-after-cas", "recover", "after-cas", false},
		{"reopen-all-phases", "reopen", "before-put", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := minioChildCredentialEnvironment(tc.action, tc.phase)
			values := make(map[string]string, len(env))
			for _, item := range env {
				name, value, ok := strings.Cut(item, "=")
				if !ok {
					t.Fatalf("invalid child env binding %q", item)
				}
				values[name] = value
			}
			if values["S3BLOB_IAM_READER_ACCESS_KEY"] != "iam-reader" ||
				values["S3BLOB_IAM_READER_SECRET_KEY"] != "iam-reader-secret" {
				t.Fatal("real recovery child omitted independent reader credential")
			}
			if (values["S3BLOB_IAM_WRITER_ACCESS_KEY"] != "") != tc.writerAllowed ||
				(values["S3BLOB_IAM_WRITER_SECRET_KEY"] != "") != tc.writerAllowed {
				t.Fatalf("child role drift: action=%s phase=%s writer=%t", tc.action, tc.phase, tc.writerAllowed)
			}
			for _, forbidden := range []string{
				"S3BLOB_MINIO_TEST_ACCESS_KEY", "S3BLOB_MINIO_TEST_SECRET_KEY",
				"MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD",
				"S3BLOB_IAM_OTHER_ACCESS_KEY", "S3BLOB_IAM_OTHER_SECRET_KEY",
				"S3BLOB_IAM_DENIED_ACCESS_KEY", "S3BLOB_IAM_DENIED_SECRET_KEY",
				"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
			} {
				if values[forbidden] != "" {
					t.Fatalf("child inherited unrelated/privileged %s", forbidden)
				}
			}
		})
	}
}
