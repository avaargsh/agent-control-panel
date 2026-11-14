package migrations

import "embed"

// FS contains the versioned SQL migrations shipped with the service.
//
//go:embed 0001_run_intents_outbox_inbox.sql 0002_inbox_conflict_evidence.sql 0003_inbox_dlq_dispositions.sql 0004_run_intent_principal_snapshot.sql 0005_run_capability_locks.sql
var FS embed.FS
