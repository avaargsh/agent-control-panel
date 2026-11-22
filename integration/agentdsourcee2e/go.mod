module github.com/avaargsh/agent-control-panel/integration/agentdsourcee2e

go 1.27.0

// These replacements are scoped to the ISOLATED INTEGRATION TEST module.
// The source checkout must first be pinned by the exact-SHA CI workflow.
// The ACP root and independent Sandbox source go.mod remain unchanged.
require (
	github.com/avaargsh/agent-control-panel v0.0.0
	github.com/avaargsh/agent-control-panel/services/sandbox-journal v0.0.0
	github.com/jackc/pgx/v5 v5.12.0
)

replace github.com/avaargsh/agent-control-panel => ../..
replace github.com/avaargsh/agent-control-panel/services/sandbox-journal => ../../source-pinned/services/sandbox-journal
