module github.com/avaargsh/agent-control-panel/integration/agentdsourcee2e

go 1.27.0

// Integration-only module. Root ACP and Sandbox have separate ownership;
// the CI's temporary Go workspace binds both exact checked-out SHAs. This
// module MUST NOT add replacements to root go.mod or migrate source code.
require (
	github.com/avaargsh/agent-control-panel v0.0.0
	github.com/avaargsh/agent-control-panel/services/sandbox-journal v0.0.0
	github.com/jackc/pgx/v5 v5.12.0
)
