module github.com/avaargsh/agent-control-panel/experiments/jetstream-poc

go 1.27.0

require (
	github.com/avaargsh/agent-control-panel v0.0.0
	github.com/jackc/pgx/v5 v5.12.0
	github.com/nats-io/nats.go v1.54.0
)

replace github.com/avaargsh/agent-control-panel => ../..
