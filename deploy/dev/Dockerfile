FROM golang:1.27.4-bookworm AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
RUN go build -trimpath -buildvcs=false -o /bin/acp-operations ./cmd/agent-control-panel && \
    go build -trimpath -buildvcs=false -o /bin/acp-devctl ./cmd/acp-devctl

FROM scratch AS migrate
COPY --from=build /bin/acp-devctl /acp-devctl
USER 65532:65532
ENTRYPOINT ["/acp-devctl", "migrate"]

FROM scratch AS ops
COPY --from=build /bin/acp-operations /acp-operations
COPY --from=build /bin/acp-devctl /acp-devctl
USER 65532:65532
ENTRYPOINT ["/acp-operations"]
