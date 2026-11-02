package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/avaargsh/agent-control-panel/internal/application"
	"github.com/avaargsh/agent-control-panel/internal/domain"
)

type Server struct{ runs *application.RunService }

func New(runs *application.RunService) http.Handler {
	s := &Server{runs: runs}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /api/v1/runs", s.createRun)
	mux.HandleFunc("GET /api/v1/runs/{id}", s.getRun)
	mux.HandleFunc("POST /api/v1/runs/{id}/transitions", s.transitionRun)
	return responseHeadersMiddleware(mux)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) createRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AgentID   string          `json:"agentId"`
		ReleaseID string          `json:"releaseId"`
		SessionID string          `json:"sessionId,omitempty"`
		Input     json.RawMessage `json:"input,omitempty"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	cmd := application.CreateRunCommand{
		TenantID: tenantID(r), AgentID: body.AgentID, ReleaseID: body.ReleaseID,
		SessionID: body.SessionID, Input: body.Input, IdempotencyKey: strings.TrimSpace(r.Header.Get("Idempotency-Key")),
	}
	run, created, err := s.runs.Create(r.Context(), cmd)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, run)
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.runs.Get(r.Context(), tenantID(r), r.PathValue("id"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) transitionRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ExpectedVersion int64            `json:"expectedVersion"`
		Target          domain.RunStatus `json:"target"`
		Reason          string           `json:"reason,omitempty"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	run, err := s.runs.Transition(r.Context(), tenantID(r), r.PathValue("id"), body.ExpectedVersion, body.Target, body.Reason)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func tenantID(r *http.Request) string { return strings.TrimSpace(r.Header.Get("X-Tenant-ID")) }

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func writeDomainError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
	case errors.Is(err, domain.ErrNotFound):
		writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
	case errors.Is(err, domain.ErrInvalidTransition):
		writeError(w, http.StatusConflict, "INVALID_TRANSITION", err.Error())
	case errors.Is(err, domain.ErrVersionConflict), errors.Is(err, domain.ErrIdempotencyConflict):
		writeError(w, http.StatusConflict, "CONFLICT", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
	}
}

type errorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	var response errorResponse
	response.Error.Code, response.Error.Message = code, message
	writeJSON(w, status, response)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func responseHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
