package domain

import "errors"

var (
	ErrNotFound            = errors.New("resource not found")
	ErrInvalidTransition   = errors.New("invalid run state transition")
	ErrVersionConflict     = errors.New("run version conflict")
	ErrIdempotencyConflict = errors.New("idempotency key reused with a different request")
	ErrInvalidInput        = errors.New("invalid input")
)
