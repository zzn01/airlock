// Package audit emits one structured log/slog record per gateway request.
package audit

import (
	"context"
	"log/slog"
)

// Decision is the access-control outcome for a request.
type Decision string

const (
	// Allow means the request passed authn/authz/rate-limiting and was executed.
	Allow Decision = "allow"
	// Deny means the request was rejected before or during execution.
	Deny Decision = "deny"
)

// Event is a single auditable request outcome.
type Event struct {
	ClientID   string
	Operation  string
	Method     string
	Path       string
	Decision   Decision
	Reason     string // populated on denial, e.g. "invalid_credential"
	Status     int    // HTTP status returned to the caller
	RemoteAddr string
}

// Log writes the event as one structured record: INFO for allow, WARN for deny.
func Log(logger *slog.Logger, e Event) {
	if logger == nil {
		return
	}
	attrs := []slog.Attr{
		slog.String("client_id", e.ClientID),
		slog.String("operation", e.Operation),
		slog.String("method", e.Method),
		slog.String("path", e.Path),
		slog.String("decision", string(e.Decision)),
		slog.Int("status", e.Status),
	}
	if e.Reason != "" {
		attrs = append(attrs, slog.String("reason", e.Reason))
	}
	if e.RemoteAddr != "" {
		attrs = append(attrs, slog.String("remote_addr", e.RemoteAddr))
	}

	level := slog.LevelInfo
	if e.Decision == Deny {
		level = slog.LevelWarn
	}
	logger.LogAttrs(context.Background(), level, "request", attrs...)
}
