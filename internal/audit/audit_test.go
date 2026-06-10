package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func newLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	return slog.New(h), &buf
}

func decode(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("decode log line %q: %v", buf.String(), err)
	}
	return m
}

func TestLogAllowEmitsStructuredFieldsAtInfo(t *testing.T) {
	logger, buf := newLogger()
	Log(logger, Event{
		ClientID:  "llm-1",
		Operation: "redis.get",
		Method:    "GET",
		Path:      "/redis/get",
		Decision:  Allow,
		Status:    200,
	})
	m := decode(t, buf)
	if m["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", m["level"])
	}
	if m["client_id"] != "llm-1" || m["operation"] != "redis.get" {
		t.Errorf("missing identity fields: %v", m)
	}
	if m["decision"] != "allow" {
		t.Errorf("decision = %v, want allow", m["decision"])
	}
	if m["status"] != float64(200) {
		t.Errorf("status = %v, want 200", m["status"])
	}
}

func TestLogDenyEmitsReasonAtWarn(t *testing.T) {
	logger, buf := newLogger()
	Log(logger, Event{
		ClientID:  "unknown",
		Operation: "redis.del",
		Decision:  Deny,
		Reason:    "not_allowed",
		Status:    403,
	})
	m := decode(t, buf)
	if m["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", m["level"])
	}
	if m["decision"] != "deny" {
		t.Errorf("decision = %v, want deny", m["decision"])
	}
	if m["reason"] != "not_allowed" {
		t.Errorf("reason = %v, want not_allowed", m["reason"])
	}
}
