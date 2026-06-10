// Package httpproxy is a read-only HTTP reverse-proxy backend type.
//
// It supports multiple named instances, including several of the same service
// type (e.g. two VictoriaLogs clusters). Each instance is addressed under its
// own unique path prefix (/b/<name>/...) and carries, in its own struct, a
// curated read-only endpoint allowlist (from a preset plus optional extras),
// upstream auth, response/result guardrails, the groups permitted to reach it
// (allowed_groups, the coarse gate), and per-group grants that decide allowed
// endpoints and the server-side data scope.
//
// Data scoping is enforced by the gateway when it builds the upstream request:
// client-supplied values that could widen scope are stripped before the grant's
// forced values, tenancy headers, and mandatory query filters are injected. The
// client has no code path to override or widen what a grant pins.
package httpproxy

import (
	"fmt"
	"net/url"
	"strings"
)

// Endpoint is one allowlisted upstream route. Path is a pattern where a "*"
// segment matches exactly one path segment, and a trailing "*" matches one or
// more remaining segments (e.g. "/api/dashboards/*").
type Endpoint struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

// Match reports whether method+path is this endpoint.
func (e Endpoint) Match(method, path string) bool {
	if !strings.EqualFold(method, e.Method) {
		return false
	}
	return matchPattern(e.Path, path)
}

func matchPattern(pattern, path string) bool {
	ps := segments(pattern)
	xs := segments(path)
	for i := range ps {
		if ps[i] == "*" {
			if i == len(ps)-1 { // trailing wildcard: match one or more remaining
				return len(xs) > i
			}
			if i >= len(xs) { // mid wildcard needs a segment to consume
				return false
			}
			continue
		}
		if i >= len(xs) || ps[i] != xs[i] {
			return false
		}
	}
	return len(xs) == len(ps)
}

func segments(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// VLScope is the VictoriaLogs tenancy + mandatory-filter scope. AccountID and
// ProjectID pin tenancy (client-supplied tenancy headers are stripped); the
// MandatoryFilter is AND-injected into the client's LogsQL query so the client
// can only ever narrow within its slice, never widen out of it.
type VLScope struct {
	AccountID       string `json:"account_id"`
	ProjectID       string `json:"project_id"`
	MandatoryFilter string `json:"mandatory_filter"`
	QueryParam      string `json:"query_param"` // default "query"
}

// Scope is the server-side data scope a grant enforces.
type Scope struct {
	ForcedQueryParams map[string]string `json:"forced_query_params"`
	ForcedHeaders     map[string]string `json:"forced_headers"`
	StripQueryParams  []string          `json:"strip_query_params"`
	StripHeaders      []string          `json:"strip_headers"`
	VictoriaLogs      *VLScope          `json:"victorialogs"`
}

// Grant binds a group to a set of allowlisted endpoint ids and a data scope on
// one backend instance.
type Grant struct {
	Group     string   `json:"group"`
	Endpoints []string `json:"endpoints"`
	Scope     Scope    `json:"scope"`
}

func (g Grant) allows(endpointID string) bool {
	for _, e := range g.Endpoints {
		if e == endpointID {
			return true
		}
	}
	return false
}

// Config is the JSON DTO for one httpproxy instance.
type Config struct {
	Name             string            `json:"name"`
	Type             string            `json:"type"` // prometheus | victorialogs | grafana
	BaseURL          string            `json:"base_url"`
	AllowedGroups    []string          `json:"allowed_groups"`
	UpstreamAuth     map[string]string `json:"upstream_auth"`
	MaxResponseBytes int64             `json:"max_response_bytes"`
	MaxResultLimit   int               `json:"max_result_limit"`
	ResultLimitParam string            `json:"result_limit_param"`
	ExtraEndpoints   []Endpoint        `json:"extra_endpoints"`
	Grants           []Grant           `json:"grants"`
}

// combineLogsQL AND-joins a mandatory filter with the client's query. Both
// sides are parenthesized so the client term cannot break out (e.g. with OR) of
// the mandatory constraint.
func combineLogsQL(mandatory, client string) string {
	mandatory = strings.TrimSpace(mandatory)
	client = strings.TrimSpace(client)
	switch {
	case mandatory == "":
		return client
	case client == "":
		return "(" + mandatory + ")"
	default:
		return "(" + mandatory + ") AND (" + client + ")"
	}
}

func validateType(t string) error {
	switch t {
	case "prometheus", "victorialogs", "grafana":
		return nil
	default:
		return fmt.Errorf("unknown backend type %q", t)
	}
}

func parseBaseURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("base_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse base_url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("base_url %q must be an absolute http(s) URL", raw)
	}
	return u, nil
}
