package httpproxy

import (
	"fmt"
	"net/http"
)

// Preset returns the curated, read-only endpoint allowlist for a backend type.
// Everything not listed — including all write/admin/delete paths — is
// unreachable by construction (default-deny), not blocklisted.
func Preset(typ string) ([]Endpoint, error) {
	switch typ {
	case "prometheus":
		return prometheusPreset(), nil
	case "victorialogs":
		return victoriaLogsPreset(), nil
	case "grafana":
		return grafanaPreset(), nil
	default:
		return nil, fmt.Errorf("unknown backend type %q", typ)
	}
}

func prometheusPreset() []Endpoint {
	return []Endpoint{
		{ID: "prom.query", Method: http.MethodGet, Path: "/api/v1/query"},
		{ID: "prom.query_range", Method: http.MethodGet, Path: "/api/v1/query_range"},
		{ID: "prom.series", Method: http.MethodGet, Path: "/api/v1/series"},
		{ID: "prom.labels", Method: http.MethodGet, Path: "/api/v1/labels"},
		{ID: "prom.label_values", Method: http.MethodGet, Path: "/api/v1/label/*/values"},
		{ID: "prom.metadata", Method: http.MethodGet, Path: "/api/v1/metadata"},
		{ID: "prom.targets", Method: http.MethodGet, Path: "/api/v1/targets"},
	}
}

func victoriaLogsPreset() []Endpoint {
	return []Endpoint{
		{ID: "vl.query", Method: http.MethodGet, Path: "/select/logsql/query"},
		{ID: "vl.hits", Method: http.MethodGet, Path: "/select/logsql/hits"},
		{ID: "vl.field_names", Method: http.MethodGet, Path: "/select/logsql/field_names"},
		{ID: "vl.field_values", Method: http.MethodGet, Path: "/select/logsql/field_values"},
	}
}

func grafanaPreset() []Endpoint {
	return []Endpoint{
		{ID: "grafana.search", Method: http.MethodGet, Path: "/api/search"},
		{ID: "grafana.dashboard_get", Method: http.MethodGet, Path: "/api/dashboards/*"},
		{ID: "grafana.ds_query", Method: http.MethodPost, Path: "/api/ds/query"},
	}
}
