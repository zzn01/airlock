package mcpserver

import "net/http"

// Backend kinds. The non-redis values match httpproxy instance types so a tool
// can be associated with the instances that can serve it.
const (
	backendRedis        = "redis"
	backendPrometheus   = "prometheus"
	backendVictoriaLogs = "victorialogs"
	backendGrafana      = "grafana"
)

// paramSpec describes one tool argument and how it maps onto the synthesized
// HTTP request. Unless it is the bodyParam, an argument becomes a query
// parameter of the same name.
type paramSpec struct {
	name        string
	typ         string // JSON Schema type: string | integer | number | object
	required    bool
	description string
}

// toolSpec is one curated MCP tool. Each maps to exactly one airlock operation:
// a redis op-pipeline route (opID/opPath) or an httpproxy endpoint
// (endpointID/upstreamPath) addressed under /b/<instance>/.
type toolSpec struct {
	name        string
	description string
	backend     string // backendRedis or an httpproxy type
	method      string

	// op pipeline (redis).
	opID   string
	opPath string

	// proxy pipeline (httpproxy).
	endpointID   string
	upstreamPath string

	// bodyParam, when set, names the object argument sent as the JSON request
	// body instead of a query parameter (used by POST tools).
	bodyParam string

	params []paramSpec
}

func (t toolSpec) isRedis() bool { return t.backend == backendRedis }

// catalog is the static set of MCP tools. The list a given client sees is
// filtered from this by authorization (see tools.go); enforcement on every call
// is the gateway's, not the catalog's.
var catalog = []toolSpec{
	{
		name:        "redis_get",
		description: "Read the string value stored at a Redis key.",
		backend:     backendRedis,
		method:      http.MethodGet,
		opID:        "redis.get",
		opPath:      "/redis/get",
		params: []paramSpec{
			{name: "key", typ: "string", required: true, description: "Redis key to read."},
		},
	},
	{
		name:        "redis_scan",
		description: "Incrementally iterate Redis keys matching a glob-style pattern.",
		backend:     backendRedis,
		method:      http.MethodGet,
		opID:        "redis.scan",
		opPath:      "/redis/scan",
		params: []paramSpec{
			{name: "pattern", typ: "string", description: `Glob match pattern (default "*").`},
			{name: "cursor", typ: "integer", description: "Iteration cursor from a previous scan (default 0)."},
			{name: "count", typ: "integer", description: "Hint for keys returned per call (default 100)."},
		},
	},
	{
		name:        "redis_exists",
		description: "Report whether a Redis key exists.",
		backend:     backendRedis,
		method:      http.MethodGet,
		opID:        "redis.exists",
		opPath:      "/redis/exists",
		params: []paramSpec{
			{name: "key", typ: "string", required: true, description: "Redis key to check."},
		},
	},
	{
		name:        "redis_ttl",
		description: "Read the remaining time-to-live (seconds) of a Redis key.",
		backend:     backendRedis,
		method:      http.MethodGet,
		opID:        "redis.ttl",
		opPath:      "/redis/ttl",
		params: []paramSpec{
			{name: "key", typ: "string", required: true, description: "Redis key to inspect."},
		},
	},
	{
		name:         "prometheus_query",
		description:  "Evaluate a Prometheus instant query (PromQL) on an instance.",
		backend:      backendPrometheus,
		method:       http.MethodGet,
		endpointID:   "prom.query",
		upstreamPath: "/api/v1/query",
		params: []paramSpec{
			{name: "query", typ: "string", required: true, description: "PromQL expression."},
			{name: "time", typ: "string", description: "Evaluation timestamp (RFC3339 or Unix seconds); optional."},
		},
	},
	{
		name:         "prometheus_query_range",
		description:  "Evaluate a Prometheus range query (PromQL) over a time window.",
		backend:      backendPrometheus,
		method:       http.MethodGet,
		endpointID:   "prom.query_range",
		upstreamPath: "/api/v1/query_range",
		params: []paramSpec{
			{name: "query", typ: "string", required: true, description: "PromQL expression."},
			{name: "start", typ: "string", required: true, description: "Range start (RFC3339 or Unix seconds)."},
			{name: "end", typ: "string", required: true, description: "Range end (RFC3339 or Unix seconds)."},
			{name: "step", typ: "string", required: true, description: `Resolution step (duration, e.g. "30s").`},
		},
	},
	{
		name:         "victorialogs_query",
		description:  "Run a LogsQL query against VictoriaLogs. Tenancy and a mandatory filter are enforced server-side.",
		backend:      backendVictoriaLogs,
		method:       http.MethodGet,
		endpointID:   "vl.query",
		upstreamPath: "/select/logsql/query",
		params: []paramSpec{
			{name: "query", typ: "string", required: true, description: "LogsQL query. A mandatory filter is AND-combined server-side; you can only narrow within it."},
			{name: "limit", typ: "integer", description: "Maximum number of results (the server may cap this)."},
			{name: "start", typ: "string", description: "Start of the time range; optional."},
			{name: "end", typ: "string", description: "End of the time range; optional."},
		},
	},
	{
		name:         "grafana_search",
		description:  "Search Grafana dashboards and folders on an instance.",
		backend:      backendGrafana,
		method:       http.MethodGet,
		endpointID:   "grafana.search",
		upstreamPath: "/api/search",
		params: []paramSpec{
			{name: "query", typ: "string", description: "Search text; optional."},
			{name: "tag", typ: "string", description: "Filter by tag; optional."},
			{name: "type", typ: "string", description: "Filter by item type (dash-db, dash-folder); optional."},
		},
	},
	{
		name:         "grafana_ds_query",
		description:  "Execute a Grafana datasource query. The body is the Grafana /api/ds/query request payload.",
		backend:      backendGrafana,
		method:       http.MethodPost,
		endpointID:   "grafana.ds_query",
		upstreamPath: "/api/ds/query",
		bodyParam:    "body",
		params: []paramSpec{
			{name: "body", typ: "object", required: true, description: "The /api/ds/query JSON payload (queries, range, etc.)."},
		},
	},
}
