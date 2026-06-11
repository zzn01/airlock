package httpproxy

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// VictoriaLogs multitenancy header names. Client-supplied values for these are
// always stripped and replaced by the grant's pinned tenancy.
const (
	headerAccountID = "AccountID"
	headerProjectID = "ProjectID"
)

// hopByHop headers are connection-scoped and must not be forwarded upstream.
var hopByHop = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// gatewayCredentialHeaders are the client's credentials to the gateway; they
// are never forwarded to the upstream.
var gatewayCredentialHeaders = []string{"Authorization", "X-Api-Key"}

// Instance is a constructed, validated httpproxy backend.
type Instance struct {
	cfg       Config
	baseURL   *url.URL
	endpoints []Endpoint
	client    *http.Client
}

// New validates cfg, resolves the preset (plus any extra endpoints), and parses
// the base URL.
func New(cfg Config) (*Instance, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("httpproxy: name is required")
	}
	if err := validateType(cfg.Type); err != nil {
		return nil, fmt.Errorf("httpproxy %q: %w", cfg.Name, err)
	}
	base, err := parseBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("httpproxy %q: %w", cfg.Name, err)
	}
	preset, err := Preset(cfg.Type)
	if err != nil {
		return nil, fmt.Errorf("httpproxy %q: %w", cfg.Name, err)
	}
	eps := append(append([]Endpoint{}, preset...), cfg.ExtraEndpoints...)
	return &Instance{
		cfg:       cfg,
		baseURL:   base,
		endpoints: eps,
		client:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Name returns the instance name.
func (in *Instance) Name() string { return in.cfg.Name }

// Type returns the instance's service type (prometheus|victorialogs|grafana).
func (in *Instance) Type() string { return in.cfg.Type }

// AllowedGroups returns the coarse-gate group list.
func (in *Instance) AllowedGroups() []string { return in.cfg.AllowedGroups }

// Effective returns the client groups that intersect the instance's
// allowed_groups, in client-group order. An empty result means the coarse gate
// denies the client outright.
func (in *Instance) Effective(clientGroups []string) []string {
	allowed := make(map[string]bool, len(in.cfg.AllowedGroups))
	for _, g := range in.cfg.AllowedGroups {
		allowed[g] = true
	}
	var out []string
	for _, g := range clientGroups {
		if allowed[g] {
			out = append(out, g)
		}
	}
	return out
}

// MatchEndpoint returns the allowlisted endpoint for method+path, if any.
func (in *Instance) MatchEndpoint(method, path string) (Endpoint, bool) {
	for _, e := range in.endpoints {
		if e.Match(method, path) {
			return e, true
		}
	}
	return Endpoint{}, false
}

// Grant returns the grant authorizing endpointID for the first of effective (in
// order) whose grant lists it. The union over the client's effective groups
// decides whether the endpoint is allowed; the data scope applied is that of
// the first matching grant.
func (in *Instance) Grant(effective []string, endpointID string) (Grant, bool) {
	for _, group := range effective {
		for _, g := range in.cfg.Grants {
			if g.Group == group && g.allows(endpointID) {
				return g, true
			}
		}
	}
	return Grant{}, false
}

// Proxy builds the scoped upstream request, executes it, and writes the capped
// response. All scope enforcement (strip → force → inject → cap) happens here,
// so a client cannot widen what the grant pins.
func (in *Instance) Proxy(w http.ResponseWriter, r *http.Request, upstreamPath string, _ Endpoint, g Grant) {
	q := r.URL.Query()
	in.clampResultLimit(q)
	applyScopeQuery(q, g.Scope)

	up := *in.baseURL
	up.Path = singleJoin(in.baseURL.Path, upstreamPath)
	up.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(r.Context(), r.Method, up.String(), r.Body)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	req.Header = in.upstreamHeaders(r.Header, g.Scope)

	resp, err := in.client.Do(req)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	in.writeCapped(w, resp)
}

// clampResultLimit bounds the configured result-count parameter to the
// instance's cap (and sets it to the cap when the client omits or exceeds it).
func (in *Instance) clampResultLimit(q url.Values) {
	if in.cfg.MaxResultLimit <= 0 || in.cfg.ResultLimitParam == "" {
		return
	}
	cur := q.Get(in.cfg.ResultLimitParam)
	n, err := strconv.Atoi(cur)
	if cur == "" || err != nil || n <= 0 || n > in.cfg.MaxResultLimit {
		q.Set(in.cfg.ResultLimitParam, strconv.Itoa(in.cfg.MaxResultLimit))
	}
}

// applyScopeQuery strips, then forces, then AND-injects the VictoriaLogs
// mandatory filter into the query parameters.
func applyScopeQuery(q url.Values, sc Scope) {
	for _, k := range sc.StripQueryParams {
		q.Del(k)
	}
	for k, v := range sc.ForcedQueryParams {
		q.Set(k, v)
	}
	if sc.VictoriaLogs != nil {
		param := sc.VictoriaLogs.QueryParam
		if param == "" {
			param = "query"
		}
		q.Set(param, combineLogsQL(sc.VictoriaLogs.MandatoryFilter, q.Get(param)))
	}
}

// upstreamHeaders builds the outbound header set: client headers minus
// hop-by-hop, gateway credentials, stripped headers, forced/tenancy header
// names; then the grant's forced headers, VictoriaLogs tenancy, and the
// instance's upstream auth.
func (in *Instance) upstreamHeaders(client http.Header, sc Scope) http.Header {
	drop := map[string]bool{}
	for h := range hopByHop {
		drop[http.CanonicalHeaderKey(h)] = true
	}
	for _, h := range gatewayCredentialHeaders {
		drop[http.CanonicalHeaderKey(h)] = true
	}
	for _, h := range sc.StripHeaders {
		drop[http.CanonicalHeaderKey(h)] = true
	}
	for h := range sc.ForcedHeaders {
		drop[http.CanonicalHeaderKey(h)] = true
	}
	for h := range in.cfg.UpstreamAuth {
		drop[http.CanonicalHeaderKey(h)] = true
	}
	if sc.VictoriaLogs != nil {
		drop[http.CanonicalHeaderKey(headerAccountID)] = true
		drop[http.CanonicalHeaderKey(headerProjectID)] = true
	}

	out := http.Header{}
	for k, vs := range client {
		if drop[http.CanonicalHeaderKey(k)] {
			continue
		}
		out[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
	}
	for k, v := range sc.ForcedHeaders {
		out.Set(k, v)
	}
	if sc.VictoriaLogs != nil {
		out.Set(headerAccountID, sc.VictoriaLogs.AccountID)
		out.Set(headerProjectID, sc.VictoriaLogs.ProjectID)
	}
	for k, v := range in.cfg.UpstreamAuth {
		out.Set(k, v)
	}
	return out
}

// writeCapped copies the upstream response to the client, truncating the body
// to MaxResponseBytes to bound the tokens fed back to the model.
func (in *Instance) writeCapped(w http.ResponseWriter, resp *http.Response) {
	max := in.cfg.MaxResponseBytes
	var body []byte
	truncated := false
	if max > 0 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, max+1))
		if int64(len(buf)) > max {
			buf = buf[:max]
			truncated = true
		}
		body = buf
	} else {
		body, _ = io.ReadAll(resp.Body)
	}

	for k, vs := range resp.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] || http.CanonicalHeaderKey(k) == "Content-Length" {
			continue
		}
		w.Header()[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
	}
	if truncated {
		w.Header().Set("X-Airlock-Truncated", "true")
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func singleJoin(a, b string) string {
	switch {
	case a == "" || a == "/":
		return b
	case strings.HasSuffix(a, "/") && strings.HasPrefix(b, "/"):
		return a + strings.TrimPrefix(b, "/")
	case !strings.HasSuffix(a, "/") && !strings.HasPrefix(b, "/"):
		return a + "/" + b
	default:
		return a + b
	}
}

// Manager indexes instances by name for the strict per-instance routing
// boundary: a request names exactly one instance and is matched only against
// that instance's allowlist.
type Manager struct {
	instances map[string]*Instance
}

// NewManager returns an empty manager.
func NewManager() *Manager { return &Manager{instances: make(map[string]*Instance)} }

// Add registers an instance. Instance names must be unique.
func (m *Manager) Add(in *Instance) error {
	if _, dup := m.instances[in.Name()]; dup {
		return fmt.Errorf("duplicate httpproxy instance name %q", in.Name())
	}
	m.instances[in.Name()] = in
	return nil
}

// Instance returns the instance with the given name, if any.
func (m *Manager) Instance(name string) (*Instance, bool) {
	in, ok := m.instances[name]
	return in, ok
}

// Instances returns all registered instances, sorted by name for deterministic
// iteration (e.g. when building the MCP tool list).
func (m *Manager) Instances() []*Instance {
	out := make([]*Instance, 0, len(m.instances))
	for _, in := range m.instances {
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
