package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/zzn01/airlock/internal/config"
)

// addTools registers, on srv, exactly the tools client may call. Visibility is
// read-only introspection over the same data the gateway enforces against, so
// it can never drift from enforcement; the gateway still authorizes every call.
func (s *Server) addTools(srv *mcp.Server, client config.Client, token string) {
	for _, spec := range catalog {
		if spec.isRedis() {
			// A redis tool is visible only if the client's allowlist permits the
			// op and the redis backend is actually configured.
			if !client.Allowed(spec.opID) || !s.g.HasOperation(spec.method, spec.opPath) {
				continue
			}
			s.register(srv, spec, token, nil)
			continue
		}
		reachable := s.reachableInstances(client, spec)
		if len(reachable) == 0 {
			continue
		}
		s.register(srv, spec, token, reachable)
	}
}

// reachableInstances returns the names of instances of the tool's backend type
// the client may reach for the tool's endpoint, using the exact checks the
// gateway runs: coarse group gate, endpoint allowlist, and grant (default-deny).
func (s *Server) reachableInstances(client config.Client, spec toolSpec) []string {
	var names []string
	for _, inst := range s.g.Proxies().Instances() {
		if inst.Type() != spec.backend {
			continue
		}
		effective := inst.Effective(client.Groups)
		if len(effective) == 0 {
			continue
		}
		ep, ok := inst.MatchEndpoint(spec.method, spec.upstreamPath)
		if !ok {
			continue
		}
		if _, ok := inst.Grant(effective, ep.ID); !ok {
			continue
		}
		names = append(names, inst.Name())
	}
	return names
}

// register adds one tool to srv. instances is the per-client enum of reachable
// instance names for an httpproxy tool, or nil for a redis tool.
func (s *Server) register(srv *mcp.Server, spec toolSpec, token string, instances []string) {
	tool := &mcp.Tool{
		Name:        spec.name,
		Description: spec.description,
		InputSchema: inputSchema(spec, instances),
	}
	srv.AddTool(tool, s.handlerFor(spec, token))
}

// inputSchema builds the tool's JSON Schema. httpproxy tools gain a required
// "instance" argument constrained to an enum of the reachable instances, so the
// model cannot even name an instance it may not reach.
func inputSchema(spec toolSpec, instances []string) map[string]any {
	props := map[string]any{}
	var required []string

	if !spec.isRedis() {
		enum := make([]any, len(instances))
		for i, n := range instances {
			enum[i] = n
		}
		props["instance"] = map[string]any{
			"type":        "string",
			"description": "Target backend instance.",
			"enum":        enum,
		}
		required = append(required, "instance")
	}

	for _, p := range spec.params {
		ps := map[string]any{"type": p.typ}
		if p.description != "" {
			ps["description"] = p.description
		}
		props[p.name] = ps
		if p.required {
			required = append(required, p.name)
		}
	}

	schema := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		req := make([]any, len(required))
		for i, r := range required {
			req[i] = r
		}
		schema["required"] = req
	}
	return schema
}

// handlerFor returns the tool handler: unmarshal arguments, then dispatch
// through the gateway pipeline. The client token is captured per connection.
func (s *Server) handlerFor(spec toolSpec, token string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := map[string]any{}
		if raw := req.Params.Arguments; len(raw) > 0 {
			if err := json.Unmarshal(raw, &args); err != nil {
				return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
			}
		}
		return s.dispatch(ctx, spec, token, args), nil
	}
}
