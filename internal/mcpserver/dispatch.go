package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// dispatch translates a tool call into the HTTP request the gateway already
// understands and runs it through the same pipeline as the HTTP front-end
// (gateway.ServeHTTP). All authorization, scoping, rate limiting, and audit
// therefore happen exactly once, in the gateway. The recorded response becomes
// the MCP tool result; a non-2xx status surfaces as an MCP tool error so the
// model sees the refusal and can self-correct.
func (s *Server) dispatch(ctx context.Context, spec toolSpec, token string, args map[string]any) *mcp.CallToolResult {
	path, errResult := s.requestPath(spec, args)
	if errResult != nil {
		return errResult
	}

	query := url.Values{}
	var body []byte
	for _, p := range spec.params {
		raw, present := args[p.name]
		if !present || raw == nil {
			if p.required {
				return errorResult("missing required argument: " + p.name)
			}
			continue
		}
		if p.name == spec.bodyParam {
			b, err := json.Marshal(raw)
			if err != nil {
				return errorResult(fmt.Sprintf("invalid %s: %v", p.name, err))
			}
			body = b
			continue
		}
		str, err := scalarToString(raw)
		if err != nil {
			return errorResult(fmt.Sprintf("invalid %s: %v", p.name, err))
		}
		if str == "" {
			if p.required {
				return errorResult("missing required argument: " + p.name)
			}
			continue
		}
		query.Set(p.name, str)
	}

	target := path
	if enc := query.Encode(); enc != "" {
		target += "?" + enc
	}

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, spec.method, target, reqBody)
	if err != nil {
		return errorResult(fmt.Sprintf("build request: %v", err))
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	rec := httptest.NewRecorder()
	s.g.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	respBody, _ := io.ReadAll(res.Body)
	text := string(respBody)

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		msg := strings.TrimSpace(text)
		return errorResult(fmt.Sprintf("airlock refused or upstream error (HTTP %d): %s", res.StatusCode, msg))
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// requestPath resolves the gateway path for the call. For httpproxy tools it
// validates and embeds the required instance argument.
func (s *Server) requestPath(spec toolSpec, args map[string]any) (string, *mcp.CallToolResult) {
	if spec.isRedis() {
		return spec.opPath, nil
	}
	instance, _ := args["instance"].(string)
	instance = strings.TrimSpace(instance)
	if instance == "" {
		return "", errorResult("missing required argument: instance")
	}
	if strings.ContainsAny(instance, "/?#") {
		return "", errorResult("invalid instance name")
	}
	up := spec.upstreamPath
	if !strings.HasPrefix(up, "/") {
		up = "/" + up
	}
	return "/b/" + instance + up, nil
}

// scalarToString renders a JSON-decoded scalar as a query value. JSON numbers
// arrive as float64; whole numbers are rendered without a fractional part.
func scalarToString(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case bool:
		return strconv.FormatBool(x), nil
	case float64:
		if !math.IsInf(x, 0) && !math.IsNaN(x) && x == math.Trunc(x) {
			return strconv.FormatInt(int64(x), 10), nil
		}
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case json.Number:
		return x.String(), nil
	default:
		return "", fmt.Errorf("unsupported value type %T", v)
	}
}

func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}
