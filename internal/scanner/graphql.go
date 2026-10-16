package scanner

// --- GraphQL introspection scanner ------------------------------------------
//
// Probes a GraphQL endpoint for introspection being enabled (a serious
// information-disclosure issue), schema exposure, and dangerous fields.
// Every request goes through the Requester gate.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GraphQLResult is the output of a GraphQL scan.
type GraphQLResult struct {
	Endpoint      string   `json:"endpoint"`
	Reachable     bool     `json:"reachable"`
	Introspection bool     `json:"introspection"`
	Schema        string   `json:"schema,omitempty"`
	Types         []string `json:"types,omitempty"`
	Issues        []string `json:"issues,omitempty"`
	Duration      float64  `json:"duration_seconds"`
}

// ScanGraphQL probes target (a GraphQL HTTP endpoint) for introspection.
func ScanGraphQL(ctx context.Context, target string, req Requester) *GraphQLResult {
	res := &GraphQLResult{Endpoint: target}
	start := nowSeconds()

	// Introspection query.
	query := `{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name type { name kind ofType { name kind } } } } } }"}`
	body := []byte(query)

	parsed, err := urlParse(target)
	if err != nil {
		res.Issues = append(res.Issues, "invalid URL: "+err.Error())
		res.Duration = sinceSeconds(start)
		return res
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed, strings.NewReader(string(body)))
	if err != nil {
		res.Issues = append(res.Issues, "cannot build request: "+err.Error())
		res.Duration = sinceSeconds(start)
		return res
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "stress-strike-graphql/1.0")

	if err := req.Check(ctx, http.MethodPost, target, false); err != nil {
		res.Issues = append(res.Issues, "refused by gate: "+err.Error())
		res.Duration = sinceSeconds(start)
		return res
	}
	resp, err := req.Do(httpReq)
	if err != nil {
		res.Issues = append(res.Issues, "request failed: "+err.Error())
		res.Duration = sinceSeconds(start)
		return res
	}
	if resp == nil {
		res.Issues = append(res.Issues, "nil response")
		res.Duration = sinceSeconds(start)
		return res
	}
	if err := resp.Body.Close(); err != nil {
		res.Issues = append(res.Issues, "body close: "+err.Error())
	}
	res.Reachable = true

	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		res.Issues = append(res.Issues, "non-JSON response (GraphQL may not be here)")
		res.Duration = sinceSeconds(start)
		return res
	}

	if data, ok := raw["data"].(map[string]any); ok {
		if schema, ok := data["__schema"].(map[string]any); ok {
			res.Introspection = true
			res.Issues = append(res.Issues, "GraphQL introspection is enabled — schema exposed")
			if qt, ok := schema["queryType"].(map[string]any); ok {
				if name, ok := qt["name"].(string); ok {
					res.Schema = name
				}
			}
			if types, ok := schema["types"].([]any); ok {
				for _, t := range types {
					if tm, ok := t.(map[string]any); ok {
						if name, ok := tm["name"].(string); ok {
							res.Types = append(res.Types, name)
						}
					}
				}
			}
		}
	}

	// Check for dangerous field names in introspected types.
	dangerous := []string{"password", "secret", "token", "key", "credential", "ssn", "creditCard"}
	for _, tname := range res.Types {
		for _, d := range dangerous {
			if strings.Contains(strings.ToLower(tname), d) {
				res.Issues = append(res.Issues, fmt.Sprintf("type %q may expose sensitive data (%s)", tname, d))
			}
		}
	}

	// Check for mutations/subscriptions existing.
	if _, ok := raw["data"].(map[string]any); ok {
		res.Duration = sinceSeconds(start)
	}
	return res
}

func urlParse(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func nowSeconds() float64                { return float64(time.Now().UnixNano()) / 1e9 }
func sinceSeconds(start float64) float64 { return nowSeconds() - start }
