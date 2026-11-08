package scanner

// graphql_test.go — coverage for the GraphQL introspection scanner.
//
// The scanner never dials: every request goes through core.Requester, so the tests
// use the passiveFakeRequester from checks_passive_test.go to script answers.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner/core"
)

func TestScanGraphQLIntrospectionEnabled(t *testing.T) {
	var got *http.Request
	fr := &passiveFakeRequester{
		handler: func(r *http.Request) (*http.Response, error) {
			got = r
			return passiveTestResponse(200, http.Header{"Content-Type": {"application/json"}}, `{
				"data":{"__schema":{
					"queryType":{"name":"Query"},
					"types":[
						{"name":"User"},
						{"name":"UserPassword"},
						{"name":"AuthToken"},
						{"name":"PaymentInfo"}
					]
				}}
			}`), nil
		},
	}

	res := ScanGraphQL(context.Background(), "https://api.example.test/graphql", fr)
	if res == nil {
		t.Fatal("ScanGraphQL returned nil")
	}
	if !res.Reachable {
		t.Error("Reachable = false, want true")
	}
	if !res.Introspection {
		t.Error("Introspection = false, want true")
	}
	if res.Schema != "Query" {
		t.Errorf("Schema = %q, want Query", res.Schema)
	}
	wantTypes := []string{"User", "UserPassword", "AuthToken", "PaymentInfo"}
	if len(res.Types) != len(wantTypes) {
		t.Fatalf("Types = %v, want %v", res.Types, wantTypes)
	}
	for i, want := range wantTypes {
		if res.Types[i] != want {
			t.Errorf("Types[%d] = %q, want %q", i, res.Types[i], want)
		}
	}

	joined := strings.Join(res.Issues, "\n")
	if !strings.Contains(joined, "introspection is enabled") {
		t.Errorf("Issues = %v, want an introspection disclosure", res.Issues)
	}
	for _, name := range []string{"UserPassword", "AuthToken"} {
		if !strings.Contains(joined, name) {
			t.Errorf("Issues do not flag the sensitive type %q: %v", name, res.Issues)
		}
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v, want a positive value", res.Duration)
	}
	if got == nil {
		t.Fatal("the requester never saw the request")
	}
	if got.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", got.Method)
	}
	if ct := got.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if ua := got.Header.Get("User-Agent"); !strings.Contains(ua, "graphql") {
		t.Errorf("User-Agent = %q", ua)
	}
}

func TestScanGraphQLNoIntrospection(t *testing.T) {
	fr := &passiveFakeRequester{
		handler: func(*http.Request) (*http.Response, error) {
			// Valid GraphQL data, but introspection is disabled server-side.
			return passiveTestResponse(200, nil, `{"data":{"viewer":{"id":1}}}`), nil
		},
	}
	res := ScanGraphQL(context.Background(), "https://api.example.test/graphql", fr)
	if !res.Reachable {
		t.Error("Reachable = false, want true")
	}
	if res.Introspection {
		t.Error("Introspection = true, want false")
	}
	if len(res.Issues) != 0 {
		t.Errorf("Issues = %v, want none for a schema-less answer", res.Issues)
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v", res.Duration)
	}
}

func TestScanGraphQLNonJSONResponse(t *testing.T) {
	fr := &passiveFakeRequester{
		handler: func(*http.Request) (*http.Response, error) {
			return passiveTestResponse(200, nil, "<html>not graphql</html>"), nil
		},
	}
	res := ScanGraphQL(context.Background(), "https://api.example.test/graphql", fr)
	if !res.Reachable {
		t.Error("Reachable = false, want true: the endpoint answered")
	}
	if res.Introspection {
		t.Error("Introspection = true for an HTML body")
	}
	if !strings.Contains(strings.Join(res.Issues, " "), "non-JSON response") {
		t.Errorf("Issues = %v, want a non-JSON note", res.Issues)
	}
}

func TestScanGraphQLGateRefusal(t *testing.T) {
	fr := &passiveFakeRequester{refuse: core.ErrOutOfScope}
	res := ScanGraphQL(context.Background(), "https://out-of-scope.example.test/graphql", fr)
	if res.Reachable {
		t.Error("Reachable = true although the gate refused")
	}
	if len(fr.fetched()) != 0 {
		t.Errorf("the gate refused but %d request(s) were sent", len(fr.fetched()))
	}
	if !strings.Contains(strings.Join(res.Issues, " "), "refused by gate") {
		t.Errorf("Issues = %v, want a gate refusal", res.Issues)
	}
}

func TestScanGraphQLRequestFailure(t *testing.T) {
	fr := &passiveFakeRequester{
		handler: func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial tcp: connection refused")
		},
	}
	res := ScanGraphQL(context.Background(), "https://api.example.test/graphql", fr)
	if res.Reachable {
		t.Error("Reachable = true after a transport failure")
	}
	if !strings.Contains(strings.Join(res.Issues, " "), "request failed") {
		t.Errorf("Issues = %v", res.Issues)
	}
}

func TestScanGraphQLNilResponse(t *testing.T) {
	fr := &passiveFakeRequester{
		handler: func(*http.Request) (*http.Response, error) { return nil, nil },
	}
	res := ScanGraphQL(context.Background(), "https://api.example.test/graphql", fr)
	if res.Reachable {
		t.Error("Reachable = true for a nil response")
	}
	if !strings.Contains(strings.Join(res.Issues, " "), "nil response") {
		t.Errorf("Issues = %v", res.Issues)
	}
}

func TestScanGraphQLInvalidURL(t *testing.T) {
	res := ScanGraphQL(context.Background(), "http://[::1", &passiveFakeRequester{})
	if res.Reachable {
		t.Error("Reachable = true for an unparseable URL")
	}
	if !strings.Contains(strings.Join(res.Issues, " "), "invalid URL") {
		t.Errorf("Issues = %v", res.Issues)
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v", res.Duration)
	}
}

func TestURLParseAndClock(t *testing.T) {
	got, err := urlParse("https://example.test/graphql?x=1")
	if err != nil {
		t.Fatalf("urlParse: %v", err)
	}
	if got != "https://example.test/graphql?x=1" {
		t.Errorf("urlParse = %q", got)
	}
	if _, err := urlParse("http://[::1"); err == nil {
		t.Error("urlParse accepted a malformed host")
	}

	start := nowSeconds()
	time.Sleep(2 * time.Millisecond)
	elapsed := sinceSeconds(start)
	if elapsed <= 0 {
		t.Errorf("sinceSeconds = %v, want a positive delta", elapsed)
	}
	if elapsed > 5 {
		t.Errorf("sinceSeconds = %v, want a small delta", elapsed)
	}
}
