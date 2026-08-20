package engine

import (
	"strings"
	"testing"

	"stress-strike/internal/config"
)

// TestCheckAssertionsDetailed tests the checkAssertions function with various assertions
func TestCheckAssertionsDetailed(t *testing.T) {
	body := []byte(`{"data":{"token":"abc"},"ok":true}`)

	t.Run("all pass", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{
			{Type: "status", Value: "200"},
			{Type: "json_path", Value: "data.token"},
			{Type: "regex", Value: `"ok":true`},
		}, 200, body)
		if err != nil {
			t.Fatalf("all assertions should pass, got %v", err)
		}
	})

	t.Run("status 2xx matches 201", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "status", Value: "2xx"}}, 201, body)
		if err != nil {
			t.Fatalf("2xx should match 201: %v", err)
		}
	})

	t.Run("status 5xx matches 503", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "status", Value: "5xx"}}, 503, body)
		if err != nil {
			t.Fatalf("5xx should match 503: %v", err)
		}
	})

	t.Run("status 20x matches 201", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "status", Value: "20x"}}, 201, body)
		if err != nil {
			t.Fatalf("20x should match 201: %v", err)
		}
	})

	t.Run("status 20x matches 209", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "status", Value: "20x"}}, 209, body)
		if err != nil {
			t.Fatalf("20x should match 209: %v", err)
		}
	})

	t.Run("status 20x not match 210", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "status", Value: "20x"}}, 210, body)
		if err == nil {
			t.Fatal("20x should not match 210")
		}
	})

	t.Run("status exact match fails", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "status", Value: "200"}}, 500, body)
		if err == nil {
			t.Fatal("expected failure for mismatched status")
		}
	})

	t.Run("json_path missing fails", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "json_path", Value: "data.missing"}}, 200, body)
		if err == nil {
			t.Fatal("expected failure for missing json path")
		}
	})

	t.Run("json_path empty body fails", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "json_path", Value: "data.token"}}, 200, []byte(""))
		if err == nil {
			t.Fatal("expected failure for empty body json path")
		}
	})

	t.Run("json_path invalid json fails", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "json_path", Value: "data.token"}}, 200, []byte("not json"))
		if err == nil {
			t.Fatal("expected failure for invalid json")
		}
	})

	t.Run("regex unmatched fails", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "regex", Value: "NOPE"}}, 200, body)
		if err == nil {
			t.Fatal("expected failure for unmatched regex")
		}
	})

	t.Run("regex matches", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "regex", Value: "token"}}, 200, body)
		if err != nil {
			t.Fatalf("regex should match: %v", err)
		}
	})

	t.Run("regex case sensitive", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "regex", Value: "TOKEN"}}, 200, body)
		if err == nil {
			t.Fatal("regex should be case sensitive")
		}
	})

	t.Run("invalid status assertion fails", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "status", Value: "abc"}}, 200, body)
		if err == nil {
			t.Fatal("expected failure for invalid status assertion")
		}
	})

	t.Run("invalid status format fails", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "status", Value: "2x"}}, 200, body)
		if err == nil {
			t.Fatal("expected failure for invalid status format")
		}
	})

	t.Run("invalid status 6xx fails", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "status", Value: "6xx"}}, 200, body)
		if err == nil {
			t.Fatal("expected failure for 6xx (invalid)")
		}
	})

	t.Run("unsupported assertion type fails", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "nope", Value: "x"}}, 200, body)
		if err == nil {
			t.Fatal("expected failure for unsupported assertion type")
		}
	})

	t.Run("empty assertions passes", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{}, 200, body)
		if err != nil {
			t.Fatalf("empty assertions should pass: %v", err)
		}
	})

	t.Run("multiple assertions first fails", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{
			{Type: "status", Value: "500"},
			{Type: "json_path", Value: "data.token"},
		}, 200, body)
		if err == nil {
			t.Fatal("expected failure for first assertion")
		}
		if err.Error() != "status assertion \"500\" failed: got 200" {
			t.Errorf("error message = %q", err.Error())
		}
	})
}

// TestMatchStatus tests the matchStatus function
func TestMatchStatus(t *testing.T) {
	tests := []struct {
		name     string
		want     string
		got      int
		expected bool
		wantErr  bool
	}{
		{"exact 200", "200", 200, true, false},
		{"exact 404", "404", 404, true, false},
		{"exact 500", "500", 500, true, false},
		{"exact mismatch", "200", 500, false, false},
		{"2xx matches 200", "2xx", 200, true, false},
		{"2xx matches 201", "2xx", 201, true, false},
		{"2xx matches 299", "2xx", 299, true, false},
		{"2xx not match 300", "2xx", 300, false, false},
		{"5xx matches 500", "5xx", 500, true, false},
		{"5xx matches 503", "5xx", 503, true, false},
		{"5xx not match 499", "5xx", 499, false, false},
		{"20x matches 200", "20x", 200, true, false},
		{"20x matches 209", "20x", 209, true, false},
		{"20x not match 210", "20x", 210, false, false},
		{"30x matches 301", "30x", 301, true, false},
		{"30x matches 307", "30x", 307, true, false},
		{"30x not match 310", "30x", 310, false, false},
		{"invalid abc", "abc", 200, false, true},
		{"invalid 2x (partial match)", "2x", 200, false, false},  // Sscanf parses "2", no error
		{"invalid 6xx (out of range)", "6xx", 200, false, false}, // '6' > '5', falls to Sscanf
		{"invalid 2xx9 (too long)", "2xx9", 200, false, false},   // len 4, falls to Sscanf
		{"whitespace  200  ", "  200  ", 200, true, false},
		{"whitespace 2xx ", " 2xx ", 201, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := matchStatus(tt.want, tt.got)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error for invalid status assertion")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tt.expected {
				t.Errorf("matchStatus(%q, %d) = %v, want %v", tt.want, tt.got, ok, tt.expected)
			}
		})
	}
}

// TestCheckAssertion tests individual assertion checking
func TestCheckAssertion(t *testing.T) {
	body := []byte(`{"user":{"id":42,"name":"test"},"status":"ok"}`)

	t.Run("status assertion", func(t *testing.T) {
		err := checkAssertion(config.Assertion{Type: "status", Value: "200"}, 200, body)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("json_path assertion nested", func(t *testing.T) {
		err := checkAssertion(config.Assertion{Type: "json_path", Value: "user.id"}, 200, body)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("json_path assertion deep nested", func(t *testing.T) {
		err := checkAssertion(config.Assertion{Type: "json_path", Value: "user.name"}, 200, body)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("json_path assertion missing", func(t *testing.T) {
		err := checkAssertion(config.Assertion{Type: "json_path", Value: "user.email"}, 200, body)
		if err == nil {
			t.Error("expected error for missing json path")
		}
	})

	t.Run("regex assertion", func(t *testing.T) {
		err := checkAssertion(config.Assertion{Type: "regex", Value: `id.*42`}, 200, body)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("regex assertion no match", func(t *testing.T) {
		err := checkAssertion(config.Assertion{Type: "regex", Value: `notfound`}, 200, body)
		if err == nil {
			t.Error("expected error for no regex match")
		}
	})

	t.Run("invalid regex assertion", func(t *testing.T) {
		err := checkAssertion(config.Assertion{Type: "regex", Value: `[invalid`}, 200, body)
		if err == nil {
			t.Error("expected error for invalid regex")
		}
		if !strings.Contains(err.Error(), "invalid regex") {
			t.Errorf("error message should mention invalid regex: %v", err)
		}
	})
}

// TestExtractJSONPath tests the extractJSONPath function indirectly
func TestExtractJSONPath(t *testing.T) {
	body := []byte(`{"data":{"token":"abc-123","nested":{"value":42}},"array":[1,2,3]}`)

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{"simple", "data.token", "abc-123", false},
		{"nested", "data.nested.value", "42", false},
		{"missing", "data.missing", "", true},
		{"array", "array", "[1 2 3]", false}, // string representation of array
		{"root", "data", "map[nested:map[value:42] token:abc-123]", false},
		{"empty path", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractJSONPath(body, tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestAssertionsWithVariables tests assertions with variable rendering
func TestAssertionsWithVariables(t *testing.T) {
	// This tests the integration of assertions with the engine's variable system
	// The actual variable rendering happens in the engine, but we can test
	// that assertions work with dynamic values

	body := []byte(`{"data":{"user_id":123,"session":"abc"}}`)

	// Test that assertions work with various status codes
	t.Run("status 2xx with body", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{
			{Type: "status", Value: "2xx"},
			{Type: "json_path", Value: "data.user_id"},
		}, 201, body)
		if err != nil {
			t.Fatalf("should pass: %v", err)
		}
	})

	t.Run("regex with special chars", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{
			{Type: "regex", Value: `session":"abc`},
		}, 200, body)
		if err != nil {
			t.Fatalf("should pass: %v", err)
		}
	})
}

// TestAssertionErrorMessages tests that error messages are informative
func TestAssertionErrorMessages(t *testing.T) {
	body := []byte(`{"ok":false}`)

	t.Run("status error message", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "status", Value: "200"}}, 500, body)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "status assertion") {
			t.Errorf("error should mention status assertion: %v", err)
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("error should mention actual status: %v", err)
		}
	})

	t.Run("json_path error message", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "json_path", Value: "data.missing"}}, 200, body)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "json_path assertion") {
			t.Errorf("error should mention json_path: %v", err)
		}
	})

	t.Run("regex error message", func(t *testing.T) {
		err := checkAssertions([]config.Assertion{{Type: "regex", Value: "notfound"}}, 200, body)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "regex assertion") {
			t.Errorf("error should mention regex: %v", err)
		}
	})
}
