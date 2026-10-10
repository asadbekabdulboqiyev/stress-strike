package engine

import (
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

// These benchmarks cover the per-request work that runs for every iteration
// regardless of scenario: building the variable map, interpolating templates,
// and reading a recorded sample. They exist to keep the hot path honest — a
// regression here shows up as a throughput drop long before it shows up in a
// functional test.

func benchScenario() *config.Scenario {
	return &config.Scenario{
		BaseURL: "http://127.0.0.1:9",
		Variables: map[string]string{
			"env":  "staging",
			"tier": "gold",
		},
	}
}

// BenchmarkNewVars measures one get/clear/populate cycle. The map is returned
// to the pool on every iteration, so the benchmark mirrors the real usage
// rather than allocating a fresh map each time.
func BenchmarkNewVars(b *testing.B) {
	sc := benchScenario()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vars := newVars(sc, i)
		putVars(vars)
	}
}

// BenchmarkNewVarsCold measures the same work with pooling disabled, so the
// two numbers can be compared directly. It is the cost the pool removes.
func BenchmarkNewVarsCold(b *testing.B) {
	sc := benchScenario()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = newVarsCold(sc, i)
	}
}

// newVarsCold is the straightforward allocation the pool avoids. Kept as a
// benchmark fixture so the improvement stays measurable.
func newVarsCold(scenario *config.Scenario, userIndex int) map[string]string {
	vars := make(map[string]string, len(scenario.Variables)+6)
	for k, v := range scenario.Variables {
		vars[k] = v
	}
	n := userIndex + 1
	vars["user"] = "user" + itoa(n)
	vars["pass"] = "pass" + itoa(n)
	vars["email"] = "user" + itoa(n) + "@test.local"
	vars["item"] = "item" + itoa(n)
	vars["id"] = itoa(n)
	return vars
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// BenchmarkRenderNoPlaceholder is the common case: most requests do not
// interpolate anything, so render must return the template untouched.
func BenchmarkRenderNoPlaceholder(b *testing.B) {
	tmpl := "http://127.0.0.1:9/api/v1/health"
	vars := map[string]string{"user": "user42"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = render(tmpl, vars)
	}
}

// BenchmarkRenderWithPlaceholder covers a URL that interpolates several
// variables, which is where the regexp scan and its allocations show up.
func BenchmarkRenderWithPlaceholder(b *testing.B) {
	tmpl := "http://127.0.0.1:9/api/{{env}}/users/{{user}}/items/{{item}}?tier={{tier}}"
	vars := map[string]string{
		"user": "user42", "env": "staging", "item": "item42", "tier": "gold",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = render(tmpl, vars)
	}
}

// BenchmarkRenderBodyJSON covers a JSON request body, which additionally pays
// for escaping the interpolated values.
func BenchmarkRenderBodyJSON(b *testing.B) {
	tmpl := `{"user":"{{user}}","email":"{{email}}","item":"{{item}}"}`
	vars := map[string]string{
		"user": "user42", "email": "user42@test.local", "item": "item42",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = renderBody(tmpl, vars)
	}
}

// BenchmarkRenderBodyParallel is the shape that matters under load: many
// virtual users rendering at once, so it also exercises the pool under
// contention.
func BenchmarkRenderBodyParallel(b *testing.B) {
	tmpl := `{"user":"{{user}}","email":"{{email}}","item":"{{item}}"}`
	sc := benchScenario()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			vars := newVars(sc, i)
			_ = renderBody(tmpl, vars)
			putVars(vars)
			i++
		}
	})
}
