package engine

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

// renderRef is the regexp implementation render replaced. It is kept here as
// the oracle for TestRenderMatchesRegexpReference: the hand-written scan has
// to accept exactly the same grammar and produce byte-identical output, and the
// only way to be sure that stays true as either side is edited is to hold both
// of them to the same cases.
func renderRef(tmpl string, vars map[string]string) string {
	if !strings.Contains(tmpl, "{{") {
		return tmpl
	}
	return placeholderRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		key := placeholderRe.FindStringSubmatch(m)[1]
		if v, ok := vars[key]; ok {
			return v
		}
		return m
	})
}

func TestRenderMatchesRegexpReference(t *testing.T) {
	vars := map[string]string{
		"user": "user7",
		"id":   "7",
		"item": "item7",
		"a":    "A",
		"a.b":  "dotted",
		"a-b":  "dashed",
		"a_b":  "underscored",
		"a1":   "digit",
		"UPPER": "up",
		"":     "empty-value",
	}
	cases := []string{
		"{{user}}",
		"{{ user }}",
		"{{  user  }}",
		"\t{{user}}\t",
		"\n{{user}}\n",
		"{{user}}{{user}}",
		"a{{user}}b{{id}}c",
		"plain",
		"",
		"{{",
		"}}",
		"{{}}",
		"{{ }}",
		"{{  }}",
		"{{unknown}}",
		"{{user}}{{unknown}}{{id}}",
		"{{a.b}}",
		"{{a-b}}",
		"{{a_b}}",
		"{{a1}}",
		"{{UPPER}}",
		"{{}}extra",
		"{{ }user}",
		"{{user",
		"user}}",
		"{{user}}}",
		"{{{user}}}",
		"{{{{user}}}}",
		"{{-user-}}",
		"{{.user}}",
		"{{user.}}",
		"{{_}}",
		"{{.}}",
		"{{-}}",
		"http://host/api/{{id}}/x?a={{user}}&b={{item}}",
		"{{a}} {{b}} {{a}}",
		"prefix {{unknown}} suffix {{user}}",
		"{{user}}{{",
		"{{{{",
		"}}}}",
		"{{user}\n}",
		"{{\nuser\n}}",
		"{{\r\nuser}}",
		"{{user\t}}\n",
		"no placeholder at all",
		"{{user}}{",
		"}{{{user}}}{",
	}
	for _, tmpl := range cases {
		t.Run(strconv.Quote(tmpl), func(t *testing.T) {
			want := renderRef(tmpl, vars)
			got := render(tmpl, vars)
			if got != want {
				t.Fatalf("render(%q) = %q, reference = %q", tmpl, got, want)
			}
		})
	}
}

// TestRenderFuzzAgainstReference drives both implementations with randomly
// generated templates built from placeholder-ish fragments. Hand-written
// scanners and regexps disagree most easily on malformed input and on
// overlapping delimiters, which is exactly what random fragment assembly
// produces in volume.
func TestRenderFuzzAgainstReference(t *testing.T) {
	pieces := []string{
		"{{", "}}", "{", "}", "{{user}}", "{{ id }}", "{{unknown}}", "{{a.b}}",
		"{{-x-}}", "{{_}}", "user", "id", "abc", " ", "\t", "\n", "/", "?", "&",
		"=", ".-_", "123", "{{a b}}", "{{ }}", "a{{b}}c",
	}
	vars := map[string]string{"user": "u1", "id": "2", "a.b": "dot", "a-b": "dsh", "a_b": "und", "a1": "d1"}
	rng := rand.New(rand.NewSource(20260901))
	for i := 0; i < 20000; i++ {
		n := 1 + rng.Intn(8)
		var sb strings.Builder
		for j := 0; j < n; j++ {
			sb.WriteString(pieces[rng.Intn(len(pieces))])
		}
		tmpl := sb.String()
		want := renderRef(tmpl, vars)
		got := render(tmpl, vars)
		if got != want {
			t.Fatalf("iteration %d: render(%q) = %q, reference = %q", i, tmpl, got, want)
		}
	}
}

// TestNewVarsPoolIsolation guards the pooling change. newVars hands out a
// recycled map, so a stale key left behind by a previous user would silently
// leak one virtual user's values into another's request.
func TestNewVarsPoolIsolation(t *testing.T) {
	sc := &config.Scenario{Variables: map[string]string{"env": "prod"}}
	const n = 500
	seen := make([]map[string]string, n)
	for i := 0; i < n; i++ {
		seen[i] = newVars(sc, i)
		if seen[i]["env"] != "prod" {
			t.Fatalf("iteration %d lost scenario variable: %v", i, seen[i])
		}
		want := "user" + strconv.Itoa(i+1)
		if seen[i]["user"] != want {
			t.Fatalf("iteration %d: user = %q, want %q", i, seen[i]["user"], want)
		}
	}
	// Pool reuse: after the maps are returned, later calls must still be clean.
	for i := 0; i < n; i++ {
		putVars(seen[i])
	}
	for i := 0; i < n; i++ {
		v := newVars(sc, i+n)
		want := "user" + strconv.Itoa(i+n+1)
		if v["user"] != want {
			t.Fatalf("after reuse, iteration %d: user = %q, want %q", i, v["user"], want)
		}
		for k := range v {
			if k != "env" && k != "user" && k != "pass" && k != "email" && k != "item" && k != "id" {
				t.Fatalf("stale key %q survived pool reuse", k)
			}
		}
		putVars(v)
	}
}

// TestNewVarsPoolConcurrent exercises the pool from many goroutines, which is
// how it is actually used: one iteration per virtual user, running in parallel.
func TestNewVarsPoolConcurrent(t *testing.T) {
	sc := &config.Scenario{Variables: map[string]string{"env": "prod"}}
	const goroutines, per = 32, 200
	errCh := make(chan string, goroutines*per)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				idx := g*per + i
				v := newVars(sc, idx)
				want := "user" + strconv.Itoa(idx+1)
				if v["user"] != want {
					errCh <- fmt.Sprintf("goroutine %d: user = %q, want %q", g, v["user"], want)
					return
				}
				if v["email"] != want+"@test.local" {
					errCh <- fmt.Sprintf("goroutine %d: email = %q", g, v["email"])
					return
				}
				putVars(v)
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Fatal(msg)
	}
}

// TestBodyRegexpCaching verifies the compiled-pattern cache returns the same
// compiled regexp and reports the same error as a fresh compile, including
// for an invalid pattern that must not be retried on every request.
func TestBodyRegexpCaching(t *testing.T) {
	re1, err1 := bodyRegexp(`id["']?\s*:\s*(\d+)`)
	re2, err2 := bodyRegexp(`id["']?\s*:\s*(\d+)`)
	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected errors: %v / %v", err1, err2)
	}
	if re1 != re2 {
		t.Fatal("cache returned a different compiled regexp for the same pattern")
	}
	if got := re1.FindSubmatch([]byte(`{"id": 42}`)); len(got) != 2 || string(got[1]) != "42" {
		t.Fatalf("cached regexp did not match: %q", got)
	}

	// An invalid pattern must keep failing, with the same wrapped message.
	_, badErr := bodyRegexp(`([unclosed`)
	_, badErr2 := bodyRegexp(`([unclosed`)
	if badErr == nil || badErr2 == nil {
		t.Fatal("invalid pattern unexpectedly compiled")
	}
	if badErr.Error() != badErr2.Error() {
		t.Fatalf("cached error differs: %q vs %q", badErr, badErr2)
	}
}

