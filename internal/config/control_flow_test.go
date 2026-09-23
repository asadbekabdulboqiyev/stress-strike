package config

import (
	"strconv"
	"strings"
	"testing"
)

// ---- Condition parsing / evaluation ----

func TestParseConditionFormats(t *testing.T) {
	cases := []struct {
		expr    string
		wantVar string
		wantOp  string
		wantVal string
	}{
		{"${login_status} == 200", "login_status", "==", "200"},
		{"{{token}} != ''", "token", "!=", ""},
		{`${host} contains "api-"`, "host", "contains", "api-"},
		{"${trace} =~ ^[0-9a-f]{32}$", "trace", "=~", "^[0-9a-f]{32}$"},
		{"bare == 1", "bare", "==", "1"},
		{`${msg} == "hello world"`, "msg", "==", "hello world"},
		{`${msg} == 'single quoted'`, "msg", "==", "single quoted"},
	}
	for _, tc := range cases {
		c, err := ParseCondition(tc.expr)
		if err != nil {
			t.Errorf("ParseCondition(%q) error: %v", tc.expr, err)
			continue
		}
		if c.Var != tc.wantVar || c.Op != tc.wantOp || c.Expected != tc.wantVal {
			t.Errorf("ParseCondition(%q) = {%q %q %q}, want {%q %q %q}",
				tc.expr, c.Var, c.Op, c.Expected, tc.wantVar, tc.wantOp, tc.wantVal)
		}
	}
}

func TestParseConditionInvalid(t *testing.T) {
	for _, expr := range []string{"", "   ", "noop", "a b c", "${a} ==", "${a} != ", "a === b", "${a} > 5", "${} == 1"} {
		if _, err := ParseCondition(expr); err == nil {
			t.Errorf("ParseCondition(%q) expected error", expr)
		}
	}
}

func TestParseConditionInvalidRegex(t *testing.T) {
	if _, err := ParseCondition("${a} =~ [unclosed"); err == nil {
		t.Error("expected error for unclosed regex")
	}
}

func TestConditionEval(t *testing.T) {
	vars := map[string]string{
		"status": "200",
		"token":  "abc123",
		"host":   "api-prod-1",
		"empty":  "",
		"price":  "9.5",
	}
	cases := []struct {
		expr string
		want bool
	}{
		{"${status} == 200", true},
		{"${status} == 201", false},
		{"${price} == 9.5", true},
		{"${price} == 9.5000", true}, // numeric comparison
		{"${status} != 500", true},
		{"${token} != ''", true},
		{"${empty} == ''", true},
		{`${host} contains "prod"`, true},
		{`${host} contains "dev"`, false},
		{"${token} =~ ^abc[0-9]+$", true},
		{"${token} =~ ^zzz$", false},
		// Missing variable → false for every operator.
		{"${missing} == 200", false},
		{"${missing} != 200", false},
		{`${missing} contains "x"`, false},
		{"${missing} =~ .*", false},
	}
	for _, tc := range cases {
		c, err := ParseCondition(tc.expr)
		if err != nil {
			t.Fatalf("ParseCondition(%q): %v", tc.expr, err)
		}
		if got := c.Eval(vars); got != tc.want {
			t.Errorf("Eval(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}
}

// ---- stop_on_status matcher ----

func TestParseStatusMatcher(t *testing.T) {
	cases := []struct {
		spec      string
		wantLower int
		wantUpper int
		wantErr   bool
	}{
		{"", 0, 0, false},
		{"2xx", 200, 299, false},
		{"3xx", 300, 399, false},
		{"4xx", 400, 499, false},
		{"5xx", 500, 599, false},
		{"429", 429, 429, false},
		{"200", 200, 200, false},
		{"6xx", 0, 0, true},
		{"0xx", 0, 0, true},
		{"abc", 0, 0, true},
		{"42", 0, 0, true}, // out of range
		{"700", 0, 0, true},
	}
	for _, tc := range cases {
		lo, hi, err := parseStatusMatcher(tc.spec)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseStatusMatcher(%q) expected error", tc.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseStatusMatcher(%q) error: %v", tc.spec, err)
			continue
		}
		if lo != tc.wantLower || hi != tc.wantUpper {
			t.Errorf("parseStatusMatcher(%q) = [%d,%d], want [%d,%d]",
				tc.spec, lo, hi, tc.wantLower, tc.wantUpper)
		}
	}
}

// ---- Step normalization ----

func TestNormalizeControlFlowDefaults(t *testing.T) {
	sc := &Scenario{
		Profile: Profile{Users: 1, Duration: 2, Timeout: 5},
		Steps:   []Step{{Name: "s", URL: "/x", Type: "http"}},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}
	st := sc.Steps[0]
	if st.OnError != "stop" {
		t.Errorf("on_error default = %q, want stop", st.OnError)
	}
	if st.StopStatusLower != 0 || st.StopStatusUpper != 0 {
		t.Errorf("empty stop_on_status should compile to 0/0, got %d/%d", st.StopStatusLower, st.StopStatusUpper)
	}
}

func TestNormalizeControlFlowValidation(t *testing.T) {
	cases := []struct {
		name    string
		step    Step
		wantErr string
	}{
		{"bad think_time", Step{Name: "s", URL: "/x", ThinkTime: -1}, "think_time"},
		{"bad retries", Step{Name: "s", URL: "/x", Retries: -2}, "retries"},
		{"bad backoff", Step{Name: "s", URL: "/x", RetryBackoff: -0.5}, "retry_backoff"},
		{"bad on_error", Step{Name: "s", URL: "/x", OnError: "maybe"}, "on_error"},
		{"bad stop_on_status", Step{Name: "s", URL: "/x", StopOnStatus: "7xx"}, "7xx"},
	}
	for _, tc := range cases {
		sc := &Scenario{Profile: Profile{Users: 1, Duration: 2, Timeout: 5}, Steps: []Step{tc.step}}
		err := sc.Normalize()
		if err == nil {
			t.Errorf("%s: expected error", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestNormalizeStopOnStatusCompiled(t *testing.T) {
	sc := &Scenario{
		Profile: Profile{Users: 1, Duration: 2, Timeout: 5},
		Steps: []Step{
			{Name: "a", URL: "/a", StopOnStatus: "429"},
			{Name: "b", URL: "/b", StopOnStatus: "5xx"},
		},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}
	if lo, hi := sc.Steps[0].StopStatusLower, sc.Steps[0].StopStatusUpper; lo != 429 || hi != 429 {
		t.Errorf("a: compiled [%d,%d], want [429,429]", lo, hi)
	}
	if lo, hi := sc.Steps[1].StopStatusLower, sc.Steps[1].StopStatusUpper; lo != 500 || hi != 599 {
		t.Errorf("b: compiled [%d,%d], want [500,599]", lo, hi)
	}
}

func TestNormalizeIfStep(t *testing.T) {
	sc := &Scenario{
		Profile: Profile{Users: 1, Duration: 2, Timeout: 5},
		Steps: []Step{{
			Name:      "branch",
			Type:      "if",
			Condition: "${login_status} == 200",
			Steps: []Step{
				{Name: "inner", URL: "/dashboard", Type: "http"},
			},
		}},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}
	br := sc.Steps[0]
	if br.Cond == nil || br.Cond.Var != "login_status" || br.Cond.Op != "==" {
		t.Errorf("if step condition not parsed: %+v", br.Cond)
	}
	if br.StopStatusLower != 0 {
		t.Errorf("if step default stop_on_status should be disabled")
	}
	inner := br.Steps[0]
	if inner.Name != "inner" || inner.Method != "GET" || inner.Type != "http" {
		t.Errorf("nested step not normalized: %+v", inner)
	}
	if inner.OnError != "stop" {
		t.Errorf("nested on_error default = %q, want stop", inner.OnError)
	}
}

func TestNormalizeIfStepNestedControlFlow(t *testing.T) {
	sc := &Scenario{
		Profile: Profile{Users: 1, Duration: 2, Timeout: 5},
		Steps: []Step{{
			Name:      "branch",
			Type:      "if",
			Condition: "${token} != ''",
			ThinkTime: 0.25,
			Steps: []Step{{
				Name:         "inner",
				URL:          "/x",
				Type:         "http",
				ThinkTime:    0.1,
				Retries:      2,
				RetryBackoff: 0.2,
				OnError:      "continue",
				StopOnStatus: "429",
			}},
		}},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}
	br := sc.Steps[0]
	if br.ThinkTime != 0.25 {
		t.Errorf("if think_time = %v, want 0.25", br.ThinkTime)
	}
	inner := br.Steps[0]
	if inner.Retries != 2 || inner.RetryBackoff != 0.2 || inner.OnError != "continue" {
		t.Errorf("nested control flow not preserved: %+v", inner)
	}
	if lo, hi := inner.StopStatusLower, inner.StopStatusUpper; lo != 429 || hi != 429 {
		t.Errorf("nested stop_on_status compiled [%d,%d], want [429,429]", lo, hi)
	}
}

func TestNormalizeIfStepMissingCondition(t *testing.T) {
	sc := &Scenario{
		Profile: Profile{Users: 1, Duration: 2, Timeout: 5},
		Steps:   []Step{{Name: "b", Type: "if", Steps: []Step{{Name: "i", URL: "/x"}}}},
	}
	err := sc.Normalize()
	if err == nil || !strings.Contains(err.Error(), "condition") {
		t.Fatalf("expected condition error, got %v", err)
	}
}

func TestNormalizeIfStepMissingSteps(t *testing.T) {
	sc := &Scenario{
		Profile: Profile{Users: 1, Duration: 2, Timeout: 5},
		Steps:   []Step{{Name: "b", Type: "if", Condition: "${a} == 1"}},
	}
	err := sc.Normalize()
	if err == nil || !strings.Contains(err.Error(), "nested step") {
		t.Fatalf("expected nested-step error, got %v", err)
	}
}

func TestNormalizeIfStepBadCondition(t *testing.T) {
	sc := &Scenario{
		Profile: Profile{Users: 1, Duration: 2, Timeout: 5},
		Steps:   []Step{{Name: "b", Type: "if", Condition: "nonsense here", Steps: []Step{{Name: "i", URL: "/x"}}}},
	}
	if err := sc.Normalize(); err == nil {
		t.Fatal("expected invalid condition error")
	}
}

func TestNormalizeIfStepTooDeep(t *testing.T) {
	leaf := Step{Name: "leaf", URL: "/x"}
	top := Step{Name: "i0", Type: "if", Condition: "${a} == 1", Steps: []Step{leaf}}
	for i := 1; i <= maxStepNesting+1; i++ {
		top = Step{Name: "i" + strconv.Itoa(i), Type: "if", Condition: "${a} == 1", Steps: []Step{top}}
	}
	sc := &Scenario{Profile: Profile{Users: 1, Duration: 2, Timeout: 5}, Steps: []Step{top}}
	if err := sc.Normalize(); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("expected nesting-depth error, got %v", err)
	}
}

// ---- gRPC streaming validation ----

func TestNormalizeGrpcStreamAlias(t *testing.T) {
	sc := &Scenario{
		Profile: Profile{Users: 1, Duration: 2, Timeout: 5},
		Steps: []Step{{
			Name:       "ingest",
			Type:       "grpc-stream",
			URL:        "grpc://localhost:50051",
			GrpcMethod: "/ingest.Service/IngestEvents",
		}},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}
	st := sc.Steps[0]
	if st.Type != "grpc" || !st.GrpcStream {
		t.Errorf("grpc-stream alias: Type=%q GrpcStream=%v, want grpc/true", st.Type, st.GrpcStream)
	}
}

func TestNormalizeGrpcStreamRequiresMethod(t *testing.T) {
	cases := []Step{
		{Name: "s", Type: "grpc-stream", URL: "grpc://h"},
		{Name: "s", Type: "grpc", URL: "grpc://h", GrpcStream: true, GrpcMethod: ""},
	}
	for _, step := range cases {
		sc := &Scenario{Profile: Profile{Users: 1, Duration: 2, Timeout: 5}, Steps: []Step{step}}
		err := sc.Normalize()
		if err == nil || !strings.Contains(err.Error(), "grpc_method") {
			t.Errorf("step %+v: expected grpc_method error, got %v", step, err)
		}
	}
}

func TestNormalizeGrpcStreamOnNonGrpc(t *testing.T) {
	sc := &Scenario{
		Profile: Profile{Users: 1, Duration: 2, Timeout: 5},
		Steps:   []Step{{Name: "s", Type: "http", URL: "/x", GrpcStream: true}},
	}
	err := sc.Normalize()
	if err == nil || !strings.Contains(err.Error(), "only valid on grpc") {
		t.Fatalf("expected grpc-only error, got %v", err)
	}
}

// ---- Burst profile ----

func TestProfileBurstTransform(t *testing.T) {
	p := Profile{Type: ProfileBurst, Users: 500}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	if p.Type != ProfileSteady {
		t.Errorf("burst type = %q, want steady", p.Type)
	}
	if p.Duration != 3 {
		t.Errorf("burst default duration = %d, want 3", p.Duration)
	}
	if p.Users != 500 {
		t.Errorf("burst users = %d, want 500", p.Users)
	}
	if p.Gate {
		t.Error("burst must not enable gate (gate is a one-shot volley)")
	}
}

func TestProfileBurstKeepsExplicitDuration(t *testing.T) {
	p := Profile{Type: ProfileBurst, Users: 50, Duration: 10}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	if p.Duration != 10 {
		t.Errorf("burst duration = %d, want 10", p.Duration)
	}
}

func TestProfileHTTP2DefaultEnabled(t *testing.T) {
	p := Profile{Type: ProfileSteady, Users: 1, Duration: 2}
	if !p.HTTP2Enabled() {
		t.Error("HTTP2Enabled() should default to true (nil)")
	}
	on := true
	p.Http2 = &on
	if !p.HTTP2Enabled() {
		t.Error("HTTP2Enabled() with explicit true should be true")
	}
	off := false
	p.Http2 = &off
	if p.HTTP2Enabled() {
		t.Error("HTTP2Enabled() with explicit false should be false")
	}
}
