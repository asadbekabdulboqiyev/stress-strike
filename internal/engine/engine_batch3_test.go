package engine

import (
	"context"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

// ============================================================================
// Load profiles — concurrency curves
// ============================================================================

func TestSteadyProfileCurve(t *testing.T) {
	p := &steadyProfile{users: 50, dur: 30 * time.Second}
	if p.ConcurrencyAt(0) != 50 || p.ConcurrencyAt(15*time.Second) != 50 || p.ConcurrencyAt(29*time.Second) != 50 {
		t.Fatal("steady profile must pin concurrency")
	}
	if p.MaxConcurrency() != 50 || p.Duration() != 30*time.Second {
		t.Fatal("steady metadata off")
	}
}

func TestRampProfileCurve(t *testing.T) {
	type tc struct {
		name string
		at   time.Duration
		want int
	}
	cases := []tc{
		{"at start", 0, 1},
		{"quarter ramp", 25 * time.Second, 12},
		{"mid ramp", 50 * time.Second, 25},
		{"three-quarter", 75 * time.Second, 37},
		{"past ramp", 100 * time.Second, 50},
		{"way past", 10 * time.Minute, 50},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &rampProfile{users: 50, ramp: 100 * time.Second, dur: 120 * time.Second}
			if got := p.ConcurrencyAt(c.at); got != c.want {
				t.Fatalf("ramp at %v = %d, want %d", c.at, got, c.want)
			}
		})
	}
}

func TestSpikeProfileCurve(t *testing.T) {
	p := &spikeProfile{baseline: 5, spikeUsers: 80, warmup: 10 * time.Second, hold: 10 * time.Second}
	// During warmup: baseline.
	if p.ConcurrencyAt(0) != 5 || p.ConcurrencyAt(9*time.Second) != 5 {
		t.Fatal("baseline during warmup")
	}
	// During hold: spike.
	if p.ConcurrencyAt(15*time.Second) != 80 {
		t.Fatal("spike during hold")
	}
	// After hold: settle back to baseline.
	if p.ConcurrencyAt(30*time.Second) != 5 {
		t.Fatal("baseline after hold")
	}
	if p.MaxConcurrency() != 80 {
		t.Fatal("spike max")
	}
}

func TestWaveProfileCurve(t *testing.T) {
	p := &waveProfile{users: 100, period: 10 * time.Second, dur: 40 * time.Second}
	// Peaks at phase = Pi/2 (elapsed = period/4); troughs at (3/4)period.
	if p.ConcurrencyAt(0) != 50 {
		t.Fatalf("wave at 0 = %d, want 50", p.ConcurrencyAt(0))
	}
	if got := p.ConcurrencyAt((10 * time.Second) / 4); got < 99 || got > 100 {
		t.Fatalf("wave peak = %d, want ~100", got)
	}
	if got := p.ConcurrencyAt((3 * 10 * time.Second) / 4); got < 1 || got > 2 {
		t.Fatalf("wave trough = %d, want 1", got)
	}
	// Never above users:
	for i := 0; i < 40; i++ {
		if n := p.ConcurrencyAt(time.Duration(i) * time.Second); n < 1 || n > 100 {
			t.Fatalf("wave out of range at %ds: %d", i, n)
		}
	}
	if p.MaxConcurrency() != 100 || p.Duration() != 40*time.Second {
		t.Fatal("wave metadata off")
	}
}

// ============================================================================
// Constant-RPS ramp curve
// ============================================================================

func TestConstantRPSTargetRampTable(t *testing.T) {
	p := newConstantRPSProfile(1000, 10, 60*time.Second)
	type tc struct {
		name string
		at   time.Duration
		want int
	}
	cases := []tc{
		{"ramp start above zero", 0, 1},
		{"2s into 10s ramp", 2 * time.Second, 200},
		{"half ramp", 5 * time.Second, 500},
		{"just before ramp end", 9 * time.Second, 900},
		{"at ramp end full", 10 * time.Second, 1000},
		{"past ramp full", 30 * time.Second, 1000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := p.TargetRPSAt(c.at); got != c.want {
				t.Fatalf("TargetRPSAt(%v)=%d, want %d", c.at, got, c.want)
			}
		})
	}
	if p.IsConstantRPS() != true || p.Duration() != 60*time.Second || p.MaxConcurrency() != 1000 {
		t.Fatal("constant-rps metadata off")
	}
}

func TestConstantRPSDefaultRamp(t *testing.T) {
	// Ramp defaults to half of a 4s duration, floor 1s.
	p := newConstantRPSProfile(100, 0, 4*time.Second)
	if p.RampDuration() != 2*time.Second {
		t.Fatalf("default ramp = %v, want 2s", p.RampDuration())
	}
	short := newConstantRPSProfile(100, 0, time.Second)
	if short.RampDuration() != time.Second {
		t.Fatalf("short dur ramp = %v, want 1s floor", short.RampDuration())
	}
}

// ============================================================================
// buildProfile dispatch
// ============================================================================

func TestBuildProfileDispatchTable(t *testing.T) {
	type tc struct {
		name    string
		profile config.Profile
		wantDur time.Duration
	}
	cases := []tc{
		{"steady", config.Profile{Type: config.ProfileSteady, Users: 10, Duration: 20}, 20 * time.Second},
		{"soak", config.Profile{Type: config.ProfileSoak, Users: 10, Duration: 20}, 20 * time.Second},
		{"linear ramp", config.Profile{Type: config.ProfileLinearRamp, Users: 10, RampUp: 5, Duration: 20}, 20 * time.Second},
		{"spike", config.Profile{Type: config.ProfileSpike, Users: 5, SpikeUsers: 50, SpikeWarmup: 10, SpikeHold: 10, Duration: 30}, 20 * time.Second},
		{"wave", config.Profile{Type: config.ProfileWave, Users: 10, WavePeriod: 3, Duration: 30}, 30 * time.Second},
		{"constant rps", config.Profile{Type: config.ProfileConstantRPS, TargetRPS: 500, Duration: 30}, 30 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := buildProfile(c.profile)
			if err != nil {
				t.Fatal(err)
			}
			if p.Duration() != c.wantDur {
				t.Fatalf("duration = %v, want %v", p.Duration(), c.wantDur)
			}
			if p.MaxConcurrency() < 1 {
				t.Fatalf("max concurrency %d < 1", p.MaxConcurrency())
			}
		})
	}
}

func TestBuildProfileUnsupported(t *testing.T) {
	if _, err := buildProfile(config.Profile{Type: "quantum-burst"}); err == nil {
		t.Fatal("unsupported profile type must error")
	}
}

// ============================================================================
// Token bucket — throttle integrity
// ============================================================================

func TestTokenBucketAllowsUpToBurst(t *testing.T) {
	// Burst of 3: three wait() calls return instantly, fourth blocks.
	b := newTokenBucket(3)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		start := time.Now()
		if err := b.wait(ctx); err != nil {
			t.Fatal(err)
		}
		if time.Since(start) > 200*time.Millisecond {
			t.Fatalf("call %d blocked despite burst budget", i)
		}
	}
	// Fourth must yield instantly-ready flag via ctx; run with tiny timeout.
	tctx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	if err := b.wait(tctx); err == nil {
		t.Fatal("burst exceeded: wait returned despite zero tokens")
	}
}

func TestTokenBucketRefillRate(t *testing.T) {
	// 10 rps => initially full (10 tokens). Drain the burst, then the next
	// batch of 5 must be paced at ~0.5s (one token / 100ms).
	b := newTokenBucket(10)
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if err := b.wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := b.wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	took := time.Since(start).Seconds()
	if took < 0.3 || took > 1.5 {
		t.Fatalf("5 paced waits took %.2fs, expected ~0.5s", took)
	}
}

func TestTokenBucketBurstCapsAtInitial(t *testing.T) {
	// Burst equals the initial rate. After full drain, idling longer than
	// burst/rate seconds must not let more than `burst` tokens accumulate.
	b := newTokenBucket(20) // burst 20, so 1.3s of idle would yield 26 uncapped
	for i := 0; i < 20; i++ {
		_ = b.wait(context.Background())
	}
	time.Sleep(1300 * time.Millisecond)
	for i := 0; i < 20; i++ {
		if err := b.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// 21st token must NOT be available: burst ceiling caps accumulation at 20
	// (uncapped idling would have banked 26). At 20/s the 21st needs ~50ms.
	tctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := b.wait(tctx); err == nil {
		t.Fatal("burst ceiling ignored: more than 20 tokens accumulated")
	}
}

func TestTokenBucketSetRateZeroBlocks(t *testing.T) {
	b := newTokenBucket(0) // zero-rate ramp
	tctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	if err := b.wait(tctx); err == nil {
		t.Fatal("zero-rate bucket returned a token")
	}
	// Raising the rate unblocks it.
	b.setRate(1000)
	start := time.Now()
	if err := b.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("bucket did not unblock after setRate")
	}
}

func TestTokenBucketNegativeClamped(t *testing.T) {
	b := newTokenBucket(-5)
	tctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := b.wait(tctx); err == nil {
		t.Fatal("negative rate produced a token")
	}
	b.setRate(-1)
	if err := b.wait(tctx2(t)); err == nil {
		t.Fatal("setRate(negative) produced a token")
	}
}

func tctx2(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)
	return c
}

func TestTokenBucketContextCancellation(t *testing.T) {
	b := newTokenBucket(1)
	_ = b.wait(context.Background()) // drain
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(80 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if err := b.wait(ctx); err == nil {
		t.Fatal("cancelled wait returned a token")
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("cancel surfaced too fast %v", elapsed)
	}
}

func TestTokenBucketSetRateIncreaseCeiling(t *testing.T) {
	b := newTokenBucket(1)
	_ = b.wait(context.Background()) // drain the single token
	b.setRate(5)                     // raise ceiling to 5
	time.Sleep(1200 * time.Millisecond)
	// Refill would be 6s*5=30 uncapped; ceiling caps at 5 -> 5 instant, 6th blocks.
	for i := 0; i < 5; i++ {
		if err := b.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	tctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := b.wait(tctx); err == nil {
		t.Fatal("raised ceiling exceeded: more than 5 tokens accumulated")
	}
}

// ============================================================================
// Variables rendering
// ============================================================================

func TestRenderPlaceholderTable(t *testing.T) {
	vars := map[string]string{
		"user": "user3", "id": "3", "item": "item3",
	}
	type tc struct {
		name string
		tmpl string
		want string
	}
	cases := []tc{
		{"exact", "{{user}}", "user3"},
		{"with spaces", "{{ user }}", "user3"},
		{"inline", "u={{id}}-x", "u=3-x"},
		{"unknown preserved", "{{nope}}", "{{nope}}"},
		{"mixed", "item={{item}};user={{user}}", "item=item3;user=user3"},
		{"no placeholders untouched", "plain path", "plain path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := render(c.tmpl, vars); got != c.want {
				t.Fatalf("render(%q) = %q, want %q", c.tmpl, got, c.want)
			}
		})
	}
}

func TestNewVarsPerUser(t *testing.T) {
	sc := &config.Scenario{Variables: map[string]string{"env": "prod"}}
	v1 := newVars(sc, 0)
	v2 := newVars(sc, 1)
	if v1["user"] != "user1" || v2["user"] != "user2" {
		t.Fatalf("user vars: %q vs %q", v1["user"], v2["user"])
	}
	if v1["id"] != "1" || v2["id"] != "2" {
		t.Fatalf("id vars: %q vs %q", v1["id"], v2["id"])
	}
	if v1["email"] != "user1@test.local" {
		t.Fatalf("email var: %q", v1["email"])
	}
	if v1["env"] != "prod" {
		t.Fatal("scenario variables not inherited")
	}
}

// ============================================================================
// Assertion engine
// ============================================================================

func TestAssertionStatusClassTable(t *testing.T) {
	body := []byte(`{}`)
	type tc struct {
		name   string
		want   string
		code   int
		passes bool
	}
	cases := []tc{
		{"exact 200", "200", 200, true},
		{"exact 404", "404", 404, true},
		{"exact mismatch", "200", 201, false},
		{"2xx wildcard", "2xx", 299, true},
		{"4xx wildcard", "4xx", 404, true},
		{"4xx rejected 200", "4xx", 200, false},
		{"5xx wildcard", "5xx", 503, true},
		{"20x wildcard", "20x", 209, true},
		{"20x rejected 210", "20x", 210, false},
		{"3xx wildcard", "3xx", 302, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkAssertions([]config.Assertion{{Type: "status", Value: c.want}}, c.code, body)
			if c.passes && err != nil {
				t.Fatalf("%s matched status %d: unexpected error %v", c.want, c.code, err)
			}
			if !c.passes && err == nil {
				t.Fatalf("%s wrongly accepted status %d", c.want, c.code)
			}
		})
	}
}

func TestAssertionBodyRules(t *testing.T) {
	body := []byte(`{"data":{"token":"abc123"},"ok":true}`)
	type tc struct {
		name    string
		asserts []config.Assertion
		passes  bool
	}
	cases := []tc{
		{"json path present", []config.Assertion{{Type: "json_path", Value: "data.token"}}, true},
		{"json path absent", []config.Assertion{{Type: "json_path", Value: "data.missing"}}, false},
		{"regex hit", []config.Assertion{{Type: "regex", Value: `"ok":true`}}, true},
		{"regex miss", []config.Assertion{{Type: "regex", Value: `"ok":false`}}, false},
		{"regex numeric hit", []config.Assertion{{Type: "regex", Value: `abc123`}}, true},
		{"regex numeric miss", []config.Assertion{{Type: "regex", Value: `zzz`}}, false},
		{"compound all pass", []config.Assertion{{Type: "status", Value: "200"}, {Type: "regex", Value: "abc123"}}, true},
		{"compound one fails", []config.Assertion{{Type: "status", Value: "200"}, {Type: "regex", Value: "zzz"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkAssertions(c.asserts, 200, body)
			if c.passes && err != nil {
				t.Fatalf("assertions should pass: %v", err)
			}
			if !c.passes && err == nil {
				t.Fatal("assertions should fail")
			}
		})
	}
}

// Combine several failure modes into one goroutine-safe smoke.
func TestAssertionUnknownTypeErrors(t *testing.T) {
	if err := checkAssertions([]config.Assertion{{Type: "bogus"}}, 200, nil); err == nil {
		t.Fatal("unknown assertion type must error")
	}
}
