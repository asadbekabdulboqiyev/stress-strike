package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	tep "github.com/asadbekabdulboqiyev/teno-event-protocol/packages/tep-go/tep"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

// TestTepStepPushesSignedEvent runs a full wire round-trip: the engine's
// tepClient forges and signs a TEP envelope, and a real Consumer server
// verifies the HMAC and accepts it. A 200 back proves signature + envelope +
// header wiring all work together.
func TestTepStepPushesSignedEvent(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"

	consumer := tep.NewConsumer([]byte(secret), func(e *tep.Envelope) (tep.TepCode, error) {
		return tep.CodeOK, nil
	})

	var sigHeader string
	pushHandler := consumer.PushHandler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/events/push" {
			sigHeader = r.Header.Get(tep.HeaderSignature)
			pushHandler(w, r)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	e := &Engine{}
	step := config.Step{
		Type:      "tep",
		URL:       srv.URL + "/v1/events/push",
		TepType:   "loadtest.finished",
		TepSecret: secret,
		TepKey:    "stress-strike",
		TepSource: "stress-strike",
		Body:      `{"rps":1200}`,
	}

	res, body := e.tepClient(context.Background(), step, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("unexpected error: %s", res.errName)
	}
	if res.status != 200 {
		t.Fatalf("status = %d, want 200 (consumer verified the HMAC and accepted)", res.status)
	}
	if len(body) == 0 {
		t.Fatal("expected response body to be captured")
	}
	if sigHeader == "" {
		t.Fatal("missing x-tep-signature header on the wire")
	}
}

// TestTepStepBadSecretRejected confirms a mismatched secret is refused by the
// consumer (401 → status_4xx in step terms), surfacing misconfig at run time.
func TestTepStepBadSecretRejected(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"

	consumer := tep.NewConsumer([]byte(secret), func(e *tep.Envelope) (tep.TepCode, error) {
		return tep.CodeOK, nil
	})
	srv := httptest.NewServer(consumer.PushHandler())
	defer srv.Close()

	e := &Engine{}
	step := config.Step{
		Type:      "tep",
		URL:       srv.URL + "/v1/events/push",
		TepType:   "loadtest.finished",
		TepSecret: "ffffffffffffffffffffffffffffffff",
		TepKey:    "stress-strike",
		TepSource: "stress-strike",
	}

	res, _ := e.tepClient(context.Background(), step, 5*time.Second)
	if res.errName != "status_4xx" {
		t.Fatalf("errName = %q, want status_4xx (bad secret must be rejected)", res.errName)
	}
}

func TestTepStepRejectsShortSecretAtConfigTime(t *testing.T) {
	sc := &config.Scenario{Profile: config.Profile{Users: 1}, Steps: []config.Step{{
		Type:      "tep",
		URL:       "http://x/push",
		TepType:   "a.b",
		TepSecret: "short",
	}}}
	if err := sc.Normalize(); err == nil {
		t.Fatal("expected config error for short tep_secret")
	}
}
