package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"stress-strike/internal/config"
)

func TestGateModeFiresSimultaneously(t *testing.T) {
	var hits atomic.Int64
	firstSeen := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			select {
			case firstSeen <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	const users = 25
	sc := &config.Scenario{
		Name: "race-strike",
		Profile: config.Profile{
			Type:     config.ProfileSteady,
			Users:    users,
			Duration: 10,
			Timeout:  3,
			Gate:     true,
		},
		Steps: []config.Step{{Name: "strike", Method: "GET", URL: srv.URL}},
	}

	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tel, err := eng.Run(ctx, RunOptions{Quiet: true})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}

	if got := hits.Load(); got != users {
		t.Errorf("hits = %d, want exactly %d (one strike per user)", got, users)
	}
	if tel.TotalRequests() != users {
		t.Errorf("recorded requests = %d, want %d", tel.TotalRequests(), users)
	}
	if elapsed > 5*time.Second {
		t.Errorf("gate run took %v — workers should fire once and drain fast", elapsed)
	}
}

func TestGateRequiresMultipleUsers(t *testing.T) {
	p := config.Profile{Type: config.ProfileSteady, Users: 1, Duration: 10, Gate: true}
	if err := p.Normalize(); err == nil {
		t.Error("expected error for gate with single user")
	}
}
