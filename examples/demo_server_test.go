package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The YAML scenario files are not code; the only executable in examples/ is
// demo_server.go, whose HTTP handlers are exercised here with httptest
// recorders — no sockets, no network traffic.

func TestDemoHealth(t *testing.T) {
	rec := httptest.NewRecorder()
	handleHealth(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("health body = %q, want \"ok\"", rec.Body.String())
	}
}

func TestDemoFailAlways500(t *testing.T) {
	rec := httptest.NewRecorder()
	handleFail(rec, httptest.NewRequest(http.MethodGet, "/fail", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("fail status = %d, want 500", rec.Code)
	}
}

func TestDemoLogin(t *testing.T) {
	// Valid credentials -> 200 with a token.
	valid := httptest.NewRecorder()
	handleLogin(valid, httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(`{"username":"user1","password":"pass1"}`)))
	if valid.Code != http.StatusOK {
		t.Fatalf("valid login status = %d, want 200", valid.Code)
	}
	var body struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(valid.Body.Bytes(), &body); err != nil {
		t.Fatalf("valid login body not JSON: %v (%s)", err, valid.Body.String())
	}
	if body.Data.Token != "tok-user1" {
		t.Errorf("token = %q, want tok-user1", body.Data.Token)
	}

	// Wrong password -> 401.
	bad := httptest.NewRecorder()
	handleLogin(bad, httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(`{"username":"user1","password":"nope"}`)))
	if bad.Code != http.StatusUnauthorized {
		t.Errorf("bad login status = %d, want 401", bad.Code)
	}

	// GET is not allowed -> 405.
	method := httptest.NewRecorder()
	handleLogin(method, httptest.NewRequest(http.MethodGet, "/api/login", nil))
	if method.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET login status = %d, want 405", method.Code)
	}

	// Malformed body -> 400.
	malformed := httptest.NewRecorder()
	handleLogin(malformed, httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader("not-json{")))
	if malformed.Code != http.StatusBadRequest {
		t.Errorf("malformed login status = %d, want 400", malformed.Code)
	}
}

func TestDemoProfileRequiresToken(t *testing.T) {
	noAuth := httptest.NewRecorder()
	handleProfile(noAuth, httptest.NewRequest(http.MethodGet, "/api/profile", nil))
	if noAuth.Code != http.StatusUnauthorized {
		t.Errorf("profile without token status = %d, want 401", noAuth.Code)
	}

	withAuth := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer tok-user")
	handleProfile(withAuth, req)
	if withAuth.Code != http.StatusOK {
		t.Errorf("profile with token status = %d, want 200", withAuth.Code)
	}
}

func TestDemoCartAndCheckout(t *testing.T) {
	for _, path := range []string{"/api/cart", "/api/checkout"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer tok-user")
		switch path {
		case "/api/cart":
			handleCart(rec, req)
		case "/api/checkout":
			handleCheckout(rec, req)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200", path, rec.Code)
		}
	}
}
