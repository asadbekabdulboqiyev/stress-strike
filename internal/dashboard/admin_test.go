package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/adminlock"
)

func resetAdminThrottleForTest() func() {
	adminAttempts.reset()
	return adminAttempts.reset
}

func adminStatusViaHandler(t *testing.T, method, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	switch path {
	case "/api/admin/status":
		(&Server{}).handleAdminStatus(w, req)
	case "/api/admin/unlock":
		(&Server{}).handleAdminUnlock(w, req)
	case "/api/admin/lock":
		(&Server{}).handleAdminLock(w, req)
	default:
		t.Fatalf("unknown admin path %q", path)
	}
	return w
}

func TestAdminStatusGetOK(t *testing.T) {
	resetAdminThrottleForTest()()
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())

	w := adminStatusViaHandler(t, http.MethodGet, "/api/admin/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var payload adminStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Configured {
		t.Error("configured must be false for a fresh state file")
	}
	if payload.Active || payload.SecondsLeft != 0 {
		t.Errorf("fresh status = %+v, want inactive", payload)
	}
	if payload.Hint == "" {
		t.Error("status payload should carry the operator hint")
	}
}

func TestAdminStatusMethodNotAllowed(t *testing.T) {
	resetAdminThrottleForTest()()
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())

	w := adminStatusViaHandler(t, http.MethodPost, "/api/admin/status", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestAdminUnlockRequiresCode(t *testing.T) {
	resetAdminThrottleForTest()()
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())

	w := adminStatusViaHandler(t, http.MethodPost, "/api/admin/unlock", `{"code":"","minutes":15}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty code status = %d, want 400: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "admin code required") {
		t.Errorf("body = %s, want admin-code-required message", w.Body.String())
	}
}

func TestAdminUnlockRejectsWrongCode(t *testing.T) {
	resetAdminThrottleForTest()()
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())

	w := adminStatusViaHandler(t, http.MethodPost, "/api/admin/unlock", `{"code":"WRONGCODE1","minutes":15}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong code status = %d, want 403: %s", w.Code, w.Body.String())
	}
}

func TestAdminUnlockOpensWindowForCorrectCode(t *testing.T) {
	resetAdminThrottleForTest()()
	home := t.TempDir()
	t.Setenv("STRESS_STRIKE_HOME", home)
	store, err := adminlock.Open(adminlock.DefaultPath())
	if err != nil {
		t.Fatalf("open admin store: %v", err)
	}
	code, err := store.Code()
	if err != nil {
		t.Fatalf("code: %v", err)
	}

	w := adminStatusViaHandler(t, http.MethodPost, "/api/admin/unlock", `{"code":"`+code+`","minutes":15}`)
	if w.Code != http.StatusOK {
		t.Fatalf("unlock status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var unlockResp struct {
		Status adminStatusResponse `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &unlockResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if unlockResp.Status.Active != true || unlockResp.Status.SecondsLeft < 14*60 {
		t.Errorf("unlocked status = %+v, want active with ~15m left", unlockResp.Status)
	}

	w = adminStatusViaHandler(t, http.MethodGet, "/api/admin/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var payload adminStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !payload.Configured {
		t.Error("configured must be true once the admin state file exists")
	}
	if !payload.Active || payload.SecondsLeft < 14*60 {
		t.Errorf("status = %+v, want active bypass window", payload)
	}
}

func TestAdminUnlockClampsMinutes(t *testing.T) {
	resetAdminThrottleForTest()()
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())
	store, err := adminlock.Open(adminlock.DefaultPath())
	if err != nil {
		t.Fatalf("open admin store: %v", err)
	}
	code, err := store.Code()
	if err != nil {
		t.Fatalf("code: %v", err)
	}

	// minutes <= 0 falls back to the documented default (15).
	w := adminStatusViaHandler(t, http.MethodPost, "/api/admin/unlock", `{"code":"`+code+`","minutes":0}`)
	if w.Code != http.StatusOK {
		t.Fatalf("unlock(default minutes) = %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status struct {
			SecondsLeft int64 `json:"seconds_left"`
		} `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status.SecondsLeft < 14*60 || resp.Status.SecondsLeft > 16*60 {
		t.Errorf("default minutes window = %d, want ~900", resp.Status.SecondsLeft)
	}

	adminAttempts.reset()
	// minutes above the maximum are clamped to 24h.
	w = adminStatusViaHandler(t, http.MethodPost, "/api/admin/unlock", `{"code":"`+code+`","minutes":5000}`)
	if w.Code != http.StatusOK {
		t.Fatalf("unlock(max minutes) = %d: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status.SecondsLeft > 86400 {
		t.Errorf("clamped window = %d, want <= 86400", resp.Status.SecondsLeft)
	}
}

func TestAdminLockClosesWindow(t *testing.T) {
	resetAdminThrottleForTest()()
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())
	store, err := adminlock.Open(adminlock.DefaultPath())
	if err != nil {
		t.Fatalf("open admin store: %v", err)
	}
	code, err := store.Code()
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if w := adminStatusViaHandler(t, http.MethodPost, "/api/admin/unlock", `{"code":"`+code+`","minutes":30}`); w.Code != http.StatusOK {
		t.Fatalf("unlock = %d: %s", w.Code, w.Body.String())
	}

	w := adminStatusViaHandler(t, http.MethodPost, "/api/admin/lock", "")
	if w.Code != http.StatusOK {
		t.Fatalf("lock = %d: %s", w.Code, w.Body.String())
	}
	var payload adminStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Active || payload.SecondsLeft != 0 {
		t.Errorf("after lock status = %+v, want inactive", payload)
	}
}

func TestHumanSecondsDash(t *testing.T) {
	cases := map[int64]string{
		0:     "0s",
		45:    "45s",
		60:    "1m",
		90:    "1m 30s",
		125:   "2m 5s",
		86399: "1439m 59s",
	}
	for sec, want := range cases {
		if got := humanSecondsDash(sec); got != want {
			t.Errorf("humanSecondsDash(%d) = %q, want %q", sec, got, want)
		}
	}
}
