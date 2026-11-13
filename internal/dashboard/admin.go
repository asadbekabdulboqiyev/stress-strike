package dashboard

// Admin area: the local bypass switch behind an admin code.
//
// The routes are ordinary JSON endpoints on the same loopback dashboard, and
// they only ever touch local state:
//
//	GET  /api/admin/status   {configured, active, seconds_left, expires_at}
//	POST /api/admin/unlock   {code, minutes}  → opens the window
//	POST /api/admin/lock                       → closes it
//
// The code itself is never sent to the browser. The operator reads it with
// `Sift admin code` on the host and types it in. Failed attempts are
// throttled so a script cannot brute-force an 8-character code through the
// dashboard, and every switch change lands in the same audit trail as scans.

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/adminlock"
	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

const (
	maxAdminBody     = 4 << 10
	adminMaxFailures = 5
	adminLockoutTime = 2 * time.Minute
	adminDefaultMins = 15
	adminMaxMins     = 24 * 60
)

// adminThrottle slows repeated wrong codes. One dashboard process serves one
// operator, so a single counter is enough.
type adminThrottle struct {
	mu       sync.Mutex
	failures int
	until    time.Time
}

var adminAttempts adminThrottle

func (t *adminThrottle) blocked(now time.Time) (bool, int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Before(t.until) {
		return true, int64(t.until.Sub(now).Seconds()) + 1
	}
	return false, 0
}

func (t *adminThrottle) fail(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures++
	if t.failures >= adminMaxFailures {
		t.until = now.Add(adminLockoutTime)
		t.failures = 0
	}
}

func (t *adminThrottle) reset() {
	t.mu.Lock()
	t.failures = 0
	t.until = time.Time{}
	t.mu.Unlock()
}

type adminStatusResponse struct {
	Configured  bool   `json:"configured"`
	Active      bool   `json:"active"`
	SecondsLeft int64  `json:"seconds_left"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	UnlockedAt  string `json:"unlocked_at,omitempty"`
	Hint        string `json:"hint,omitempty"`
}

func adminStatusPayload() adminStatusResponse {
	st := adminlock.CurrentStatus()
	out := adminStatusResponse{
		Configured:  adminStateExists(),
		Active:      st.Active,
		SecondsLeft: st.SecondsLeft,
		Hint:        "Run `Sift admin code` on the host to read the code. The code is never sent to the browser.",
	}
	if !st.ExpiresAt.IsZero() {
		out.ExpiresAt = st.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if !st.UnlockedAt.IsZero() {
		out.UnlockedAt = st.UnlockedAt.UTC().Format(time.RFC3339)
	}
	return out
}

func adminStateExists() bool {
	_, err := os.Stat(adminlock.DefaultPath())
	return err == nil
}

func (s *Server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(adminStatusPayload())
}

type adminUnlockRequest struct {
	Code    string `json:"code"`
	Minutes int    `json:"minutes"`
}

func (s *Server) handleAdminUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}

	now := time.Now()
	if blocked, secs := adminAttempts.blocked(now); blocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":       "too many wrong codes — try again later",
			"retry_after": secs,
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	var req adminUnlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Minutes <= 0 {
		req.Minutes = adminDefaultMins
	}
	if req.Minutes > adminMaxMins {
		req.Minutes = adminMaxMins
	}

	store, err := adminlock.Open(adminlock.DefaultPath())
	if err != nil {
		adminAttempts.fail(now)
		writeAdminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The code is the gate. An empty code is rejected instead of falling back
	// to the stored one: a fallback would let any local HTTP client open the
	// bypass without ever reading the code from the host.
	code := strings.TrimSpace(req.Code)
	if code == "" {
		adminAttempts.fail(now)
		writeAdminError(w, http.StatusBadRequest,
			"admin code required — run `Sift admin code` on the host and enter it here")
		return
	}
	st, err := store.Unlock(code, time.Duration(req.Minutes)*time.Minute)
	if err != nil {
		adminAttempts.fail(now)
		writeAdminError(w, http.StatusForbidden, err.Error())
		return
	}
	adminAttempts.reset()

	auditAdminSwitch("admin-unlock", true, "bypass window opened for "+humanSecondsDash(st.SecondsLeft))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  adminStatusPayload(),
		"warning": "Admin bypass is ON: scans run without an authorization ticket until " + st.ExpiresAt.Local().Format("15:04:05") + ". Cloud metadata stays denied.",
	})
}

func (s *Server) handleAdminLock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	if !adminStateExists() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": adminStatusPayload()})
		return
	}
	store, err := adminlock.Open(adminlock.DefaultPath())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := store.Lock(); err != nil {
		writeAdminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	adminAttempts.reset()
	auditAdminSwitch("admin-lock", true, "bypass window closed")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  adminStatusPayload(),
		"warning": "",
	})
}

func writeAdminError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// auditAdminSwitch records a switch change in the shared hash-chained trail, so
// `Sift audit show` explains why a later scan needed no ticket.
func auditAdminSwitch(rule string, allowed bool, reason string) {
	_ = owaspAudit(authz.Entry{
		Actor:   "dashboard-admin",
		Action:  "admin",
		Targets: []string{"local"},
		Class:   "local",
		Allowed: allowed,
		Rule:    rule,
		Reason:  reason,
	})
}

func humanSecondsDash(sec int64) string {
	if sec <= 0 {
		return "0s"
	}
	if sec < 60 {
		return strconv.FormatInt(sec, 10) + "s"
	}
	m := sec / 60
	s := sec % 60
	if s == 0 {
		return strconv.FormatInt(m, 10) + "m"
	}
	return strconv.FormatInt(m, 10) + "m " + strconv.FormatInt(s, 10) + "s"
}
