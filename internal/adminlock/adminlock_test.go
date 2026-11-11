package adminlock

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// newStore points the admin state store at a throwaway file.
func newStore(t *testing.T, dir, name string) *Store {
	t.Helper()
	return mustStoreOpen(t, filepath.Join(dir, name))
}

func mustStoreOpen(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	return s
}

func TestOpenMissingStateMintsFreshCode(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir, "admin.json")

	st, err := s.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Active {
		t.Error("fresh state must not be active")
	}

	code, err := s.Code()
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if len(code) == 0 {
		t.Fatal("empty admin code minted")
	}
	if len(code) != 9 {
		t.Errorf("code = %q, want 9 chars (8 + separator)", code)
	}
	if code[4] != '-' {
		t.Errorf("code = %q, want separator at index 4", code)
	}

	if _, err := os.Stat(filepath.Join(dir, "admin.json")); err != nil {
		t.Errorf("state file not created: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "admin.json")); err == nil {
		if runtime.GOOS != "windows" {
			// POSIX permission bits do not exist on Windows: the mode is
			// reported as 0666 and only the read-only bit is meaningful.
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("state file mode = %o, want 600", fi.Mode().Perm())
			}
		}
	}
}

func TestOpenMalformedStateIsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.json")
	if err := os.WriteFile(path, []byte(`{not json`), 0o600); err != nil {
		t.Fatalf("seed corrupt state: %v", err)
	}
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("Open on corrupt file = %v, want corrupt error", err)
	}
}

func TestOpenExistingStateKeepsCode(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir, "admin.json")
	first, err := s.Code()
	if err != nil {
		t.Fatalf("Code: %v", err)
	}

	reopened := mustStoreOpen(t, filepath.Join(dir, "admin.json"))
	second, err := reopened.Code()
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if second != first {
		t.Errorf("reopen changed the code: %q -> %q", first, second)
	}
}

func TestVerifyAcceptsNormalizedCode(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir, "admin.json")
	code, err := s.Code()
	if err != nil {
		t.Fatalf("Code: %v", err)
	}

	if ok, err := s.Verify(code); err != nil || !ok {
		t.Fatalf("Verify(correct) = %v, %v", ok, err)
	}
	if ok, err := s.Verify(strings.ToLower(strings.ReplaceAll(code, "-", ""))); err != nil || !ok {
		t.Fatalf("Verify(lowercased/separators-stripped) = %v, %v", ok, err)
	}
	if ok, err := s.Verify("WRONGCODE1"); err != nil || ok {
		t.Fatalf("Verify(wrong) = %v, %v", ok, err)
	}
}

func TestUnlockWrongCodeFailsAndDoesNotOpen(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir, "admin.json")

	if _, err := s.Unlock("WRONGCODE1", 5*time.Minute); err == nil {
		t.Fatalf("Unlock(wrong) = %+v, want error", err)
	}
	if st, err := s.Status(); err != nil || st.Active {
		t.Errorf("window must stay closed after a wrong code: %+v, %v", st, err)
	}
}

func TestUnlockCorrectCodeOpensWindow(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir, "admin.json")
	code, err := s.Code()
	if err != nil {
		t.Fatalf("Code: %v", err)
	}

	before := time.Now().UTC()
	st, err := s.Unlock(code, 5*time.Minute)
	if err != nil {
		t.Fatalf("Unlock(correct): %v", err)
	}
	if !st.Active {
		t.Fatalf("window not active: %+v", st)
	}
	if st.ExpiresAt.IsZero() || st.UnlockedAt.IsZero() {
		t.Fatalf("unlock stamps missing: %+v", st)
	}
	left := time.Until(st.ExpiresAt.UTC())
	if left < 299*time.Second || left > 301*time.Second {
		t.Errorf("seconds left = %v, want ~300", left)
	}
	if st.SecondsLeft < 299 || st.SecondsLeft > 301 {
		t.Errorf("SecondsLeft = %d, want ~300", st.SecondsLeft)
	}
	if before.After(st.ExpiresAt) {
		t.Error("window should start in the future")
	}
}

func TestUnlockClampsTTL(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir, "admin.json")
	code, _ := s.Code()

	if st, err := s.Unlock(code, MaxTTL+time.Hour); err != nil {
		t.Fatalf("Unlock: %v", err)
	} else if st.SecondsLeft > 86400 {
		t.Errorf("TTL not clamped to MaxTTL: %v", st.SecondsLeft)
	}

	if st, err := s.Unlock(code, 0); err != nil {
		t.Fatalf("Unlock(default ttl): %v", err)
	} else if st.SecondsLeft < 14*60 || st.SecondsLeft > 16*60 {
		t.Errorf("default TTL = %v seconds, want ~900", st.SecondsLeft)
	}
}

func TestLockClosesWindow(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir, "admin.json")
	code, _ := s.Code()
	if _, err := s.Unlock(code, 30*time.Minute); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	st, err := s.Lock()
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if st.Active {
		t.Error("window should be closed after Lock")
	}
	if !st.ExpiresAt.IsZero() || !st.UnlockedAt.IsZero() {
		t.Errorf("lock should clear the window: %+v", st)
	}
}

func TestRotateReplacesCodeAndClosesWindow(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir, "admin.json")
	code, _ := s.Code()
	if _, err := s.Unlock(code, 30*time.Minute); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	newCode, err := s.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newCode == code {
		t.Errorf("Rotate returned the same code %q", newCode)
	}
	if ok, err := s.Verify(code); err != nil || ok {
		t.Errorf("old code still verifies: %v, %v", ok, err)
	}
	if ok, err := s.Verify(newCode); err != nil || !ok {
		t.Errorf("new code does not verify: %v, %v", ok, err)
	}
	if st, err := s.Status(); err != nil || st.Active {
		t.Errorf("window should be closed after Rotate: %+v, %v", st, err)
	}
}

func TestStatusWithoutUnlockIsInactive(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir, "admin.json")
	st, err := s.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Active || st.SecondsLeft != 0 {
		t.Errorf("fresh status = %+v, want inactive", st)
	}
}

func TestStatusExpiredWindowIsInactive(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir, "admin.json")
	code, err := s.Code()
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	st := State{
		Code:        code,
		CreatedAt:   time.Now().UTC(),
		UnlockedAt:  time.Now().UTC().Add(-2 * time.Minute),
		UnlockUntil: time.Now().UTC().Add(-time.Minute),
	}
	if err := s.save(st); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got, err := s.Status(); err != nil || got.Active {
		t.Errorf("expired window must be inactive: %+v, %v", got, err)
	}
}

func TestActiveWithoutStateFile(t *testing.T) {
	t.Setenv("STRESS_STRIKE_HOME", t.TempDir())
	if Active() {
		t.Error("Active() must be false when no state file exists")
	}
	if got := CurrentStatus(); got.Active || got.SecondsLeft != 0 {
		t.Errorf("CurrentStatus() = %+v, want zero value", got)
	}
}

func TestActiveWithUnlockedState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("STRESS_STRIKE_HOME", home)
	s := newStore(t, home, "admin.json")
	code, err := s.Code()
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if _, err := s.Unlock(code, 10*time.Minute); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !Active() {
		t.Error("Active() must be true while the window is open")
	}
	st := CurrentStatus()
	if !st.Active || st.SecondsLeft <= 0 {
		t.Errorf("CurrentStatus() = %+v, want active with seconds left", st)
	}
}

func TestStatusJSONShape(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir, "admin.json")
	code, _ := s.Code()
	if _, err := s.Unlock(code, 15*time.Minute); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	st, err := s.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.ExpiresAt.IsZero() {
		t.Fatal("expected expires_at to be set while unlocked")
	}
	if _, err := json.Marshal(st); err != nil {
		t.Fatalf("status must be JSON-encodable: %v", err)
	}
}
