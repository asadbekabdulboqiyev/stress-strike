// Package adminlock stores the local operator's admin code and the temporary
// authorization bypass it unlocks.
//
// The bypass is deliberately narrow and visible:
//
//   - it is gated by a code that exists only on this machine (0600 state file),
//   - it expires (15 minutes by default) unless it is extended,
//   - it never unlocks cloud instance-metadata addresses (the credential-theft
//     path) — callers must still refuse those,
//   - every unlock and lock is an audit event the CLI and dashboard both write
//     to the same hash-chained trail.
//
// It is a maintenance switch for the person sitting at the machine, not a
// remote backdoor.
package adminlock

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
)

// DefaultTTL is how long one unlock lasts when the caller asks for no specific
// duration.
const DefaultTTL = 15 * time.Minute

// MaxTTL caps an unlock so a forgotten toggle cannot become permanent.
const MaxTTL = 24 * time.Hour

// codeAlphabet omits characters that are easy to confuse when read from a
// terminal (0/O, 1/I/L, 5/S).
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

const codeLen = 8

// State is the on-disk record.
type State struct {
	Code        string    `json:"code"`
	CreatedAt   time.Time `json:"created_at"`
	UnlockedAt  time.Time `json:"unlocked_at,omitempty"`
	UnlockUntil time.Time `json:"unlock_until,omitempty"`
}

// Status is what the UI needs: never the code itself.
type Status struct {
	Active     bool      `json:"active"`
	UnlockedAt time.Time `json:"unlocked_at,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	SecondsLeft int64    `json:"seconds_left"`
}

// Store reads and writes the state file.
type Store struct {
	path string
}

// DefaultPath is the admin state file next to the authorization policy.
func DefaultPath() string {
	return filepath.Join(authz.ConfigHome(), "admin.json")
}

// Open loads (or creates) the store at path. A missing file creates a fresh
// code; a malformed file is reported instead of silently replaced, so an
// operator does not lose an unlock because of a typo.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	st, err := s.load()
	if err == nil {
		if st.Code == "" {
			if err := s.regenerate(); err != nil {
				return nil, err
			}
		}
		return s, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := s.regenerate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path reports where the state lives.
func (s *Store) Path() string { return s.path }

func (s *Store) load() (State, error) {
	var st State
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return st, err
	}
	if len(raw) == 0 {
		return st, nil
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return State{}, fmt.Errorf("admin state %s is corrupt: %w (delete it to issue a new code)", s.path, err)
	}
	return st, nil
}

func (s *Store) save(st State) error {
	dir := filepath.Dir(s.path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create admin state directory: %w", err)
		}
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(s.path)+".tmp*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

func (s *Store) regenerate() error {
	code, err := newCode()
	if err != nil {
		return err
	}
	return s.save(State{Code: code, CreatedAt: time.Now().UTC()})
}

// newCode returns a human-readable code like "K7QM-3XPA".
func newCode() (string, error) {
	buf := make([]byte, codeLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate admin code: %w", err)
	}
	out := make([]byte, 0, codeLen+1)
	for i, b := range buf {
		if i == codeLen/2 {
			out = append(out, '-')
		}
		out = append(out, codeAlphabet[int(b)%len(codeAlphabet)])
	}
	return string(out), nil
}

// Code returns the current admin code.
func (s *Store) Code() (string, error) {
	st, err := s.load()
	if err != nil {
		return "", err
	}
	if st.Code == "" {
		if err := s.regenerate(); err != nil {
			return "", err
		}
		return s.Code()
	}
	return st.Code, nil
}

// Rotate replaces the code and drops any active unlock. A rotated code is the
// "someone else saw it" recovery step.
func (s *Store) Rotate() (string, error) {
	if err := s.regenerate(); err != nil {
		return "", err
	}
	return s.Code()
}

// Status reports the current unlock window.
func (s *Store) Status() (Status, error) {
	st, err := s.load()
	if err != nil {
		return Status{}, err
	}
	return statusOf(st, time.Now()), nil
}

func statusOf(st State, now time.Time) Status {
	out := Status{UnlockedAt: st.UnlockedAt, ExpiresAt: st.UnlockUntil}
	if !st.UnlockUntil.IsZero() && now.Before(st.UnlockUntil) {
		out.Active = true
		out.SecondsLeft = int64(st.UnlockUntil.Sub(now).Seconds())
		if out.SecondsLeft < 0 {
			out.SecondsLeft = 0
		}
	}
	return out
}
// Verify reports whether code matches the stored code.
func (s *Store) Verify(code string) (bool, error) {
	st, err := s.load()
	if err != nil {
		return false, err
	}
	want := normalize(st.Code)
	got := normalize(code)
	if want == "" || got == "" {
		return false, nil
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1, nil
}

// Unlock verifies code and opens a bypass window. ttl is clamped to (0, MaxTTL];
// zero means DefaultTTL. The audit trail is the caller's job (it knows whether
// the request came from the CLI or the dashboard).
func (s *Store) Unlock(code string, ttl time.Duration) (Status, error) {
	ok, err := s.Verify(code)
	if err != nil {
		return Status{}, err
	}
	if !ok {
		return Status{}, errors.New("admin code does not match — run `stress-strike admin code` on the host to read the current code")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl > MaxTTL {
		ttl = MaxTTL
	}
	st, err := s.load()
	if err != nil {
		return Status{}, err
	}
	now := time.Now().UTC()
	st.UnlockedAt = now
	st.UnlockUntil = now.Add(ttl)
	if err := s.save(st); err != nil {
		return Status{}, err
	}
	return statusOf(st, time.Now()), nil
}

// Lock closes the bypass window immediately.
func (s *Store) Lock() (Status, error) {
	st, err := s.load()
	if err != nil {
		return Status{}, err
	}
	st.UnlockUntil = time.Time{}
	st.UnlockedAt = time.Time{}
	if err := s.save(st); err != nil {
		return Status{}, err
	}
	return statusOf(st, time.Now()), nil
}

// normalize upper-cases a code and drops separators so "k7qm-3xpa" and
// "K7QM3XPA" both work.
func normalize(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(code)) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Active reports whether a bypass window is open for the default store. It is
// the hot path used by every authorization decision: an unreadable or missing
// state file means "not active", never an error that blocks a scan. It never
// creates the state file, so a plain scan does not mint an admin code.
func Active() bool {
	raw, err := os.ReadFile(DefaultPath())
	if err != nil || len(raw) == 0 {
		return false
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return false
	}
	return statusOf(st, time.Now()).Active
}

// CurrentStatus reports the bypass window of the default store without
// creating it.
func CurrentStatus() Status {
	raw, err := os.ReadFile(DefaultPath())
	if err != nil || len(raw) == 0 {
		return Status{}
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return Status{}
	}
	return statusOf(st, time.Now())
}
