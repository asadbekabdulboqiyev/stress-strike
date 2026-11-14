package bounty

// triage_test.go — policy table, append validation and audit replay.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testAt = "2026-11-14T12:00:00Z"

func testEvent(from, to State, role Role) Event {
	return Event{
		At:     testAt,
		Actor:  "alice",
		Role:   role,
		From:   from,
		To:     to,
		Reason: "test transition",
	}
}

func appendOK(t *testing.T, path string, e Event) {
	t.Helper()
	if err := AppendEvent(path, e); err != nil {
		t.Fatalf("AppendEvent(%s -> %s as %s): %v", stateLabel(e.From), e.To, e.Role, err)
	}
}

func TestTransitionTableAllowsEveryListedEdge(t *testing.T) {
	for _, rule := range transitionRules {
		for _, role := range rule.roles {
			if err := Transition(rule.from, rule.to, role); err != nil {
				t.Errorf("listed edge %s -> %s as %s rejected: %v", stateLabel(rule.from), rule.to, role, err)
			}
		}
		// Every role that is not listed for the edge must be denied.
		for _, role := range []Role{RoleReporter, RoleTriager, RoleProgramOwner, RoleAuditor} {
			listed := false
			for _, r := range rule.roles {
				if r == role {
					listed = true
				}
			}
			if listed {
				continue
			}
			if err := Transition(rule.from, rule.to, role); err == nil {
				t.Errorf("unlisted role %s was allowed on %s -> %s", role, stateLabel(rule.from), rule.to)
			}
		}
	}
}

func TestTransitionDeniedEdges(t *testing.T) {
	cases := []struct {
		name string
		from State
		to   State
		role Role
	}{
		{"skip triage", StateSubmitted, StateRewarded, RoleProgramOwner},
		{"backwards", StateTriaged, StateSubmitted, RoleTriager},
		{"terminal rejected", StateRejected, StateTriaged, RoleTriager},
		{"terminal rewarded", StateRewarded, StateAccepted, RoleProgramOwner},
		{"needs_info straight to accepted", StateNeedsInfo, StateAccepted, RoleTriager},
		{"self transition", StateTriaged, StateTriaged, RoleTriager},
		{"auditor writes", StateSubmitted, StateTriaged, RoleAuditor},
		{"reporter triages", StateSubmitted, StateTriaged, RoleReporter},
		{"triager rewards", StateAccepted, StateRewarded, RoleTriager},
		{"unknown role", StateSubmitted, StateTriaged, Role("admin")},
		{"unknown target", StateSubmitted, State("paid"), RoleTriager},
		{"unknown source", State("lost"), StateTriaged, RoleTriager},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Transition(tc.from, tc.to, tc.role); err == nil {
				t.Fatalf("Transition(%q, %q, %q) was allowed", tc.from, tc.to, tc.role)
			}
		})
	}
}

func TestAppendEventAndReplay(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "triage.jsonl")
	digest := strings.Repeat("a", 64)

	events := []Event{
		testEvent(StateNone, StateSubmitted, RoleReporter),
		testEvent(StateSubmitted, StateTriaged, RoleTriager),
		testEvent(StateTriaged, StateNeedsInfo, RoleTriager),
		testEvent(StateNeedsInfo, StateTriaged, RoleReporter),
		testEvent(StateTriaged, StateAccepted, RoleTriager),
		testEvent(StateAccepted, StateRewarded, RoleProgramOwner),
	}
	for _, e := range events {
		e.PackageDigest = digest
		appendOK(t, logPath, e)
	}

	loaded, err := LoadEvents(logPath)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(loaded) != len(events) {
		t.Fatalf("replayed %d events, want %d", len(loaded), len(events))
	}
	state, err := CurrentState(loaded)
	if err != nil {
		t.Fatalf("CurrentState: %v", err)
	}
	if state != StateRewarded {
		t.Fatalf("current state = %q, want rewarded", state)
	}
	if loaded[0].PackageDigest != digest {
		t.Fatalf("package digest not replayed: %q", loaded[0].PackageDigest)
	}

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("log mode is %o, want 600", got)
	}
}

func TestAppendEventRejectsInvalidTransitionBeforeWriting(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "triage.jsonl")
	appendOK(t, logPath, testEvent(StateNone, StateSubmitted, RoleReporter))

	before, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}

	denied := []struct {
		name string
		e    Event
	}{
		{"reporter cannot triage", testEvent(StateSubmitted, StateTriaged, RoleReporter)},
		{"triager cannot reward", testEvent(StateSubmitted, StateRewarded, RoleProgramOwner)},
		{"auditor cannot move", testEvent(StateSubmitted, StateTriaged, RoleAuditor)},
	}
	for _, tc := range denied {
		if err := AppendEvent(logPath, tc.e); err == nil {
			t.Fatalf("%s: AppendEvent accepted a denied transition", tc.name)
		}
	}

	after, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log after denied appends: %v", err)
	}
	if before.Size() != after.Size() {
		t.Fatalf("denied transitions changed the log: %d -> %d bytes", before.Size(), after.Size())
	}
}

func TestAppendEventRejectsBadFieldsWithoutCreatingFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "triage.jsonl")

	bad := []Event{
		{At: testAt, Actor: "", Role: RoleReporter, From: StateNone, To: StateSubmitted, Reason: "x"},
		{At: testAt, Actor: "  ", Role: RoleReporter, From: StateNone, To: StateSubmitted, Reason: "x"},
		{At: testAt, Actor: "alice", Role: RoleReporter, From: StateNone, To: StateSubmitted, Reason: "  "},
		{At: testAt, Actor: "alice", Role: RoleReporter, From: StateNone, To: StateSubmitted, Reason: strings.Repeat("r", maxReasonBytes+1)},
		{At: "yesterday", Actor: "alice", Role: RoleReporter, From: StateNone, To: StateSubmitted, Reason: "x"},
		{At: testAt, Actor: "alice", Role: Role("admin"), From: StateNone, To: StateSubmitted, Reason: "x"},
		{At: testAt, Actor: "alice", Role: RoleReporter, From: StateNone, To: StateSubmitted, Reason: "x", PackageDigest: "deadbeef"},
	}
	for i, e := range bad {
		if err := AppendEvent(logPath, e); err == nil {
			t.Errorf("case %d: AppendEvent accepted an invalid event", i)
		}
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("invalid events created the log file (stat err = %v)", err)
	}
}

func TestAppendEventFirstEventMustBeSubmission(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "triage.jsonl")
	e := testEvent(StateNone, StateTriaged, RoleTriager)
	if err := AppendEvent(logPath, e); err == nil {
		t.Fatal("AppendEvent accepted a workflow that starts at triaged")
	}

	// Even a structurally valid edge is rejected when the log is empty and the
	// event does not start the workflow.
	e = testEvent(StateSubmitted, StateTriaged, RoleTriager)
	if err := AppendEvent(logPath, e); err == nil {
		t.Fatal("AppendEvent accepted a non-submission first event")
	}
}

func TestAppendEventRejectsBrokenChain(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "triage.jsonl")
	appendOK(t, logPath, testEvent(StateNone, StateSubmitted, RoleReporter))
	appendOK(t, logPath, testEvent(StateSubmitted, StateTriaged, RoleTriager))

	before, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}

	// The log is at triaged; an event claiming submitted as its source must be
	// rejected.
	stale := testEvent(StateSubmitted, StateAccepted, RoleTriager)
	if err := AppendEvent(logPath, stale); err == nil {
		t.Fatal("AppendEvent accepted an event that does not continue the chain")
	}

	after, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log after rejected append: %v", err)
	}
	if before.Size() != after.Size() {
		t.Fatal("a rejected append changed the log")
	}
}

func TestAppendEventRejectsDigestChange(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "triage.jsonl")
	first := testEvent(StateNone, StateSubmitted, RoleReporter)
	first.PackageDigest = strings.Repeat("a", 64)
	appendOK(t, logPath, first)

	second := testEvent(StateSubmitted, StateTriaged, RoleTriager)
	second.PackageDigest = strings.Repeat("b", 64)
	if err := AppendEvent(logPath, second); err == nil {
		t.Fatal("AppendEvent accepted an event for a different package")
	}
}

func TestLoadEventsRejectsMalformedLogs(t *testing.T) {
	validFirst := `{"at":"2026-11-14T12:00:00Z","actor":"alice","role":"reporter","from":"","to":"submitted","reason":"received"}`

	cases := []struct {
		name    string
		content string
	}{
		{"bad json", `{"at":`},
		{"unknown field", `{"at":"2026-11-14T12:00:00Z","actor":"alice","role":"reporter","from":"","to":"submitted","reason":"x","extra":1}`},
		{"first not submitted", `{"at":"2026-11-14T12:00:00Z","actor":"alice","role":"triager","from":"submitted","to":"triaged","reason":"x"}`},
		{"first starts elsewhere", `{"at":"2026-11-14T12:00:00Z","actor":"alice","role":"triager","from":"","to":"triaged","reason":"x"}`},
		{"chain gap", validFirst + "\n" + `{"at":"2026-11-14T12:00:00Z","actor":"bob","role":"triager","from":"needs_info","to":"triaged","reason":"x"}` + "\n"},
		{"empty line in middle is tolerated", validFirst + "\n\n"},
		{"bad role", validFirst + "\n" + `{"at":"2026-11-14T12:00:00Z","actor":"bob","role":"admin","from":"submitted","to":"triaged","reason":"x"}` + "\n"},
		{"digest change", `{"at":"2026-11-14T12:00:00Z","actor":"alice","role":"reporter","from":"","to":"submitted","reason":"x","package_digest":"` + strings.Repeat("a", 64) + `"}` + "\n" + `{"at":"2026-11-14T12:00:00Z","actor":"bob","role":"triager","from":"submitted","to":"triaged","reason":"x","package_digest":"` + strings.Repeat("b", 64) + `"}` + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "triage.jsonl")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write log: %v", err)
			}
			_, err := LoadEvents(path)
			if tc.name == "empty line in middle is tolerated" {
				if err != nil {
					t.Fatalf("LoadEvents rejected a trailing blank line: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("LoadEvents accepted a malformed log")
			}
		})
	}
}

func TestLoadEventsMissingFile(t *testing.T) {
	_, err := LoadEvents(filepath.Join(t.TempDir(), "absent.jsonl"))
	if err == nil {
		t.Fatal("LoadEvents accepted a missing file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing log error does not wrap os.ErrNotExist: %v", err)
	}
}

func TestCurrentStateEmpty(t *testing.T) {
	state, err := CurrentState(nil)
	if err != nil {
		t.Fatalf("CurrentState(nil): %v", err)
	}
	if state != StateNone {
		t.Fatalf("state = %q, want the empty state", state)
	}
}

func TestStateTerminal(t *testing.T) {
	terminal := []State{StateRejected, StateDuplicate, StateRewarded}
	open := []State{StateSubmitted, StateTriaged, StateNeedsInfo, StateAccepted}
	for _, s := range terminal {
		if !s.Terminal() {
			t.Errorf("%q should be terminal", s)
		}
	}
	for _, s := range open {
		if s.Terminal() {
			t.Errorf("%q should not be terminal", s)
		}
	}
}
