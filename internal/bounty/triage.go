package bounty

// triage.go — the append-only triage state machine.
//
// A triage log is a JSONL file of events. Each event names the state it moves
// from and to, the actor, the actor's role, a reason, and the package digest it
// concerns. The log is append-only in the operating-system sense
// (O_APPEND|O_CREATE, mode 0600) and the chain is validated on read: the first
// event must submit the report, and every later event must start where the
// previous one ended.
//
// The log is not a distributed ledger. A single writer appends one line at a
// time; AppendEvent validates the chain by reading the log before opening it
// for append, so two concurrent writers can both pass validation and interleave.
// That is a documented limitation, not an accident: deployments that need
// multi-writer safety must serialize append through one process or anchor the
// log externally. For the single-operator workflow this package targets, the
// fail-closed validation before the write is the useful property.
//
// Roles are policy, not identity: this package does not authenticate anyone.
// A deployment must establish that the actor claiming the triager role really
// is one; here the role only decides which transitions the workflow accepts.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// State is one stage of the triage workflow. StateNone ("") is the state before
// a report has been submitted; it is never stored as a "to" state.
type State string

const (
	// StateNone is the absence of a triage state. It is used only as the "from"
	// value of the first event.
	StateNone State = ""
	// StateSubmitted means the report and its package were received.
	StateSubmitted State = "submitted"
	// StateTriaged means a human has reviewed the report and formed an opinion.
	StateTriaged State = "triaged"
	// StateNeedsInfo means triage is blocked on the reporter.
	StateNeedsInfo State = "needs_info"
	// StateAccepted means the report is confirmed as a valid finding.
	StateAccepted State = "accepted"
	// StateRejected means the report is not a valid finding.
	StateRejected State = "rejected"
	// StateDuplicate means the finding duplicates another report.
	StateDuplicate State = "duplicate"
	// StateRewarded means a human decided the accepted report earned a reward.
	// This is an audit outcome, not a payment instruction.
	StateRewarded State = "rewarded"
)

// Valid reports whether s is a defined, storable state.
func (s State) Valid() bool {
	switch s {
	case StateSubmitted, StateTriaged, StateNeedsInfo, StateAccepted, StateRejected, StateDuplicate, StateRewarded:
		return true
	}
	return false
}

// Terminal reports whether s has no outgoing transitions.
func (s State) Terminal() bool {
	switch s {
	case StateRejected, StateDuplicate, StateRewarded:
		return true
	}
	return false
}

// Role is the capacity in which an actor acts. Roles are not identities: the
// caller is responsible for authenticating the actor.
type Role string

const (
	// RoleReporter is the party that submitted the report.
	RoleReporter Role = "reporter"
	// RoleTriager reviews reports and decides their validity.
	RoleTriager Role = "triager"
	// RoleProgramOwner owns the program and authorises rewards.
	RoleProgramOwner Role = "program_owner"
	// RoleAuditor observes. Auditors may read the log but never move a report.
	RoleAuditor Role = "auditor"
)

// Valid reports whether r is a defined role.
func (r Role) Valid() bool {
	switch r {
	case RoleReporter, RoleTriager, RoleProgramOwner, RoleAuditor:
		return true
	}
	return false
}

// transitionRule is one allowed edge and the roles permitted to take it.
type transitionRule struct {
	from  State
	to    State
	roles []Role
}

// transitionRules is the complete, explicit policy. Anything not listed here
// is denied, including every self-transition.
var transitionRules = []transitionRule{
	// A reporter, triager or owner may submit. A bare report with no workflow
	// history is the normal first event.
	{StateNone, StateSubmitted, []Role{RoleReporter, RoleTriager, RoleProgramOwner}},

	// A triager (or owner) picks a fresh report up.
	{StateSubmitted, StateTriaged, []Role{RoleTriager, RoleProgramOwner}},
	{StateSubmitted, StateNeedsInfo, []Role{RoleTriager, RoleProgramOwner}},
	{StateSubmitted, StateRejected, []Role{RoleTriager, RoleProgramOwner}},
	{StateSubmitted, StateDuplicate, []Role{RoleTriager, RoleProgramOwner}},

	// A triaged report can be resolved, or sent back for clarification.
	{StateTriaged, StateNeedsInfo, []Role{RoleTriager, RoleProgramOwner}},
	{StateTriaged, StateAccepted, []Role{RoleTriager, RoleProgramOwner}},
	{StateTriaged, StateRejected, []Role{RoleTriager, RoleProgramOwner}},
	{StateTriaged, StateDuplicate, []Role{RoleTriager, RoleProgramOwner}},

	// The reporter answers a needs_info request; triage resumes.
	{StateNeedsInfo, StateTriaged, []Role{RoleReporter, RoleTriager, RoleProgramOwner}},
	{StateNeedsInfo, StateRejected, []Role{RoleTriager, RoleProgramOwner}},

	// Only the program owner authorises a reward, and only for an accepted
	// report. Accepted findings can still be rejected on later review.
	{StateAccepted, StateRewarded, []Role{RoleProgramOwner}},
	{StateAccepted, StateRejected, []Role{RoleTriager, RoleProgramOwner}},
}

// allowedRoles returns the roles permitted to take from -> to, or nil.
func allowedRoles(from, to State) []Role {
	for _, rule := range transitionRules {
		if rule.from == from && rule.to == to {
			return rule.roles
		}
	}
	return nil
}

// Transition validates one edge against the policy. It is deliberately strict:
// an unknown state, an unknown role, a self-transition or a missing rule is an
// error, never a silent no-op.
func Transition(from, to State, role Role) error {
	if !role.Valid() {
		return fmt.Errorf("bounty: unknown role %q", string(role))
	}
	if to == StateNone || !to.Valid() {
		return fmt.Errorf("bounty: unknown target state %q", string(to))
	}
	if from != StateNone && !from.Valid() {
		return fmt.Errorf("bounty: unknown source state %q", string(from))
	}
	if from == to {
		return fmt.Errorf("bounty: %q -> %q is not a transition", string(from), string(to))
	}
	roles := allowedRoles(from, to)
	if roles == nil {
		return fmt.Errorf("bounty: transition %q -> %q is not allowed", stateLabel(from), string(to))
	}
	for _, r := range roles {
		if r == role {
			return nil
		}
	}
	return fmt.Errorf("bounty: role %q may not move a report from %q to %q", string(role), stateLabel(from), string(to))
}

// stateLabel renders StateNone as "<new>" for error messages.
func stateLabel(s State) string {
	if s == StateNone {
		return "<new>"
	}
	return string(s)
}

const (
	maxActorBytes     = 256
	maxReasonBytes    = 4096
	maxEventLogBytes  = 64 << 20
	maxEventLineBytes = 64 << 10
)

// Event is one append-only triage record.
type Event struct {
	// At is the event time in RFC3339. AppendEvent fills it when empty.
	At string `json:"at"`
	// Actor is the authenticated identity the caller vouches for.
	Actor string `json:"actor"`
	// Role is the capacity the actor acted in.
	Role Role `json:"role"`
	// From is the previous state; empty for the first event.
	From State `json:"from"`
	// To is the resulting state.
	To State `json:"to"`
	// Reason explains the move. Never empty: an unexplained state change is
	// not an audit record.
	Reason string `json:"reason"`
	// PackageDigest ties the event to a specific package.
	PackageDigest string `json:"package_digest,omitempty"`
}

// Validate checks shape and policy. Transition history is validated by
// LoadEvents/CurrentState, which must also accept events written under an older
// policy; this method is the strict writer-side check.
func (e Event) Validate() error {
	if err := e.validateShape(); err != nil {
		return err
	}
	return Transition(e.From, e.To, e.Role)
}

// validateShape checks the fields a replay must trust regardless of policy.
func (e Event) validateShape() error {
	if _, err := time.Parse(time.RFC3339Nano, e.At); err != nil {
		return fmt.Errorf("bounty: event at %q is not RFC3339: %w", e.At, err)
	}
	if !utf8.ValidString(e.Actor) {
		return errors.New("bounty: event actor is not valid UTF-8")
	}
	actor := strings.TrimSpace(e.Actor)
	if actor == "" {
		return errors.New("bounty: event actor is empty")
	}
	if len(e.Actor) > maxActorBytes {
		return fmt.Errorf("bounty: event actor exceeds %d bytes", maxActorBytes)
	}
	if strings.ContainsRune(e.Actor, 0) {
		return errors.New("bounty: event actor contains a NUL byte")
	}
	if !e.Role.Valid() {
		return fmt.Errorf("bounty: event role %q is unknown", string(e.Role))
	}
	if e.From != StateNone && !e.From.Valid() {
		return fmt.Errorf("bounty: event source state %q is unknown", string(e.From))
	}
	if e.To == StateNone || !e.To.Valid() {
		return fmt.Errorf("bounty: event target state %q is unknown", string(e.To))
	}
	if !utf8.ValidString(e.Reason) {
		return errors.New("bounty: event reason is not valid UTF-8")
	}
	if strings.TrimSpace(e.Reason) == "" {
		return errors.New("bounty: event reason is empty")
	}
	if len(e.Reason) > maxReasonBytes {
		return fmt.Errorf("bounty: event reason exceeds %d bytes", maxReasonBytes)
	}
	if strings.ContainsRune(e.Reason, 0) {
		return errors.New("bounty: event reason contains a NUL byte")
	}
	if e.PackageDigest != "" && !isLowerHex(e.PackageDigest, 64) {
		return errors.New("bounty: event package_digest is not a 64 character lowercase hex digest")
	}
	return nil
}

// AppendEvent validates e (including the policy edge and the existing log's
// continuity) and then appends one JSON line to path. Validation happens before
// the file is opened for writing, so a denied transition leaves the log
// untouched.
func AppendEvent(path string, e Event) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("bounty: triage log path is required")
	}
	if e.At == "" {
		e.At = time.Now().UTC().Format(time.RFC3339)
	}
	if err := e.Validate(); err != nil {
		return err
	}

	events, err := LoadEvents(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		events = nil
	}

	if len(events) == 0 {
		if e.From != StateNone || e.To != StateSubmitted {
			return fmt.Errorf(
				"bounty: the first triage event must be %q -> %q, got %q -> %q",
				stateLabel(StateNone), StateSubmitted, e.From, e.To)
		}
	} else {
		last := events[len(events)-1]
		if e.From != last.To {
			return fmt.Errorf("bounty: event starts at %q but the log ends at %q", stateLabel(e.From), last.To)
		}
		if last.PackageDigest != "" && e.PackageDigest != last.PackageDigest {
			return fmt.Errorf("bounty: event package digest %q does not match the log's %q", e.PackageDigest, last.PackageDigest)
		}
	}

	return appendEventLine(path, e)
}

// appendEventLine writes exactly one encoded event. The single Write call plus
// O_APPEND is the documented safe approach for this workflow.
func appendEventLine(path string, e Event) error {
	cleanPath := filepath.Clean(path)
	f, err := os.OpenFile(cleanPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- path is an operator-selected triage log
	if err != nil {
		return fmt.Errorf("bounty: open triage log %s: %w", cleanPath, err)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		_ = f.Close()
		return fmt.Errorf("bounty: encode triage event: %w", err)
	}
	if buf.Len() > maxEventLineBytes {
		_ = f.Close()
		return fmt.Errorf("bounty: encoded triage event exceeds %d bytes", maxEventLineBytes)
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		_ = f.Close()
		return fmt.Errorf("bounty: append triage event to %s: %w", cleanPath, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("bounty: set mode on %s: %w", cleanPath, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("bounty: sync %s: %w", cleanPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("bounty: close triage log %s: %w", cleanPath, err)
	}
	return nil
}

// LoadEvents reads and replays a triage log. A missing file is reported as
// os.ErrNotExist (wrapped) so callers can treat "no log yet" distinctly from a
// malformed log.
//
// Replay checks the chain and every field's shape, but does not re-apply the
// current policy table: a log written under an older policy remains readable,
// and policy changes do not retroactively invalidate history.
func LoadEvents(path string) ([]Event, error) {
	cleanPath := filepath.Clean(path)
	f, err := os.Open(cleanPath) // #nosec G304 -- path is an operator-selected triage log
	if err != nil {
		return nil, fmt.Errorf("bounty: read triage log %s: %w", cleanPath, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("bounty: stat triage log %s: %w", cleanPath, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("bounty: triage log %s is not a regular file", cleanPath)
	}
	if info.Size() > maxEventLogBytes {
		return nil, fmt.Errorf("bounty: triage log %s is %d bytes, exceeding the %d byte limit", cleanPath, info.Size(), maxEventLogBytes)
	}

	reader := bufio.NewReader(io.LimitReader(f, maxEventLogBytes+1))
	var events []Event
	lineNo := 0
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			lineNo++
			if len(line) > maxEventLineBytes {
				return nil, fmt.Errorf("bounty: triage log %s line %d exceeds %d bytes", cleanPath, lineNo, maxEventLineBytes)
			}
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) > 0 {
				var e Event
				dec := json.NewDecoder(bytes.NewReader(trimmed))
				dec.DisallowUnknownFields()
				if err := dec.Decode(&e); err != nil {
					return nil, fmt.Errorf("bounty: triage log %s line %d: %w", cleanPath, lineNo, err)
				}
				if dec.More() {
					return nil, fmt.Errorf("bounty: triage log %s line %d contains trailing JSON data", cleanPath, lineNo)
				}
				if err := e.validateShape(); err != nil {
					return nil, fmt.Errorf("bounty: triage log %s line %d: %w", cleanPath, lineNo, err)
				}
				events = append(events, e)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("bounty: read triage log %s: %w", cleanPath, readErr)
		}
	}

	if err := validateChain(events); err != nil {
		return nil, err
	}
	return events, nil
}

// validateChain checks that replay describes one continuous history starting
// with a submission.
func validateChain(events []Event) error {
	var prev Event
	for i := range events {
		e := events[i]
		if i == 0 {
			if e.From != StateNone || e.To != StateSubmitted {
				return fmt.Errorf(
					"bounty: triage log must start at %q, found %q -> %q",
					StateSubmitted, stateLabel(e.From), e.To)
			}
		} else {
			if e.From != prev.To {
				return fmt.Errorf(
					"bounty: triage event %d starts at %q but event %d ended at %q",
					i+1, stateLabel(e.From), i, prev.To)
			}
			if prev.PackageDigest != "" && e.PackageDigest != prev.PackageDigest {
				return fmt.Errorf(
					"bounty: triage event %d package digest %q does not match event %d's %q",
					i+1, e.PackageDigest, i, prev.PackageDigest)
			}
		}
		prev = e
	}
	return nil
}

// CurrentState replays events and returns the latest state. An empty log has no
// state (StateNone) and is not an error: nothing has been submitted yet.
func CurrentState(events []Event) (State, error) {
	if err := validateChain(events); err != nil {
		return StateNone, err
	}
	if len(events) == 0 {
		return StateNone, nil
	}
	return events[len(events)-1].To, nil
}
