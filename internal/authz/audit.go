package authz

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Entry is one line of the audit trail.
type Entry struct {
	Seq      int64     `json:"seq"`
	Time     time.Time `json:"time"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Targets  []string  `json:"targets"`
	IPs      []string  `json:"ips,omitempty"`
	Class    string    `json:"class"`
	Allowed  bool      `json:"allowed"`
	Rule     string    `json:"rule,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Version  string    `json:"version,omitempty"`
	Argv     []string  `json:"argv,omitempty"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
}

// digest returns the hex SHA-256 over the entry with Hash cleared, mixing in
// the previous hash. Any edit to a past entry breaks every later hash.
func (e Entry) digest() string {
	c := e
	c.Hash = ""
	payload, _ := json.Marshal(c)
	h := sha256.New()
	h.Write([]byte(c.PrevHash))
	h.Write([]byte{0})
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// Log is an append-only, hash-chained audit log stored as JSON lines.
type Log struct {
	path string
	f    *os.File
	mu   sync.Mutex
}

// Open opens (creating if needed) the audit log at path. The directory is
// created with 0700 and the file with 0600: the trail records who tested what,
// which is sensitive.
func Open(path string) (*Log, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create audit dir: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	_ = os.Chmod(path, 0o600)
	return &Log{path: path, f: f}, nil
}

// Path returns the log file path.
func (l *Log) Path() string { return l.path }

// Close releases the file handle.
func (l *Log) Close() error {
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}

// Append chains and writes entry, filling in Seq, Time, PrevHash, and Hash.
// The returned entry is the stored record.
func (l *Log) Append(e Entry) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	prev, seq, err := l.tail()
	if err != nil {
		return Entry{}, err
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.Actor == "" {
		e.Actor = currentUser()
	}
	e.Seq = seq + 1
	e.PrevHash = prev
	e.Hash = e.digest()

	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, fmt.Errorf("encode audit entry: %w", err)
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return Entry{}, fmt.Errorf("write audit entry: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return Entry{}, fmt.Errorf("sync audit log: %w", err)
	}
	return e, nil
}

// tail returns the hash and sequence number of the last entry.
func (l *Log) tail() (string, int64, error) {
	last, err := lastEntry(l.path)
	if err != nil {
		return "", 0, err
	}
	if last == nil {
		return "", 0, nil
	}
	return last.Hash, last.Seq, nil
}

// Verify re-reads the log at path and recomputes the chain. It returns the
// number of valid entries. A non-nil error means the trail was tampered with
// or is corrupt.
//
// Three checks per record: the previous-hash link, the record hash, and that
// the stored bytes still round-trip to the same record (so a field added to or
// removed from the JSON is caught even though it would not change the hash).
func Verify(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	prev := ""
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return n, fmt.Errorf("parse audit line %d: %w", n+1, err)
		}
		if e.PrevHash != prev {
			return n, fmt.Errorf("entry %d: prev_hash mismatch (expected %s, got %s)", e.Seq, short(prev), short(e.PrevHash))
		}
		if e.Hash != e.digest() {
			return n, fmt.Errorf("entry %d: hash mismatch — record has been modified", e.Seq)
		}
		canon, err := json.Marshal(e)
		if err != nil {
			return n, err
		}
		if string(canon) != line {
			return n, fmt.Errorf("entry %d: stored bytes do not match the record (field added or removed)", e.Seq)
		}
		prev = e.Hash
		n++
	}
	return n, sc.Err()
}

// ReadAll parses every entry in the log at path.
func ReadAll(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return out, fmt.Errorf("parse audit line %d: %w", len(out)+1, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// lastEntry reads only the final non-empty line of the file.
func lastEntry(path string) (*Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	if size == 0 {
		return nil, nil
	}

	const chunk = 64 * 1024
	var buf []byte
	pos := size
	for pos > 0 {
		read := int64(chunk)
		if pos < read {
			read = pos
		}
		pos -= read
		part := make([]byte, read)
		if _, err := f.ReadAt(part, pos); err != nil && err != io.EOF {
			return nil, err
		}
		buf = append(part, buf...)
		trimmed := strings.TrimRight(string(buf), "\n")
		if i := strings.LastIndexByte(trimmed, '\n'); i >= 0 {
			buf = []byte(trimmed[i+1:])
			break
		}
		if pos == 0 {
			buf = []byte(trimmed)
			break
		}
	}

	line := strings.TrimSpace(string(buf))
	if line == "" {
		return nil, nil
	}
	var e Entry
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		return nil, fmt.Errorf("parse last audit entry: %w", err)
	}
	return &e, nil
}

// currentUser returns the OS username for the audit record.
func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	if v := os.Getenv("USERNAME"); v != "" {
		return v
	}
	return "unknown"
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}
