package siem

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
)

// spoolFileName is the JSON-lines file written inside Config.SpoolDir.
const spoolFileName = "siem-spool.jsonl"

// spoolPath returns the absolute path of the spool file.
func (n *Notifier) spoolPath() string {
	return filepath.Join(n.cfg.SpoolDir, spoolFileName)
}

// spoolEvent appends ev as a JSON line to the spool file, returning whether it
// was persisted. It deliberately never returns an error: spooling is a
// last-resort safety net, and the caller has already recorded the event as
// Dropped/Failed. An I/O problem is therefore reported only through the boolean
// (the event is still counted, just not persisted).
//
// Durability policy: each record is one O_APPEND write, so records are
// append-only and never interleave, but the write is not fsynced — durability is
// bounded by the OS page cache. The spool file is fsynced/rewritten on
// ReplaySpool and should live on a durable volume.
func (n *Notifier) spoolEvent(ev Event) bool {
	if n.cfg.SpoolDir == "" {
		return false
	}

	line, err := json.Marshal(ev)
	if err != nil {
		return false
	}
	line = append(line, '\n')

	n.spoolMu.Lock()
	defer n.spoolMu.Unlock()

	if err := os.MkdirAll(n.cfg.SpoolDir, 0o700); err != nil {
		return false
	}
	f, err := os.OpenFile(n.spoolPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(line); err != nil {
		return false
	}
	// Enforce 0600 even if the file pre-existed with looser permissions.
	_ = f.Chmod(0o600)

	atomic.AddUint64(&n.spooled, 1)
	return true
}

// ReplaySpool re-sends every event previously written to the spool file.
//
// On full success the spool is truncated and the number of re-sent events is
// returned. If some events still fail they are rewritten to the spool (so
// nothing is lost) and an error is returned alongside the count of events that
// did succeed. Lines that cannot be decoded are preserved verbatim.
//
// ReplaySpool is a no-op returning (0, nil) when no SpoolDir is configured or
// the spool file does not exist.
func (n *Notifier) ReplaySpool(ctx context.Context) (int, error) {
	if n.cfg.SpoolDir == "" {
		return 0, nil
	}

	n.spoolMu.Lock()
	defer n.spoolMu.Unlock()

	path := n.spoolPath()
	f, err := os.Open(path) //nolint:gosec // path is the operator-configured spool file
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("siem: open spool: %w", err)
	}

	var events []Event
	var undecodable [][]byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			undecodable = append(undecodable, append([]byte(nil), line...))
			continue
		}
		events = append(events, ev)
	}
	scanErr := scanner.Err()
	_ = f.Close()
	if scanErr != nil {
		return 0, fmt.Errorf("siem: read spool: %w", scanErr)
	}

	sent := 0
	var remaining [][]byte
	for _, ev := range events {
		if err := n.deliver(ctx, ev, false); err != nil {
			line, mErr := json.Marshal(ev)
			if mErr != nil {
				// Should be impossible (it decoded successfully); skip rather
				// than lose the whole spool.
				continue
			}
			remaining = append(remaining, line)
			continue
		}
		sent++
	}
	remaining = append(remaining, undecodable...)

	if len(remaining) == 0 {
		if err := os.Truncate(path, 0); err != nil {
			return sent, fmt.Errorf("siem: truncate spool: %w", err)
		}
		return sent, nil
	}

	var buf bytes.Buffer
	for _, line := range remaining {
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return sent, fmt.Errorf("siem: rewrite spool: %w", err)
	}
	_ = os.Chmod(path, 0o600)
	return sent, fmt.Errorf("siem: %d spooled event(s) failed to replay", len(remaining))
}
