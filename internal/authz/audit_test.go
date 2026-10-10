package authz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditChainAppendAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := l.Append(Entry{Action: "run", Targets: []string{"https://a.example"}, Class: "public", Allowed: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	n, err := Verify(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 3 {
		t.Fatalf("verified %d entries, want 3", n)
	}

	entries, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].PrevHash != "" {
		t.Errorf("first entry prev_hash = %q, want empty", entries[0].PrevHash)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].PrevHash != entries[i-1].Hash {
			t.Errorf("entry %d not chained to previous", i)
		}
		if entries[i].Seq != int64(i+1) {
			t.Errorf("entry %d seq = %d", i, entries[i].Seq)
		}
	}
}

func TestAuditDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	for i := 0; i < 3; i++ {
		_, _ = l.Append(Entry{Action: "pentest", Targets: []string{"https://t.example"}, Allowed: true})
	}
	l.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Forge the first record: swap the denial to an allow.
	tampered := strings.Replace(string(raw), `"allowed":true`, `"allowed":true,"forged":true`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Verify(path); err == nil {
		t.Fatal("Verify accepted a tampered log")
	}
}

func TestAuditResumesChainAfterReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	_, _ = l.Append(Entry{Action: "run", Allowed: true})
	l.Close()

	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	e, err := l2.Append(Entry{Action: "run", Allowed: false})
	l2.Close()
	if err != nil {
		t.Fatal(err)
	}
	if e.Seq != 2 {
		t.Fatalf("seq = %d, want 2", e.Seq)
	}
	if _, err := Verify(path); err != nil {
		t.Fatalf("verify after reopen: %v", err)
	}
}

func TestAuditFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	_, _ = l.Append(Entry{Action: "run"})
	l.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("audit file mode = %o, want 600", perm)
	}
}
