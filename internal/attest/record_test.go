package attest

// record_test.go — one measured request, its canonical bytes, and the sidecar
// stream that carries the raw evidence.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordValidateTable(t *testing.T) {
	good := Record{Seq: 1, Worker: "w1", StartNS: 0, LatencyNS: 5, Status: 200, Bytes: 10}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}

	cases := map[string]Record{
		"empty_worker":   {Seq: 1},
		"long_worker":    {Seq: 1, Worker: strings.Repeat("x", MaxWorkerIDLen+1)},
		"invalid_utf8":   {Seq: 1, Worker: string([]byte{0xff, 0xfe})},
		"zero_seq":       {Worker: "w1"},
		"negative_start": {Seq: 1, Worker: "w1", StartNS: -1},
		"negative_lat":   {Seq: 1, Worker: "w1", LatencyNS: -1},
		"negative_bytes": {Seq: 1, Worker: "w1", Bytes: -1},
		"status_high":    {Seq: 1, Worker: "w1", Status: MaxStatus + 1},
		"status_neg":     {Seq: 1, Worker: "w1", Status: -1},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			if err := r.Validate(); err == nil {
				t.Fatalf("record %s was accepted", name)
			}
		})
	}
}

func TestCanonicalRecordShape(t *testing.T) {
	r := Record{Seq: 1, Worker: "w1", StartNS: 1000, LatencyNS: 5, Status: 200, Bytes: 10}
	got, err := CanonicalRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"bytes":10,"latency_ns":5,"seq":1,"start_ns":1000,"status":200,"worker":"w1"}`
	if string(got) != want {
		t.Fatalf("canonical record =\n  %s\nwant\n  %s", got, want)
	}
	if bytes.ContainsAny(got, " \n\t") {
		t.Fatalf("canonical record contains whitespace: %q", got)
	}
	if _, err := CanonicalRecord(Record{}); err == nil {
		t.Fatal("invalid record encoded without error")
	}
}

func TestRecordDigestIsIndexBound(t *testing.T) {
	r := Record{Seq: 1, Worker: "w1", LatencyNS: 5}
	d0, err := RecordDigest(0, r)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := RecordDigest(1, r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(d0, d1) {
		t.Fatal("RecordDigest ignores the index")
	}
}

func TestSortRecordsByStartThenSeq(t *testing.T) {
	recs := []Record{
		{Seq: 2, Worker: "w", StartNS: 10},
		{Seq: 1, Worker: "w", StartNS: 20},
		{Seq: 1, Worker: "w", StartNS: 10},
	}
	got := SortRecords(recs)
	wantOrder := []struct {
		start int64
		seq   uint64
	}{{10, 1}, {10, 2}, {20, 1}}
	for i, w := range wantOrder {
		if got[i].StartNS != w.start || got[i].Seq != w.seq {
			t.Fatalf("position %d = (%d,%d), want (%d,%d)", i, got[i].StartNS, got[i].Seq, w.start, w.seq)
		}
	}
	// The input slice is untouched.
	if recs[0].StartNS != 10 || recs[0].Seq != 2 {
		t.Fatal("SortRecords mutated its input")
	}
	if !RecordsInFileOrder(got) {
		t.Fatal("sorted records are not reported as in order")
	}
	if RecordsInFileOrder(recs) {
		t.Fatal("unsorted records reported as in order")
	}
}

func TestWriteAndLoadSamplesRoundTrip(t *testing.T) {
	recs := append(synthRecords("w1", 0, 5, 10, 100, 1), synthRecords("w2", 0, 3, 10, 200, 1)...)

	var buf bytes.Buffer
	if err := WriteSamples(&buf, recs); err != nil {
		t.Fatalf("WriteSamples: %v", err)
	}
	if n := bytes.Count(buf.Bytes(), []byte{'\n'}); n != len(recs) {
		t.Fatalf("wrote %d lines, want %d", n, len(recs))
	}

	path := filepath.Join(t.TempDir(), "samples.jsonl")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, stats, err := LoadSamples(path, DefaultSampleLoadOptions())
	if err != nil {
		t.Fatalf("LoadSamples: %v", err)
	}
	if stats.Records != 8 || stats.Workers != 2 {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.NonCanonicalLines != 0 || stats.UnsortedLines != 0 {
		t.Fatalf("canonical round trip produced diagnostics: %+v", stats)
	}
	if len(loaded["w1"]) != 5 || len(loaded["w2"]) != 3 {
		t.Fatalf("loaded counts = %d/%d", len(loaded["w1"]), len(loaded["w2"]))
	}
}

func TestLoadSamplesRejectsBadInput(t *testing.T) {
	write := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "s.jsonl")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	line := `{"bytes":1,"latency_ns":1,"seq":1,"start_ns":1,"status":200,"worker":"w1"}`

	t.Run("duplicate_seq", func(t *testing.T) {
		p := write(t, line+"\n"+line+"\n")
		if _, _, err := LoadSamples(p, DefaultSampleLoadOptions()); err == nil {
			t.Fatal("duplicate seq accepted")
		}
	})
	t.Run("truncated_line", func(t *testing.T) {
		p := write(t, line+"\n"+`{"bytes":1,"latency_ns":1,"seq":2,"start_n_`)
		if _, _, err := LoadSamples(p, DefaultSampleLoadOptions()); err == nil {
			t.Fatal("truncated line accepted")
		}
	})
	t.Run("trailing_data", func(t *testing.T) {
		p := write(t, line+" extra\n")
		if _, _, err := LoadSamples(p, DefaultSampleLoadOptions()); err == nil {
			t.Fatal("trailing JSON data accepted")
		}
	})
	t.Run("invalid_utf8", func(t *testing.T) {
		p := write(t, string([]byte{0xff, 0xfe, 0xfd})+"\n")
		if _, _, err := LoadSamples(p, DefaultSampleLoadOptions()); err == nil {
			t.Fatal("invalid UTF-8 accepted")
		}
	})
	t.Run("invalid_record", func(t *testing.T) {
		p := write(t, `{"bytes":0,"latency_ns":-5,"seq":1,"start_ns":1,"status":0,"worker":"w1"}`+"\n")
		if _, _, err := LoadSamples(p, DefaultSampleLoadOptions()); err == nil {
			t.Fatal("negative latency accepted")
		}
	})
	t.Run("oversized_line", func(t *testing.T) {
		huge := `{"bytes":0,"latency_ns":0,"seq":1,"start_ns":0,"status":0,"worker":"w1","pad":"` +
			strings.Repeat("A", MaxSampleLineBytes+16) + `"}`
		p := write(t, huge+"\n")
		_, _, err := LoadSamples(p, DefaultSampleLoadOptions())
		if err == nil {
			t.Fatal("oversized line accepted")
		}
		if !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("per_worker_cap", func(t *testing.T) {
		p := write(t, strings.Repeat(line+"\n", 3))
		opts := DefaultSampleLoadOptions()
		opts.MaxSamplesPerWorker = 2
		if _, _, err := LoadSamples(p, opts); err == nil {
			t.Fatal("per-worker cap not enforced")
		}
	})
	t.Run("total_cap", func(t *testing.T) {
		p := write(t, strings.Repeat(line+"\n", 3))
		opts := DefaultSampleLoadOptions()
		opts.MaxSamplesTotal = 2
		if _, _, err := LoadSamples(p, opts); err == nil {
			t.Fatal("total cap not enforced")
		}
	})
}

func TestLoadSamplesCountsNonCanonical(t *testing.T) {
	// Same values, padded with whitespace and reordered keys: it loads (values
	// are what matter) but is flagged as non-canonical.
	line := `{"worker":"w1","seq":1,"start_ns":1,"latency_ns":5,"status":200,"bytes":7}`
	p := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(p, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stats, err := LoadSamples(p, DefaultSampleLoadOptions())
	if err != nil {
		t.Fatalf("LoadSamples: %v", err)
	}
	if stats.NonCanonicalLines != 1 {
		t.Fatalf("NonCanonicalLines = %d, want 1", stats.NonCanonicalLines)
	}
}

func TestLoadSamplesSkipsBlankLines(t *testing.T) {
	line := `{"bytes":0,"latency_ns":0,"seq":1,"start_ns":0,"status":0,"worker":"w1"}`
	p := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(p, []byte("\n"+line+"\n   \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, stats, err := LoadSamples(p, DefaultSampleLoadOptions())
	if err != nil {
		t.Fatal(err)
	}
	if stats.BlankLines != 2 || stats.Records != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if len(loaded["w1"]) != 1 {
		t.Fatalf("loaded %d records", len(loaded["w1"]))
	}
}

type errWriter struct{ err error }

func (e errWriter) Write([]byte) (int, error) { return 0, e.err }

func TestSampleWriterStickyError(t *testing.T) {
	sw := NewSampleWriter(errWriter{err: errors.New("boom")})
	rec := Record{Seq: 1, Worker: "w1", LatencyNS: 1}
	_ = sw.Write(rec) // may be buffered
	if err := sw.Close(); err == nil {
		t.Fatal("Close did not report the write failure")
	}
	if err := sw.Write(rec); err == nil {
		t.Fatal("Write after a failure did not return the sticky error")
	}
}

func TestSampleWriterRejectsInvalidRecord(t *testing.T) {
	var buf bytes.Buffer
	sw := NewSampleWriter(&buf)
	if err := sw.Write(Record{}); err == nil {
		t.Fatal("invalid record accepted by the writer")
	}
}

func TestSanitizeWorkerID(t *testing.T) {
	if got := SanitizeWorkerID("  w1  "); got != "w1" {
		t.Fatalf("SanitizeWorkerID = %q", got)
	}
	long := strings.Repeat("x", MaxWorkerIDLen+10)
	if got := SanitizeWorkerID(long); len(got) != MaxWorkerIDLen {
		t.Fatalf("SanitizeWorkerID length = %d, want %d", len(got), MaxWorkerIDLen)
	}
}
