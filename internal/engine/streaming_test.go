package engine

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// echoHandler serves a fixed-size body of repeating byte 'A'.
func echoHandler(size int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "1")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(strings.Repeat("A", size)))
	}
}

// gzipHandler serves gzip-compressed body of repeating byte 'B'.
func gzipHandler(size int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("X-Test", "1")
		w.WriteHeader(http.StatusOK)

		gz, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
		data := strings.Repeat("B", size)
		gz.Write([]byte(data))
		gz.Close()
	}
}

func newTestPool() *BufferPool { return NewBufferPool() }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestStreamingResponse_SmallBody(t *testing.T) {
	body := "Hello, streaming!"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strings.TrimSpace(strings.Repeat(" ", 0)))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	sr := NewStreamingResponse(resp, newTestPool())
	defer sr.Close()

	if sr.StatusCode() != 200 {
		t.Fatalf("want 200, got %d", sr.StatusCode())
	}
	if sr.Headers().Get("Content-Type") != "text/plain" {
		t.Fatalf("want Content-Type text/plain, got %q", sr.Headers().Get("Content-Type"))
	}

	// ReadAll for a small body.
	got, err := sr.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("want %q, got %q", body, string(got))
	}
	if sr.BytesRead() != int64(len(body)) {
		t.Fatalf("BytesRead = %d, want %d", sr.BytesRead(), len(body))
	}
}

func TestStreamingResponse_ChunkedReading(t *testing.T) {
	size := 32 * 1024 // 32 KB — more than a few 4 KB chunks
	srv := httptest.NewServer(echoHandler(size))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	sr := NewStreamingResponse(resp, newTestPool())
	defer sr.Close()

	var collected []byte
	chunks := 0
	for {
		chunk, err := sr.ReadChunk()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		collected = append(collected, chunk...)
		chunks++
	}

	if len(collected) != size {
		t.Fatalf("total bytes = %d, want %d", len(collected), size)
	}
	// 32 KB / 4 KB = 8 chunks minimum
	if chunks < 8 {
		t.Fatalf("expected >= 8 chunks, got %d", chunks)
	}
	if sr.BytesRead() != int64(size) {
		t.Fatalf("BytesRead = %d, want %d", sr.BytesRead(), size)
	}
}

func TestStreamingResponse_AbortMidStream(t *testing.T) {
	srv := httptest.NewServer(echoHandler(256 * 1024)) // 256 KB
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	sr := NewStreamingResponse(resp, newTestPool())
	defer sr.Close()

	// Read one chunk then abort.
	chunk, err := sr.ReadChunk()
	if err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	if len(chunk) == 0 {
		t.Fatal("expected non-empty first chunk")
	}

	sr.Abort()

	_, err = sr.ReadChunk()
	if err == nil {
		t.Fatal("expected error after abort")
	}
	if !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("expected abort error, got: %v", err)
	}
}

func TestStreamingResponse_ReadAllThenEOF(t *testing.T) {
	srv := httptest.NewServer(echoHandler(1024))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	sr := NewStreamingResponse(resp, newTestPool())
	defer sr.Close()

	_, err = sr.ReadAll()
	if err != nil {
		t.Fatal(err)
	}

	// Second call should return io.EOF.
	_, err = sr.ReadAll()
	if err != io.EOF {
		t.Fatalf("want io.EOF on second ReadAll, got %v", err)
	}
}

func TestStreamingResponse_GzipDecompression(t *testing.T) {
	bodySize := 16 * 1024
	expected := strings.Repeat("B", bodySize)

	srv := httptest.NewServer(gzipHandler(bodySize))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	sr := NewStreamingResponse(resp, newTestPool())
	defer sr.Close()

	got, err := sr.ReadAll()
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != expected {
		t.Fatalf("decompressed body mismatch: len=%d, want %d", len(got), bodySize)
	}
}

func TestStreamingResponse_ConcurrentReads(t *testing.T) {
	bodySize := 64 * 1024
	srv := httptest.NewServer(echoHandler(bodySize))
	defer srv.Close()

	const workers = 8
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			resp, err := http.Get(srv.URL)
			if err != nil {
				t.Errorf("GET failed: %v", err)
				return
			}

			sr := NewStreamingResponse(resp, newTestPool())
			defer sr.Close()

			var total int
			for {
				chunk, err := sr.ReadChunk()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Errorf("ReadChunk: %v", err)
					return
				}
				total += len(chunk)
			}
			if total != bodySize {
				t.Errorf("worker got %d bytes, want %d", total, bodySize)
			}
		}()
	}
	wg.Wait()
}

func TestStreamingResponse_CloseReturnsBuffer(t *testing.T) {
	pool := newTestPool()

	srv := httptest.NewServer(echoHandler(1024))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	sr := NewStreamingResponse(resp, pool)
	_, err = sr.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	sr.Close()

	stats := pool.Stats()
	if stats.Gets < 1 {
		t.Fatalf("expected at least 1 pool Get, got %d", stats.Gets)
	}
	if stats.Releases < 1 {
		t.Fatalf("expected at least 1 pool Release, got %d", stats.Releases)
	}
}

func TestStreamingResponse_ContentLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "500")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(strings.Repeat("X", 500)))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	sr := NewStreamingResponse(resp, newTestPool())
	defer sr.Close()

	if sr.ContentLength() != 500 {
		t.Fatalf("ContentLength = %d, want 500", sr.ContentLength())
	}
}

func TestStreamingResponse_ChunkStats(t *testing.T) {
	var cs ChunkStats

	cs.Record(4096, nil)
	cs.Record(4096, nil)
	cs.Record(1024, io.EOF)

	chunks, bytes, errors := cs.Snapshot()
	if chunks != 3 {
		t.Fatalf("chunks = %d, want 3", chunks)
	}
	if bytes != 9216 {
		t.Fatalf("bytes = %d, want 9216", bytes)
	}
	if errors != 1 {
		t.Fatalf("errors = %d, want 1", errors)
	}
}

func TestStreamingResponse_AbortThenClose(t *testing.T) {
	srv := httptest.NewServer(echoHandler(64 * 1024))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	sr := NewStreamingResponse(resp, newTestPool())
	sr.Abort()
	err = sr.Close()
	if err != nil {
		t.Fatalf("Close after abort: %v", err)
	}
}

func TestStreamingResponse_NilPoolUsesDefault(t *testing.T) {
	srv := httptest.NewServer(echoHandler(256))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	// pool=nil should fall back to DefaultPool without panic.
	sr := NewStreamingResponse(resp, nil)
	defer sr.Close()

	got, err := sr.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 256 {
		t.Fatalf("got %d bytes, want 256", len(got))
	}
}
