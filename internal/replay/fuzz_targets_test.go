package replay

// fuzz_targets_test.go — coverage-guided fuzzing for the parsers that read
// untrusted bytes.
//
// Every input here comes from outside the process: a capture file, a HAR
// export, a TCP stream from a network nobody controls. A panic in any of them
// takes down the replay tool in the middle of an authorised engagement, and an
// unbounded allocation lets a 40-byte file exhaust the machine. Both are
// properties a table test can only sample, which is why they are fuzzed.

import (
	"bytes"
	"testing"
)

// FuzzParseHTTPStream feeds arbitrary bytes to the TCP-stream HTTP extractor.
//
// Contract under test:
//   - never panics, whatever the bytes are;
//   - emits only request packets;
//   - never buffers more than maxStreamBodyBytes for one request.
func FuzzParseHTTPStream(f *testing.F) {
	seeds := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"),
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\nGET /two HTTP/1.0\r\n\r\n"),
		[]byte("POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999\r\n\r\nab"),
		[]byte("POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
		[]byte("\x00\x01\x02\x03 not http at all"),
		[]byte("GET\r\n\r\n"),
		[]byte("GET / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n"),
		[]byte("GET / HTTP/1.1\r\n"), // truncated headers
		[]byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// A capture-derived stream is bounded by the capture file cap, and a
		// fuzz corpus entry that size is already the worst case.
		if len(data) > 1<<16 {
			t.Skip()
		}

		seen := 0
		parseHTTPStream(bytes.NewReader(data), func(p *Packet) bool {
			seen++
			if !p.IsRequest {
				t.Fatalf("emitted a non-request packet")
			}
			if p.Protocol != "http" {
				t.Fatalf("protocol = %q, want http", p.Protocol)
			}
			if len(p.Body) > int(maxStreamBodyBytes) {
				t.Fatalf("body = %d bytes, exceeds the %d cap", len(p.Body), maxStreamBodyBytes)
			}
			// Bound the work one input can cause. A 64 KiB stream cannot
			// legitimately contain more requests than this.
			return seen < 4096
		})
	})
}

// FuzzParseHARBytes feeds arbitrary documents to the HAR decoder.
//
// Contract under test: never panics, and a decode either fails cleanly or
// returns a Capture whose every packet is structurally valid.
func FuzzParseHARBytes(f *testing.F) {
	seeds := []string{
		`{"log":{"version":"1.2","entries":[]}}`,
		`{"log":{"version":"1.2","entries":[{"request":{"method":"GET","url":"https://example.com/","headers":[]},"response":{"status":200}}]}}`,
		`{"log":{"version":"1.2","entries":[{"request":{"method":"POST","url":"https://example.com/a?b=c","postData":{"text":"x"},"headers":[{"name":"Host","value":"example.com"}]},"response":{"status":200}}]}}`,
		`{}`,
		`null`,
		`[]`,
		`{"log":null}`,
		`{"log":{"entries":[{}]}}`,
		`{"log":{"entries":[{"request":{"url":"::not a url::"}}]}}`,
		`{"log":{"entries":[{"request":{"url":"https://example.com/","headers":[{"name":"","value":""}]}}]}}`,
		`{"log":{"entries":[{"request":{"url":"https://example.com/","httpVersion":"HTTP/9"}}]}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			t.Skip()
		}

		capture, err := ParseHARBytes(data, "fuzz")
		if err != nil {
			return // a clean rejection is a valid outcome
		}
		if capture == nil {
			t.Fatalf("nil capture with nil error")
		}
		for _, p := range capture.Packets {
			if p == nil {
				t.Fatalf("nil packet in capture")
			}
			if p.Method == "" && p.URL == "" {
				t.Fatalf("packet with neither method nor URL")
			}
		}
	})
}
