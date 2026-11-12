package replay

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// maxCaptureFileBytes caps in-memory capture containers (HAR/JSON): a
// captured session bigger than 512 MiB is rejected instead of being loaded
// wholesale. Classic PCAP/PCAPNG files are streamed through a packet reader
// and are not subject to this cap.
const maxCaptureFileBytes = 512 << 20 // 512 MiB

// maxStreamBodyBytes caps the buffered body of a single HTTP request extracted
// from a TCP stream. Bodies beyond 8 MiB are truncated — replay/timing only
// needs method, URL, headers and parameters, and streaming unbounded bodies
// out of a pcap would let one hostile capture exhaust host memory.
const maxStreamBodyBytes = 8 << 20 // 8 MiB

// PCAPParser parses PCAP files and extracts HTTP requests
type PCAPParser struct {
	capture *Capture
	tlsKeys []*TLSKey
	factory *tcpStreamFactory
	pool    *tcpassembly.StreamPool
	asm     *tcpassembly.Assembler
	statsMu sync.Mutex
	stats   PCAPStats

	// streams counts the per-flow HTTP parsing goroutines so ParseFile can wait
	// for all of them before it publishes the stats it read them from.
	streams sync.WaitGroup
}

type PCAPStats struct {
	TotalPackets  int
	TCPPackets    int
	HTTPRequests  int
	HTTP2Requests int
	DecryptedTLS  int
	Errors        int
}

func NewPCAPParser(keys []*TLSKey) *PCAPParser {
	p := &PCAPParser{tlsKeys: keys}
	p.resetForCapture("")
	return p
}

// resetForCapture returns the parser to the state it had when it was created,
// so ParseFile can be called more than once.
//
// Without this, a reused parser silently merged captures: the second file's
// packets were appended to the first file's, and its stats were added on top.
// A caller that parses two files with one parser got one capture containing
// both, described by numbers that belong to neither.
func (p *PCAPParser) resetForCapture(source string) {
	p.capture = &Capture{
		Source:   source,
		Format:   FormatPCAP,
		Sessions: make(map[string]*TLSSession),
		Packets:  make([]*Packet, 0, 10000),
		Metadata: make(map[string]string),
	}
	p.statsMu.Lock()
	p.stats = PCAPStats{}
	p.statsMu.Unlock()

	p.factory = &tcpStreamFactory{parser: p}
	p.pool = tcpassembly.NewStreamPool(p.factory)
	p.asm = tcpassembly.NewAssembler(p.pool)
}

// captureFormat identifies the on-disk capture container format.
type captureFormat int

const (
	capturePcap captureFormat = iota
	capturePcapNG
)

// pcapPacketSource is the minimal interface shared by pcapgo.Reader (pcap)
// and pcapgo.NgReader (pcapng). Both are pure-Go implementations that do
// NOT require cgo / libpcap, unlike github.com/google/gopacket/pcap.
type pcapPacketSource interface {
	// ReadPacketData reads the next raw packet payload and its capture info.
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
	// LinkType returns the link-layer type of the capture.
	LinkType() layers.LinkType
}

// sniffCaptureFormat inspects the first four bytes (the magic number) of a
// capture file and returns whether it is a classic pcap or a pcapng file.
// pcap magic: 0xd4c3b2a1 (little-endian) or 0xa1b2c3d4 (big-endian).
// pcapng magic: 0x0a0d0d0a (Section Header Block).
func sniffCaptureFormat(r io.Reader) (captureFormat, error) {
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return 0, fmt.Errorf("read magic bytes: %w", err)
	}
	switch magic {
	case [4]byte{0xd4, 0xc3, 0xb2, 0xa1}, [4]byte{0xa1, 0xb2, 0xc3, 0xd4}:
		return capturePcap, nil
	case [4]byte{0x0a, 0x0d, 0x0d, 0x0a}:
		return capturePcapNG, nil
	default:
		return 0, fmt.Errorf("unrecognized capture magic %x (expected pcap or pcapng)", magic)
	}
}

// ParseFile parses a PCAP or PCAPNG file and extracts HTTP requests.
//
// The file is read with the pure-Go pcapgo reader instead of the cgo-based
// github.com/google/gopacket/pcap package, so the replay tool compiles and
// runs with CGO_ENABLED=0 (e.g. on machines without a working C toolchain).
func (p *PCAPParser) ParseFile(path string) (*Capture, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	defer f.Close()

	p.resetForCapture(path)

	// Detect the container format and build the matching pure-Go reader.
	kind, err := sniffCaptureFormat(f)
	if err != nil {
		return nil, err
	}

	// gopacket allocates from sizes the capture file declares, so the
	// declaration is checked before gopacket acts on it. See captureguard.go.
	if err := validateCaptureDeclarations(f, kind); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind capture: %w", err)
	}

	var src pcapPacketSource
	switch kind {
	case capturePcap:
		r, err := pcapgo.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("open pcap reader: %w", err)
		}
		src = r
	case capturePcapNG:
		r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, fmt.Errorf("open pcapng reader: %w", err)
		}
		src = r
	default:
		return nil, fmt.Errorf("unsupported capture format")
	}

	p.readAllPackets(src)
	p.asm.FlushAll()

	// FlushAll closes the streams, but each one is drained by its own
	// goroutine. Wait for them before reading the counters they contribute to.
	p.streams.Wait()

	// Every number here describes *this* capture. They used to come from
	// process-global atomics that incremented on every parse, so the second
	// capture a long-lived process read reported the first one's requests too;
	// a one-request file could claim 57. The counters live on the parser now.
	p.capture.Metadata = map[string]string{
		"total_packets":  fmt.Sprintf("%d", p.stats.TotalPackets),
		"http_requests":  fmt.Sprintf("%d", p.stats.HTTPRequests),
		"http2_requests": fmt.Sprintf("%d", p.stats.HTTP2Requests),
		"decrypted_tls":  fmt.Sprintf("%d", p.stats.DecryptedTLS),
		"errors":         fmt.Sprintf("%d", p.stats.Errors),
	}

	return p.capture, nil
}

// readAllPackets drains a packet source, decoding each raw frame into a
// gopacket.Packet and feeding TCP packets to the stream assembler.
func (p *PCAPParser) readAllPackets(src pcapPacketSource) {
	linkType := src.LinkType()

	// A single corrupt frame must not abort the whole capture, so every error
	// other than a clean EOF is counted and the loop continues.
	//
	// io.ErrUnexpectedEOF is an *error*, not an end: it means the file stopped
	// in the middle of a record, so that frame was lost and the operator should
	// see it in stats.Errors. Only io.EOF is the clean end.
	//
	// The counters below exist because "continue on error" has no progress
	// guarantee: a source that returns the same error forever (a sticky gzip
	// error, a negative declared length that never advances) would spin
	// indefinitely. Three identical consecutive errors with no packet read in
	// between is treated as a stuck reader and the loop stops.
	const maxRepeatedErrors = 3
	var lastErr string
	repeated := 0

	for {
		data, ci, err := src.ReadPacketData()
		if err == io.EOF {
			return
		}
		if err != nil {
			p.addStats(func(s *PCAPStats) { s.Errors++ })

			if msg := err.Error(); msg == lastErr {
				repeated++
			} else {
				lastErr, repeated = msg, 1
			}
			if repeated >= maxRepeatedErrors {
				return
			}
			continue
		}

		lastErr = ""
		repeated = 0
		p.addStats(func(s *PCAPStats) { s.TotalPackets++ })
		p.processPacketData(data, linkType, ci.Timestamp)
	}
}

// processPacketData wraps a raw frame into a gopacket.Packet, preserving the
// capture timestamp (gopacket.NewPacket alone does not set one), and hands it
// to the shared decoding pipeline.
func (p *PCAPParser) processPacketData(data []byte, linkType layers.LinkType, ts time.Time) {
	packet := gopacket.NewPacket(data, linkType, gopacket.Default)
	if md := packet.Metadata(); md != nil {
		md.Timestamp = ts
	}
	p.processPacket(packet)
}

// addStats applies one mutation to the parser's counters under the lock.
//
// The counters are written from two places that run concurrently: the packet
// loop on this goroutine, and one HTTP-stream goroutine per TCP flow. Reading
// or writing them without the lock is a data race that -race catches on any
// capture with more than one flow.
func (p *PCAPParser) addStats(apply func(*PCAPStats)) {
	p.statsMu.Lock()
	apply(&p.stats)
	p.statsMu.Unlock()
}

func (p *PCAPParser) processPacket(packet gopacket.Packet) {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp := tcpLayer.(*layers.TCP)
	p.addStats(func(s *PCAPStats) { s.TCPPackets++ })

	p.asm.AssembleWithTimestamp(
		netLayer.NetworkFlow(),
		tcp,
		packet.Metadata().Timestamp,
	)
}

// --- TCP Stream Assembly ----------------------------------------------------

type tcpStreamFactory struct {
	parser *PCAPParser
}

func (f *tcpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	reader := tcpreader.NewReaderStream()
	stream := &tcpReplayStream{
		parser:    f.parser,
		net:       net,
		transport: transport,
		reader:    reader,
	}
	f.parser.streams.Add(1)
	go stream.process()
	return &reader
}

type tcpReplayStream struct {
	parser    *PCAPParser
	net       gopacket.Flow
	transport gopacket.Flow
	reader    tcpreader.ReaderStream
}

func (s *tcpReplayStream) process() {
	defer s.parser.streams.Done()

	stats := parseHTTPStream(&s.reader, func(pkt *Packet) bool {
		pkt.Timestamp = time.Now()
		pkt.SrcIP = net.ParseIP(s.net.Src().String())
		pkt.DstIP = net.ParseIP(s.net.Dst().String())
		s.parser.capture.AddPacket(pkt)
		return true
	})

	s.parser.addStats(func(st *PCAPStats) {
		st.HTTPRequests += stats.Requests
		st.Errors += stats.Errors
	})
}

// parseHTTPStream extracts every HTTP request from a reassembled TCP byte
// stream.
//
// The bytes come from a capture file, which is untrusted input: a malformed or
// deliberately hostile stream must terminate the loop, never panic, and never
// allocate more than maxStreamBodyBytes per request. Keeping it free of the
// parser and the gopacket flows makes that contract directly fuzzable — see
// FuzzParseHTTPStream.
//
// It is free of shared state on purpose: what it saw is returned, not added to
// a package-level counter, so two captures parsed by one process cannot report
// each other's numbers.
func parseHTTPStream(src io.Reader, emit func(*Packet) bool) streamParseStats {
	var stats streamParseStats
	r := bufio.NewReader(src)
	for {
		req, err := http.ReadRequest(r)
		if err != nil {
			if err != io.EOF {
				stats.Errors++
			}
			return stats
		}
		body, _ := io.ReadAll(io.LimitReader(req.Body, maxStreamBodyBytes))
		if len(body) == int(maxStreamBodyBytes) {
			// Truncated (or exactly at the cap): drain the remainder so the
			// parser stays aligned with the stream for the next request.
			io.Copy(io.Discard, req.Body)
		}
		req.Body.Close()

		url := ""
		if req.URL != nil {
			url = req.URL.String()
		}
		pkt := &Packet{
			Protocol:  "http",
			Method:    req.Method,
			URL:       url,
			Headers:   req.Header,
			Body:      body,
			IsRequest: true,
		}
		stats.Requests++
		if !emit(pkt) {
			return stats
		}
	}
}

// streamParseStats is what one HTTP stream yielded: requests emitted and reads
// that failed for a reason other than a clean EOF.
type streamParseStats struct {
	Requests int
	Errors   int
}

// --- HAR Parser -------------------------------------------------------------

func ParseHAR(path string) (*Capture, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open har: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxCaptureFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read har: %w", err)
	}
	return ParseHARBytes(data, path)
}

// ParseHARBytes parses a HAR document already in memory.
//
// The document comes from a browser export, which is untrusted: it is decoded
// with a size cap and must never panic on a malformed shape. Splitting the
// decode from the file read is what makes that contract fuzzable — see
// FuzzParseHARBytes.
func ParseHARBytes(data []byte, source string) (*Capture, error) {
	if len(data) > maxCaptureFileBytes {
		return nil, fmt.Errorf("har file exceeds %d MiB limit", maxCaptureFileBytes>>20)
	}

	var har HAR
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, fmt.Errorf("decode har: %w", err)
	}

	capture := &Capture{
		Source:   source,
		Format:   FormatHAR,
		Packets:  make([]*Packet, 0, len(har.Log.Entries)),
		Metadata: make(map[string]string),
	}
	// Entries that cannot become a replayable request are counted, not
	// silently dropped: a HAR export whose request list is malformed should
	// tell the operator how much of it was unusable.
	skipped := 0
	defer func() {
		if skipped > 0 {
			capture.Metadata["skipped_entries"] = fmt.Sprintf("%d", skipped)
		}
	}()

	for _, entry := range har.Log.Entries {
		if strings.TrimSpace(entry.Request.URL) == "" || strings.TrimSpace(entry.Request.Method) == "" {
			skipped++
			continue
		}

		ts, err := time.Parse(time.RFC3339Nano, entry.StartedDateTime)
		if err != nil {
			ts = time.Now()
		}

		fullURL := entry.Request.URL
		if len(entry.Request.QueryString) > 0 {
			qs := make([]string, 0, len(entry.Request.QueryString))
			for _, q := range entry.Request.QueryString {
				qs = append(qs, q.Name+"="+q.Value)
			}
			fullURL += "?" + joinStrings(qs, "&")
		}

		headers := make(http.Header)
		for _, h := range entry.Request.Headers {
			headers.Add(h.Name, h.Value)
		}

		var body []byte
		if entry.Request.PostData != nil && entry.Request.PostData.Text != "" {
			body = []byte(entry.Request.PostData.Text)
		}

		pkt := &Packet{
			Timestamp: ts,
			Method:    entry.Request.Method,
			URL:       fullURL,
			Headers:   headers,
			Body:      body,
			Protocol:  "http",
			IsRequest: true,
		}

		respHeaders := make(http.Header)
		for _, h := range entry.Response.Headers {
			respHeaders.Add(h.Name, h.Value)
		}
		var respBody []byte
		if entry.Response.Content.Text != "" {
			respBody = []byte(entry.Response.Content.Text)
		}

		pkt.Response = &Response{
			StatusCode: entry.Response.Status,
			Headers:    respHeaders,
			Body:       respBody,
			Timestamp:  ts.Add(time.Duration(entry.Time * float64(time.Millisecond))),
			Duration:   time.Duration(entry.Time * float64(time.Millisecond)),
		}

		capture.AddPacket(pkt)
	}

	return capture, nil
}

func joinStrings(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

// --- HAR Format Types -------------------------------------------------------

type HAR struct {
	Log HARLog `json:"log"`
}

type HARLog struct {
	Version string     `json:"version"`
	Creator HARCreator `json:"creator"`
	Entries []HAREntry `json:"entries"`
}

type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type HAREntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         HARRequest  `json:"request"`
	Response        HARResponse `json:"response"`
}

type HARRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []HARHeader `json:"headers"`
	QueryString []HARQuery  `json:"queryString"`
	PostData    *HARPost    `json:"postData,omitempty"`
}

type HARResponse struct {
	Status     int         `json:"status"`
	StatusText string      `json:"statusText"`
	Headers    []HARHeader `json:"headers"`
	Content    HARContent  `json:"content"`
}

type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARQuery struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARPost struct {
	MIMEType string `json:"mimeType"`
	Text     string `json:"text"`
}

type HARContent struct {
	Size     int    `json:"size"`
	MIMEType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
}
