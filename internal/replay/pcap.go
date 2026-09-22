package replay

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
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
}

type PCAPStats struct {
	TotalPackets  int
	TCPPackets    int
	HTTPRequests  int
	HTTP2Requests int
	DecryptedTLS  int
	Errors        int
}

// atomics for concurrent stats updates
var (
	pcapHTTPRequests atomic.Int64
	pcapErrors       atomic.Int64
)

func NewPCAPParser(keys []*TLSKey) *PCAPParser {
	p := &PCAPParser{
		capture: &Capture{
			Format:   FormatPCAP,
			Sessions: make(map[string]*TLSSession),
			Packets:  make([]*Packet, 0, 10000),
			Metadata: make(map[string]string),
		},
		tlsKeys: keys,
	}
	p.factory = &tcpStreamFactory{parser: p}
	p.pool = tcpassembly.NewStreamPool(p.factory)
	p.asm = tcpassembly.NewAssembler(p.pool)
	return p
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

	p.capture.Source = path

	// Detect the container format and build the matching pure-Go reader.
	kind, err := sniffCaptureFormat(f)
	if err != nil {
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

	p.capture.Metadata = map[string]string{
		"total_packets":  fmt.Sprintf("%d", p.stats.TotalPackets),
		"http_requests":  fmt.Sprintf("%d", pcapHTTPRequests.Load()),
		"http2_requests": fmt.Sprintf("%d", p.stats.HTTP2Requests),
		"decrypted_tls":  fmt.Sprintf("%d", p.stats.DecryptedTLS),
		"errors":         fmt.Sprintf("%d", pcapErrors.Load()),
	}

	return p.capture, nil
}

// readAllPackets drains a packet source, decoding each raw frame into a
// gopacket.Packet and feeding TCP packets to the stream assembler.
func (p *PCAPParser) readAllPackets(src pcapPacketSource) {
	linkType := src.LinkType()
	for {
		data, ci, err := src.ReadPacketData()
		if err == io.EOF {
			return
		}
		if err != nil {
			// A single corrupt frame must not abort the whole capture.
			p.stats.Errors++
			pcapErrors.Add(1)
			continue
		}
		p.stats.TotalPackets++
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
	p.stats.TCPPackets++

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
	r := bufio.NewReader(&s.reader)
	for {
		req, err := http.ReadRequest(r)
		if err != nil {
			if err != io.EOF {
				pcapErrors.Add(1)
			}
			return
		}
		body, _ := io.ReadAll(io.LimitReader(req.Body, maxStreamBodyBytes))
		if len(body) == int(maxStreamBodyBytes) {
			// Truncated (or exactly at the cap): drain the remainder so the
			// parser stays aligned with the stream for the next request.
			io.Copy(io.Discard, req.Body)
		}
		req.Body.Close()

		pkt := &Packet{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP(s.net.Src().String()),
			DstIP:     net.ParseIP(s.net.Dst().String()),
			Protocol:  "http",
			Method:    req.Method,
			URL:       req.URL.String(),
			Headers:   req.Header,
			Body:      body,
			IsRequest: true,
		}
		s.parser.capture.AddPacket(pkt)
		pcapHTTPRequests.Add(1)
	}
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
	if len(data) > maxCaptureFileBytes {
		return nil, fmt.Errorf("har file exceeds %d MiB limit", maxCaptureFileBytes>>20)
	}

	var har HAR
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, fmt.Errorf("decode har: %w", err)
	}

	capture := &Capture{
		Source:   path,
		Format:   FormatHAR,
		Packets:  make([]*Packet, 0, len(har.Log.Entries)),
		Metadata: make(map[string]string),
	}

	for _, entry := range har.Log.Entries {
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
