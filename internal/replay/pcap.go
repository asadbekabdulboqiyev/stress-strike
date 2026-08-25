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
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

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

func (p *PCAPParser) ParseFile(path string) (*Capture, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	defer handle.Close()

	p.capture.Source = path

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		p.stats.TotalPackets++
		p.processPacket(packet)
	}

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
		body, _ := io.ReadAll(req.Body)
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

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read har: %w", err)
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
