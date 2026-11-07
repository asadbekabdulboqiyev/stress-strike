package replay

// pcap_test.go — parsing coverage for pcap.go: format sniffing, classic pcap
// and pcapng readers, the corrupt-frame tolerance path, packet decoding and
// the TCP stream assembler that turns a captured HTTP exchange into a Packet.
//
// Captures are synthesized in the test with gopacket's writers, so no fixture
// binary files are needed and no network is touched.

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestSniffCaptureFormat(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want captureFormat
	}{
		{"pcap-le", []byte{0xd4, 0xc3, 0xb2, 0xa1}, capturePcap},
		{"pcap-be", []byte{0xa1, 0xb2, 0xc3, 0xd4}, capturePcap},
		{"pcapng", []byte{0x0a, 0x0d, 0x0d, 0x0a}, capturePcapNG},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sniffCaptureFormat(bytes.NewReader(tc.data))
			if err != nil {
				t.Fatalf("sniffCaptureFormat: %v", err)
			}
			if got != tc.want {
				t.Errorf("format = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("garbage", func(t *testing.T) {
		if _, err := sniffCaptureFormat(bytes.NewReader([]byte("HTTP/1.1 200 OK\r\n"))); err == nil {
			t.Fatal("sniffCaptureFormat(garbage) = nil error, want a magic mismatch")
		}
	})

	t.Run("short", func(t *testing.T) {
		if _, err := sniffCaptureFormat(bytes.NewReader([]byte{0xd4})); err == nil {
			t.Fatal("sniffCaptureFormat(1 byte) = nil error, want an EOF error")
		}
	})
}

// tcpFlags selects the control bits for a synthesized frame.
type tcpFlags struct {
	syn, ack, psh, fin bool
}

// httpExchangeFrames builds a minimal TCP handshake carrying one HTTP request
// from clientPort to serverPort. The PSH/ACK frame holds the payload.
func httpExchangeFrames(client, server net.IP, clientPort, serverPort layers.TCPPort, payload string) [][]byte {
	const clientISN, serverISN = 1000, 5000

	srcMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	dstMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 2}

	frame := func(srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort, seq, ack uint32, fl tcpFlags, body []byte) []byte {
		eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{
			Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
			SrcIP: srcIP, DstIP: dstIP,
		}
		tcp := &layers.TCP{
			SrcPort: srcPort, DstPort: dstPort,
			Seq: seq, Ack: ack, Window: 65535,
			SYN: fl.syn, ACK: fl.ack, PSH: fl.psh, FIN: fl.fin,
		}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			panic(err)
		}
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		elems := []gopacket.SerializableLayer{eth, ip, tcp}
		if len(body) > 0 {
			elems = append(elems, gopacket.Payload(body))
		}
		if err := gopacket.SerializeLayers(buf, opts, elems...); err != nil {
			panic(err)
		}
		return buf.Bytes()
	}

	return [][]byte{
		frame(client, server, clientPort, serverPort, clientISN, 0, tcpFlags{syn: true}, nil),
		frame(server, client, serverPort, clientPort, serverISN, clientISN+1, tcpFlags{syn: true, ack: true}, nil),
		frame(client, server, clientPort, serverPort, clientISN+1, serverISN+1, tcpFlags{ack: true}, nil),
		frame(client, server, clientPort, serverPort, clientISN+1, serverISN+1, tcpFlags{psh: true, ack: true}, []byte(payload)),
		frame(client, server, clientPort, serverPort, clientISN+1+uint32(len(payload)), serverISN+1, tcpFlags{fin: true, ack: true}, nil),
	}
}

func writePcap(t *testing.T, path string, frames [][]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	for i, data := range frames {
		ci := gopacket.CaptureInfo{Timestamp: base.Add(time.Duration(i) * 10 * time.Millisecond), CaptureLength: len(data), Length: len(data)}
		if err := w.WritePacket(ci, data); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseFilePcapExtractsHTTP(t *testing.T) {
	client := net.IP{10, 1, 2, 3}
	server := net.IP{10, 9, 8, 7}
	frames := httpExchangeFrames(client, server, 12345, 80, "GET /hello?x=1 HTTP/1.1\r\nHost: example.test\r\nX-Trace: abc\r\n\r\n")

	path := filepath.Join(t.TempDir(), "traffic.pcap")
	writePcap(t, path, frames)

	p := NewPCAPParser(nil)
	cap, err := p.ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if cap.Format != FormatPCAP {
		t.Errorf("Format = %v, want %v", cap.Format, FormatPCAP)
	}
	if len(cap.Packets) != 1 {
		t.Fatalf("packets = %d, want 1 (headers %v)", len(cap.Packets), cap.Metadata)
	}
	pkt := cap.Packets[0]
	if pkt.Method != "GET" {
		t.Errorf("Method = %q, want GET", pkt.Method)
	}
	if pkt.URL != "/hello?x=1" {
		t.Errorf("URL = %q, want /hello?x=1", pkt.URL)
	}
	// net/http promotes Host out of the header map into req.Host, so only the
	// remaining headers survive in Packet.Headers.
	if got := pkt.Headers.Get("X-Trace"); got != "abc" {
		t.Errorf("X-Trace header = %q, want abc", got)
	}
	if pkt.SrcIP.String() != "10.1.2.3" || pkt.DstIP.String() != "10.9.8.7" {
		t.Errorf("src/dst = %v/%v, want 10.1.2.3/10.9.8.7", pkt.SrcIP, pkt.DstIP)
	}
	if cap.Metadata["http_requests"] != "1" {
		t.Errorf("http_requests metadata = %q, want 1", cap.Metadata["http_requests"])
	}
	if cap.Metadata["total_packets"] != "5" {
		t.Errorf("total_packets metadata = %q, want 5", cap.Metadata["total_packets"])
	}
	if cap.StartTime.IsZero() || cap.EndTime.Before(cap.StartTime) {
		t.Errorf("timestamps not set: start=%v end=%v", cap.StartTime, cap.EndTime)
	}
}

func TestParseFilePcapNGExtractsHTTP(t *testing.T) {
	frames := httpExchangeFrames(net.IP{192, 168, 0, 1}, net.IP{192, 168, 0, 2}, 40000, 8080,
		"POST /submit HTTP/1.1\r\nHost: ng.test\r\nContent-Length: 3\r\n\r\nabc")

	path := filepath.Join(t.TempDir(), "traffic.pcapng")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("NewNgWriter: %v", err)
	}
	base := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	for i, data := range frames {
		ci := gopacket.CaptureInfo{Timestamp: base.Add(time.Duration(i) * 10 * time.Millisecond), CaptureLength: len(data), Length: len(data)}
		if err := w.WritePacket(ci, data); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	p := NewPCAPParser(nil)
	cap, err := p.ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile(pcapng): %v", err)
	}
	if len(cap.Packets) != 1 {
		t.Fatalf("packets = %d, want 1", len(cap.Packets))
	}
	pkt := cap.Packets[0]
	if pkt.Method != "POST" || pkt.URL != "/submit" || string(pkt.Body) != "abc" {
		t.Errorf("packet = %s %s body=%q, want POST /submit body=abc", pkt.Method, pkt.URL, pkt.Body)
	}
}

func TestParseFileErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		if _, err := NewPCAPParser(nil).ParseFile(filepath.Join(t.TempDir(), "absent.pcap")); err == nil {
			t.Fatal("ParseFile(missing) = nil error, want an open failure")
		}
	})

	t.Run("unrecognized magic", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.pcap")
		if err := os.WriteFile(path, []byte("not a capture at all"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := NewPCAPParser(nil).ParseFile(path); err == nil {
			t.Fatal("ParseFile(bad magic) = nil error, want a sniff failure")
		}
	})

	t.Run("truncated pcap header", func(t *testing.T) {
		// Correct magic, but the rest of the 24-byte file header is missing.
		path := filepath.Join(t.TempDir(), "short.pcap")
		if err := os.WriteFile(path, []byte{0xd4, 0xc3, 0xb2, 0xa1}, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := NewPCAPParser(nil).ParseFile(path); err == nil {
			t.Fatal("ParseFile(truncated) = nil error, want a reader failure")
		}
	})
}

// faultySource is a pcapPacketSource that reports a read error before EOF, so
// readAllPackets' corrupt-frame tolerance branch runs.
type faultySource struct {
	errs int
}

func (f *faultySource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if f.errs > 0 {
		f.errs--
		return nil, gopacket.CaptureInfo{}, io.ErrUnexpectedEOF
	}
	return nil, gopacket.CaptureInfo{}, io.EOF
}

func (f *faultySource) LinkType() layers.LinkType { return layers.LinkTypeEthernet }

func TestReadAllPacketsToleratesCorruptFrame(t *testing.T) {
	p := NewPCAPParser(nil)
	p.readAllPackets(&faultySource{errs: 2})
	if p.stats.Errors != 2 {
		t.Errorf("stats.Errors = %d, want 2", p.stats.Errors)
	}
	if p.stats.TotalPackets != 0 {
		t.Errorf("stats.TotalPackets = %d, want 0", p.stats.TotalPackets)
	}
}

func TestProcessPacketSkipsNonTCP(t *testing.T) {
	// An ARP-ish frame has no network layer: processPacket must skip it.
	p := NewPCAPParser(nil)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{Operation: layers.ARPRequest}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, arp); err != nil {
		t.Fatal(err)
	}
	p.processPacketData(buf.Bytes(), layers.LinkTypeEthernet, time.Now())
	if p.stats.TCPPackets != 0 || len(p.capture.Packets) != 0 {
		t.Errorf("non-TCP frame was processed: stats=%+v packets=%d", p.stats, len(p.capture.Packets))
	}

	// A UDP datagram has a network layer but no TCP layer.
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}}
	udp := &layers.UDP{SrcPort: 53, DstPort: 53}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf = gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload([]byte("dns"))); err != nil {
		t.Fatal(err)
	}
	eth.EthernetType = layers.EthernetTypeIPv4
	buf = gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload([]byte("dns"))); err != nil {
		t.Fatal(err)
	}
	p.processPacketData(buf.Bytes(), layers.LinkTypeEthernet, time.Now())
	if p.stats.TCPPackets != 0 {
		t.Errorf("UDP frame counted as TCP: stats=%+v", p.stats)
	}
}
