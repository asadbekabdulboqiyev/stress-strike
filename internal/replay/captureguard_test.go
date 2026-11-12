package replay

// captureguard_test.go — the pre-validation of attacker-declared capture sizes.
//
// The pure-Go pcapgo readers allocate from numbers that come out of the
// capture file itself: a classic-pcap frame is bounded only by the file's own
// snaplen, and an Enhanced Packet Block's captured length is not bounded at
// all. So a ~100-byte file can ask this process for 4 GiB. The guard in
// captureguard.go is the only thing between a hostile capture and that
// allocation, and these tests are what prove it refuses.
//
// Every hostile file below is written byte by byte on purpose: a pcapng writer
// would refuse to produce an impossible declaration, which is the whole point.

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// openFile opens path for the guard, which reads and seeks it.
func openFile(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// writeFile writes raw bytes to a fresh temp file and returns its path.
func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// pcapHeader builds a classic-pcap global header with the given snaplen.
func pcapHeader(t *testing.T, order binary.ByteOrder, snapLen uint32) []byte {
	t.Helper()
	hdr := make([]byte, 24)
	order.PutUint32(hdr[0:4], pcapMagicMicrosLE)
	order.PutUint16(hdr[4:6], 2) // version major
	order.PutUint16(hdr[6:8], 4) // version minor
	order.PutUint32(hdr[8:12], 0)
	order.PutUint32(hdr[12:16], 0)
	order.PutUint32(hdr[16:20], snapLen)
	order.PutUint32(hdr[20:24], 1) // Ethernet
	return hdr
}

// ngBlock assembles one pcapng block: type, total length, body, total length.
// The body must already be padded to a 4-byte boundary.
func ngBlock(order binary.ByteOrder, blockType uint32, body []byte) []byte {
	total := 12 + len(body)
	out := make([]byte, total)
	order.PutUint32(out[0:4], blockType)
	order.PutUint32(out[4:8], uint32(total))
	copy(out[8:8+len(body)], body)
	order.PutUint32(out[total-4:], uint32(total))
	return out
}

// ngSectionHeader builds a Section Header Block in little-endian order.
func ngSectionHeader(order binary.ByteOrder) []byte {
	body := make([]byte, 24)
	order.PutUint32(body[0:4], ngByteOrderMagic)
	order.PutUint16(body[4:6], 1) // major
	order.PutUint16(body[6:8], 0) // minor
	// section length: -1 (unknown) as two 32-bit words
	order.PutUint32(body[8:12], 0xffffffff)
	order.PutUint32(body[12:16], 0xffffffff)
	// no options, just the end-of-options code (0) and length (0)
	return ngBlock(order, ngBlockSectionHeader, body)
}

// ngInterface builds an Interface Description Block declaring snapLen.
func ngInterface(order binary.ByteOrder, snapLen uint32) []byte {
	body := make([]byte, 8)
	order.PutUint16(body[0:2], uint16(layers.LinkTypeEthernet))
	order.PutUint16(body[2:4], 0)
	order.PutUint32(body[4:8], snapLen)
	return ngBlock(order, ngBlockInterfaceDescriptor, body)
}

// ngEnhancedPacket builds an Enhanced Packet Block that *declares* captured
// bytes of declared but carries only payload bytes of real data.
func ngEnhancedPacket(order binary.ByteOrder, declared uint32, payload []byte) []byte {
	// Body: iface(4) tsHigh(4) tsLow(4) caplen(4) origlen(4) data...
	body := make([]byte, 20+len(payload))
	order.PutUint32(body[0:4], 0)  // interface id
	order.PutUint32(body[4:8], 0)  // timestamp high
	order.PutUint32(body[8:12], 0) // timestamp low
	order.PutUint32(body[12:16], declared)
	order.PutUint32(body[16:20], declared)
	copy(body[20:], payload)
	// pad the body to a 4-byte boundary
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	return ngBlock(order, ngBlockEnhancedPacket, body)
}

// --- classic pcap -------------------------------------------------------------

func TestValidatePcapSnapLen(t *testing.T) {
	t.Run("a normal snaplen passes", func(t *testing.T) {
		path := writeFile(t, "ok.pcap", pcapHeader(t, binary.LittleEndian, 65535))
		if err := validateCaptureDeclarations(openFile(t, path), capturePcap); err != nil {
			t.Fatalf("validateCaptureDeclarations: %v", err)
		}
	})

	t.Run("big-endian capture is read in its own byte order", func(t *testing.T) {
		// The first version of the guard decoded the magic with the wrong byte
		// order, so this file's 65535-byte snaplen was read as 4294901760 and
		// rejected. Both byte orders must pass.
		path := writeFile(t, "be.pcap", pcapHeader(t, binary.BigEndian, 65535))
		if err := validateCaptureDeclarations(openFile(t, path), capturePcap); err != nil {
			t.Fatalf("big-endian capture rejected: %v", err)
		}
	})

	t.Run("snaplen 0 is refused", func(t *testing.T) {
		path := writeFile(t, "zero.pcap", pcapHeader(t, binary.LittleEndian, 0))
		err := validateCaptureDeclarations(openFile(t, path), capturePcap)
		if err == nil {
			t.Fatal("a capture with no frame bound must be refused")
		}
		if !strings.Contains(err.Error(), "snaplen 0") {
			t.Errorf("error = %v, want it to name the zero snaplen", err)
		}
	})

	t.Run("oversized snaplen is refused", func(t *testing.T) {
		path := writeFile(t, "big.pcap", pcapHeader(t, binary.LittleEndian, 0xFFFF0000))
		err := validateCaptureDeclarations(openFile(t, path), capturePcap)
		if err == nil {
			t.Fatal("a 4 GiB snaplen must be refused")
		}
		if !strings.Contains(err.Error(), "4294901760") {
			t.Errorf("error = %v, want it to name the declared snaplen", err)
		}
	})

	t.Run("truncated global header is refused", func(t *testing.T) {
		hdr := pcapHeader(t, binary.LittleEndian, 65535)
		path := writeFile(t, "short.pcap", hdr[:16])
		if err := validateCaptureDeclarations(openFile(t, path), capturePcap); err == nil {
			t.Fatal("a capture shorter than its global header must be refused")
		}
	})
}

// --- pcapng -------------------------------------------------------------------

// validPcapNG builds a small but structurally complete pcapng capture.
func validPcapNG(t *testing.T) []byte {
	t.Helper()
	order := binary.LittleEndian
	out := ngSectionHeader(order)
	out = append(out, ngInterface(order, 65535)...)
	out = append(out, ngEnhancedPacket(order, 4, []byte("abcd"))...)
	return out
}

func TestValidatePcapNGAcceptingAValidCapture(t *testing.T) {
	path := writeFile(t, "ok.pcapng", validPcapNG(t))
	if err := validateCaptureDeclarations(openFile(t, path), capturePcapNG); err != nil {
		t.Fatalf("a valid pcapng was rejected: %v", err)
	}
}

// TestValidatePcapNGRejectsHostileEnhancedPacket is the attack the guard
// exists for: the file is ~150 bytes, but the Enhanced Packet Block claims 4
// GiB of captured data, and pcapgo would allocate exactly that.
func TestValidatePcapNGRejectsHostileEnhancedPacket(t *testing.T) {
	order := binary.LittleEndian
	data := ngSectionHeader(order)
	data = append(data, ngInterface(order, 65535)...)
	data = append(data, ngEnhancedPacket(order, 0xFFFFFFF0, []byte("abcd"))...)

	path := writeFile(t, "hostile.pcapng", data)
	if info, err := os.Stat(path); err == nil && info.Size() > 4096 {
		t.Fatalf("fixture is %d bytes; it is meant to be tiny", info.Size())
	}

	err := validateCaptureDeclarations(openFile(t, path), capturePcapNG)
	if err == nil {
		t.Fatal("a 4 GiB captured-length declaration must be refused")
	}
	if !strings.Contains(err.Error(), "captured bytes") {
		t.Errorf("error = %v, want it to describe the oversized declaration", err)
	}
}

// TestParseFileRejectsHostileCapture proves the guard is actually wired into the
// parse path, not just callable: ParseFile must return the refusal instead of
// handing the file to gopacket.
func TestParseFileRejectsHostileCapture(t *testing.T) {
	order := binary.LittleEndian
	data := ngSectionHeader(order)
	data = append(data, ngInterface(order, 65535)...)
	data = append(data, ngEnhancedPacket(order, 0xFFFFFFF0, []byte("abcd"))...)

	path := writeFile(t, "hostile.pcapng", data)
	if _, err := NewPCAPParser(nil).ParseFile(path); err == nil {
		t.Fatal("ParseFile accepted a capture declaring a 4 GiB frame")
	}
}

func TestValidatePcapNGRejectsOversizedInterfaceSnapLen(t *testing.T) {
	order := binary.LittleEndian
	data := ngSectionHeader(order)
	data = append(data, ngInterface(order, 0xFFFFFFFF)...)

	path := writeFile(t, "hostile-iface.pcapng", data)
	err := validateCaptureDeclarations(openFile(t, path), capturePcapNG)
	if err == nil {
		t.Fatal("an interface declaring a 4 GiB snaplen must be refused")
	}
	if !strings.Contains(err.Error(), "snaplen") {
		t.Errorf("error = %v, want it to name the snaplen", err)
	}
}

func TestValidatePcapNGRejectsTruncatedBlock(t *testing.T) {
	order := binary.LittleEndian
	data := ngSectionHeader(order)
	data = append(data, ngInterface(order, 65535)...)
	// A block header that claims more bytes than the file holds.
	tail := make([]byte, 8)
	order.PutUint32(tail[0:4], ngBlockEnhancedPacket)
	order.PutUint32(tail[4:8], 4096)
	data = append(data, tail...)

	path := writeFile(t, "truncated.pcapng", data)
	err := validateCaptureDeclarations(openFile(t, path), capturePcapNG)
	if err == nil {
		t.Fatal("a block running past the end of the file must be refused")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("error = %v, want it to say the capture is truncated", err)
	}
}

func TestValidatePcapNGRejectsInvalidBlockLength(t *testing.T) {
	order := binary.LittleEndian
	data := ngSectionHeader(order)
	// total length 7: below the 12-byte minimum and not 4-byte aligned.
	bad := make([]byte, 12)
	order.PutUint32(bad[0:4], ngBlockInterfaceDescriptor)
	order.PutUint32(bad[4:8], 7)
	data = append(data, bad...)

	path := writeFile(t, "badlen.pcapng", data)
	if err := validateCaptureDeclarations(openFile(t, path), capturePcapNG); err == nil {
		t.Fatal("a block with a 7-byte length must be refused")
	}
}

func TestValidatePcapNGRejectsMissingSectionHeader(t *testing.T) {
	order := binary.LittleEndian
	data := ngInterface(order, 65535)

	path := writeFile(t, "nosection.pcapng", data)
	if err := validateCaptureDeclarations(openFile(t, path), capturePcapNG); err == nil {
		t.Fatal("a pcapng that does not start with a section header must be refused")
	}
}

// TestValidatePcapNGRejectsCapturedLengthLargerThanTheBlock: a declaration the
// block cannot physically hold is unsatisfiable, and pcapgo's trailing Discard
// would go negative.
func TestValidatePcapNGRejectsCapturedLengthLargerThanTheBlock(t *testing.T) {
	order := binary.LittleEndian
	data := ngSectionHeader(order)
	data = append(data, ngInterface(order, 65535)...)

	// Declares 900 bytes captured inside a block that holds four.
	data = append(data, ngEnhancedPacket(order, 900, []byte("abcd"))...)

	path := writeFile(t, "overfull.pcapng", data)
	if err := validateCaptureDeclarations(openFile(t, path), capturePcapNG); err == nil {
		t.Fatal("a captured length larger than its block must be refused")
	}
}

// TestValidateCaptureDeclarationsRewinds keeps the contract that the caller can
// hand the same file to pcapgo afterwards.
func TestValidateCaptureDeclarationsRewinds(t *testing.T) {
	path := writeFile(t, "ok.pcap", pcapHeader(t, binary.LittleEndian, 65535))
	f := openFile(t, path)

	if err := validateCaptureDeclarations(f, capturePcap); err != nil {
		t.Fatalf("validateCaptureDeclarations: %v", err)
	}

	pos, err := f.Seek(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if pos != 0 {
		t.Errorf("file position after validation = %d, want 0", pos)
	}
}

// TestParseFileStillParsesAValidPcapNG is the other half of the guard's
// contract: it must not reject the captures this tool is meant to read.
func TestParseFileStillParsesAValidPcapNG(t *testing.T) {
	client := net.IP{10, 1, 2, 3}
	server := net.IP{10, 9, 8, 7}
	frames := httpExchangeFrames(client, server, 12345, 80,
		"GET /guarded HTTP/1.1\r\nHost: example.test\r\n\r\n")

	path := filepath.Join(t.TempDir(), "ok.pcapng")
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
		ci := gopacket.CaptureInfo{
			Timestamp:     base.Add(time.Duration(i) * 10 * time.Millisecond),
			CaptureLength: len(data),
			Length:        len(data),
		}
		if err := w.WritePacket(ci, data); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	cap, err := NewPCAPParser(nil).ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile(valid pcapng): %v", err)
	}
	if len(cap.Packets) != 1 {
		t.Fatalf("packets = %d, want 1", len(cap.Packets))
	}
	if cap.Packets[0].URL != "/guarded" {
		t.Errorf("URL = %q, want /guarded", cap.Packets[0].URL)
	}
}
