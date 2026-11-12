package replay

// captureguard.go — validating a capture's declared sizes before gopacket acts
// on them.
//
// The pure-Go pcapgo readers allocate from numbers the file itself supplies:
//
//   - pcapgo.Reader allocates make([]byte, ci.CaptureLength), where the only
//     bound is the global header's snaplen — also from the file;
//   - pcapgo.NgReader allocates make([]byte, ci.CaptureLength) from an Enhanced
//     Packet Block header with no bound at all.
//
// So a 60-byte file that declares a 4 GiB frame asks this process for 4 GiB.
// That is an upstream design decision (gopacket trusts capture files), and it
// is not something this project can patch without forking the dependency. What
// it can do is refuse the declaration before gopacket sees it: every capture is
// walked here first, and any declared size above maxCaptureSnapLen is rejected
// with an error naming the block.
//
// The check is structural, not heuristic: it reads exactly the fields the
// readers will read and applies the same limits a capture tool would.

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// maxCaptureSnapLen is the largest per-frame size this tool accepts.
//
// tcpdump/junos default to 262144; 1 MiB is generous for any real capture and
// small enough that a malicious declaration cannot exhaust memory.
const maxCaptureSnapLen = 1 << 20 // 1 MiB

// pcapng block types this guard interprets. Anything else is skipped: the
// readers skip unknown blocks too, and an unknown block cannot drive an
// allocation this guard is responsible for.
const (
	ngBlockSectionHeader       = 0x0A0D0D0A
	ngBlockInterfaceDescriptor = 0x00000001
	ngBlockPacket              = 0x00000002
	ngBlockSimplePacket        = 0x00000003
	ngBlockEnhancedPacket      = 0x00000006

	// ngByteOrderMagic is the byte-order magic at the start of a Section
	// Header Block body.
	ngByteOrderMagic = 0x1A2B3C4D

	// pcapMagicMicrosLE / pcapMagicNanosLE are the classic-pcap magic numbers
	// as they appear after decoding the file's own bytes with the file's own
	// byte order.
	pcapMagicMicrosLE = 0xA1B2C3D4
	pcapMagicNanosLE  = 0xA1B23C4D
)

// Header sizes for the pcapng packet blocks, counted from the start of the
// block: block header (8) + fixed body + captured data + padding + trailing
// length (4).
const (
	ngEnhancedPacketFixed = 8 + 20 + 4 // EPB: iface/ts/ts/caplen
	ngPacketFixed         = 8 + 16 + 4 // PB: iface/drops/ts/ts/caplen
)

// validateCaptureDeclarations reads the capture's structural headers and
// rejects any declared frame size above maxCaptureSnapLen.
//
// It must be called with the file positioned at 0. On success the file is
// rewound so the caller can hand it to pcapgo unchanged.
func validateCaptureDeclarations(f *os.File, kind captureFormat) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind capture: %w", err)
	}

	var err error
	switch kind {
	case capturePcap:
		err = validatePcapSnapLen(f)
	case capturePcapNG:
		err = validatePcapNGSizes(f)
	default:
		err = fmt.Errorf("unsupported capture format")
	}

	if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil && err == nil {
		return fmt.Errorf("rewind capture: %w", seekErr)
	}
	return err
}

// validatePcapSnapLen checks the classic pcap global header (24 bytes).
func validatePcapSnapLen(f *os.File) error {
	var hdr [24]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return fmt.Errorf("read pcap global header: %w", err)
	}

	// Pick the byte order from the magic. A file written by a little-endian
	// host stores 0xA1B2C3D4 (microsecond) or 0xA1B23C4D (nanosecond) in
	// little-endian order, so *decoding those bytes as little-endian* yields
	// the constant. Getting this backwards reads the snaplen from the wrong
	// end and reports a 65535-byte capture as 4294901760 — which is exactly
	// how the first version of this guard rejected its own test fixture.
	var order binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint32(hdr[0:4]) == pcapMagicMicrosLE,
		binary.LittleEndian.Uint32(hdr[0:4]) == pcapMagicNanosLE:
		order = binary.LittleEndian
	case binary.BigEndian.Uint32(hdr[0:4]) == pcapMagicMicrosLE,
		binary.BigEndian.Uint32(hdr[0:4]) == pcapMagicNanosLE:
		order = binary.BigEndian
	default:
		return fmt.Errorf("pcap magic %x is not a supported variant", hdr[0:4])
	}

	snapLen := order.Uint32(hdr[16:20])
	if snapLen == 0 {
		return fmt.Errorf("pcap declares snaplen 0; refusing a capture with no frame bound")
	}
	if snapLen > maxCaptureSnapLen {
		return fmt.Errorf("pcap declares snaplen %d, above the %d-byte limit", snapLen, maxCaptureSnapLen)
	}
	return nil
}

// validatePcapNGSizes walks the pcapng block structure.
//
// pcapgo does not bound an Enhanced Packet Block's captured length at all, so
// this walk is the only thing between a hostile file and a multi-gigabyte
// allocation.
func validatePcapNGSizes(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat capture: %w", err)
	}
	size := info.Size()

	var (
		order binary.ByteOrder // set by the Section Header Block
		off   int64
		seenS = false
	)

	for off < size {
		var hdr [8]byte
		if _, err := f.ReadAt(hdr[:], off); err != nil {
			return fmt.Errorf("read pcapng block header at %d: %w", off, err)
		}

		if !seenS {
			// The first block must be a Section Header Block; its length is
			// only readable in the byte order its own BOM declares.
			if binary.LittleEndian.Uint32(hdr[0:4]) != ngBlockSectionHeader {
				return fmt.Errorf("pcapng does not start with a section header")
			}
			var body [4]byte
			if _, err := f.ReadAt(body[:], off+8); err != nil {
				return fmt.Errorf("read pcapng byte-order magic: %w", err)
			}
			switch {
			case binary.LittleEndian.Uint32(body[:]) == ngByteOrderMagic:
				order = binary.LittleEndian
			case binary.BigEndian.Uint32(body[:]) == ngByteOrderMagic:
				order = binary.BigEndian
			default:
				return fmt.Errorf("pcapng section header has no valid byte-order magic")
			}
			seenS = true
		}

		blockType := order.Uint32(hdr[0:4])
		totalLen := int64(order.Uint32(hdr[4:8]))

		if totalLen < 12 || totalLen%4 != 0 {
			return fmt.Errorf("pcapng block at %d declares length %d, which is not a valid block length", off, totalLen)
		}
		if off+totalLen > size {
			return fmt.Errorf("pcapng block at %d ends at %d, past the %d-byte file (truncated capture)", off, off+totalLen, size)
		}

		switch blockType {
		case ngBlockSectionHeader:
			if off != 0 {
				// A new section may switch byte order.
				var body [4]byte
				if _, err := f.ReadAt(body[:], off+8); err != nil {
					return fmt.Errorf("read pcapng byte-order magic: %w", err)
				}
				switch {
				case binary.LittleEndian.Uint32(body[:]) == ngByteOrderMagic:
					order = binary.LittleEndian
				case binary.BigEndian.Uint32(body[:]) == ngByteOrderMagic:
					order = binary.BigEndian
				default:
					return fmt.Errorf("pcapng section header at %d has no valid byte-order magic", off)
				}
			}

		case ngBlockInterfaceDescriptor:
			// Body: link type (2), reserved (2), snaplen (4).
			if totalLen < 20 {
				return fmt.Errorf("pcapng interface block at %d is too short (%d bytes)", off, totalLen)
			}
			var field [4]byte
			if _, err := f.ReadAt(field[:], off+12); err != nil {
				return fmt.Errorf("read pcapng interface snaplen: %w", err)
			}
			if snapLen := order.Uint32(field[:]); snapLen > maxCaptureSnapLen {
				return fmt.Errorf("pcapng interface at %d declares snaplen %d, above the %d-byte limit",
					off, snapLen, maxCaptureSnapLen)
			}

		case ngBlockEnhancedPacket, ngBlockPacket:
			// Both put the captured length 12 bytes into the body, i.e. at
			// offset 20 of the block:
			// EPB: interface (4), ts high (4), ts low (4), captured len (4)
			// PB:  interface (2), drops (2), ts high (4), ts low (4), captured len (4)
			fixed := int64(ngEnhancedPacketFixed)
			if blockType == ngBlockPacket {
				fixed = ngPacketFixed
			}
			if totalLen < fixed {
				return fmt.Errorf("pcapng packet block at %d is too short (%d bytes)", off, totalLen)
			}
			var field [4]byte
			if _, err := f.ReadAt(field[:], off+20); err != nil {
				return fmt.Errorf("read pcapng captured length: %w", err)
			}
			captured := int64(order.Uint32(field[:]))
			if captured > maxCaptureSnapLen {
				return fmt.Errorf("pcapng packet at %d declares %d captured bytes, above the %d-byte limit",
					off, captured, maxCaptureSnapLen)
			}
			// A captured length the block cannot hold is unsatisfiable, and the
			// reader's trailing Discard would go negative. The bound accounts
			// for the block's own padding, so a valid capture is never rejected.
			if captured > totalLen-fixed {
				return fmt.Errorf("pcapng packet at %d declares %d captured bytes in a %d-byte block",
					off, captured, totalLen)
			}

		case ngBlockSimplePacket:
			if totalLen < 16 {
				return fmt.Errorf("pcapng simple packet block at %d is too short (%d bytes)", off, totalLen)
			}
			var field [4]byte
			if _, err := f.ReadAt(field[:], off+8); err != nil {
				return fmt.Errorf("read pcapng original length: %w", err)
			}
			if orig := int64(order.Uint32(field[:])); orig > maxCaptureSnapLen &&
				orig > totalLen-16 {
				return fmt.Errorf("pcapng simple packet at %d declares %d bytes, above the %d-byte limit",
					off, orig, maxCaptureSnapLen)
			}
		}

		off += totalLen
	}

	if !seenS {
		return fmt.Errorf("pcapng contains no section header block")
	}
	return nil
}
