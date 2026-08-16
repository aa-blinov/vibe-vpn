package pcap

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cap.pcap")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	w.WritePacket([]byte("packet-one"))
	w.WritePacket([]byte("packet-two"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 24 {
		t.Fatalf("file too small: %d", len(data))
	}
	if binary.LittleEndian.Uint32(data[0:4]) != 0xa1b2c3d4 {
		t.Fatal("bad pcap magic")
	}
	if binary.LittleEndian.Uint16(data[20:22]) != dltRaw {
		t.Fatalf("bad linktype: %d", binary.LittleEndian.Uint16(data[20:22]))
	}

	// Walk the records: 16-byte per-packet header + payload.
	off := 24
	var payloads []string
	for off < len(data) {
		plen := int(binary.LittleEndian.Uint32(data[off+8 : off+12]))
		payloads = append(payloads, string(data[off+16:off+16+plen]))
		off += 16 + plen
	}
	if len(payloads) != 2 || payloads[0] != "packet-one" || payloads[1] != "packet-two" {
		t.Fatalf("records mismatch: %v", payloads)
	}
}

func TestWriterNilAndClose(t *testing.T) {
	var w *Writer
	w.WritePacket([]byte("x")) // must not panic
	if err := w.Close(); err != nil {
		t.Fatalf("closing nil writer: %v", err)
	}

	// Opening an unwritable path fails.
	if _, err := Open(filepath.Join(t.TempDir(), "missing", "cap.pcap")); err == nil {
		t.Fatal("expected an error opening an unwritable path")
	}
}

func TestWriterCounts(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "c.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if w.Packets() != 0 {
		t.Fatalf("expected 0 packets, got %d", w.Packets())
	}
	w.WritePacket([]byte("a"))
	w.WritePacket([]byte("b"))
	if w.Packets() != 2 {
		t.Fatalf("expected 2 packets, got %d", w.Packets())
	}
	w.Close()
}
