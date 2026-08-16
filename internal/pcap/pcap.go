// Package pcap writes tunnel captures in the classic pcap file format so the
// traffic can be opened in Wireshark or tcpdump. Only IP packets that cross
// the TUN interface are recorded (linktype DLT_RAW), i.e. the decrypted
// payload, which is what passive traffic analysis will see.
package pcap

import (
	"encoding/binary"
	"os"
	"sync"
	"time"
)

// DLT_RAW, used for raw IPv4 packets (see libpcap linktype definitions).
const dltRaw = 101

// Writer is a pcap sink. It is safe for concurrent use.
type Writer struct {
	mu   sync.Mutex
	f    *os.File
	err  error
	buf  [65535]byte
	pkts uint64
}

// Open creates (or truncates) a pcap file and writes the global header.
func Open(path string) (*Writer, error) {
	f, err := os.Create(path) // #nosec G304 -- path comes from the operator's config
	if err != nil {
		return nil, err
	}
	w := &Writer{f: f}
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4) // magic
	binary.LittleEndian.PutUint16(hdr[4:6], 2)          // major
	binary.LittleEndian.PutUint16(hdr[6:8], 4)          // minor
	binary.LittleEndian.PutUint32(hdr[8:12], 0)         // thiszone
	binary.LittleEndian.PutUint32(hdr[12:16], 0)        // sigfigs
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)    // snaplen
	binary.LittleEndian.PutUint32(hdr[20:24], dltRaw)   // linktype
	if _, err := f.Write(hdr); err != nil {
		_ = f.Close()
		return nil, err
	}
	return w, nil
}

// WritePacket records one IP packet with the current timestamp.
func (w *Writer) WritePacket(pkt []byte) {
	if w == nil || w.f == nil {
		return
	}
	if len(pkt) > len(w.buf)-16 {
		pkt = pkt[:len(w.buf)-16]
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return
	}
	ts := time.Now()
	sec := ts.Unix()
	usec := ts.Nanosecond() / 1000
	// #nosec G115 -- timestamps fit uint32 until 2106; lengths are bounded below.
	binary.LittleEndian.PutUint32(w.buf[0:4], uint32(sec))
	binary.LittleEndian.PutUint32(w.buf[4:8], uint32(usec)) // #nosec G115 -- microsecond fraction fits uint32
	// #nosec G115 -- pkt was clamped to the buffer above (<= 65519 bytes).
	binary.LittleEndian.PutUint32(w.buf[8:12], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(w.buf[12:16], uint32(len(pkt))) // #nosec G115 -- same bound
	copy(w.buf[16:], pkt)
	if _, err := w.f.Write(w.buf[:16+len(pkt)]); err != nil {
		w.err = err
		return
	}
	w.pkts++
}

// Packets returns the number of packets written so far.
func (w *Writer) Packets() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pkts
}

// Close flushes and closes the file.
func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.err
	w.err = nil
	cerr := w.f.Close()
	w.f = nil
	if err != nil {
		return err
	}
	return cerr
}
