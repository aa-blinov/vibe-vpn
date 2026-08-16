// Package ippkt provides minimal IPv4 header parsing for tunnel traffic.
// Only IPv4 is supported in this version; any other traffic is dropped.
package ippkt

import (
	"encoding/binary"
	"net"
)

// Header describes the IPv4 fields we care about.
type Header struct {
	Src net.IP
	Dst net.IP
}

// Parse extracts the IPv4 header from a raw packet. It returns ok=false for
// anything that is not a sane IPv4 packet.
func Parse(pkt []byte) (Header, bool) {
	if len(pkt) < 20 {
		return Header{}, false
	}
	version := pkt[0] >> 4
	if version != 4 {
		return Header{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl > len(pkt) {
		return Header{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl || totalLen > len(pkt) {
		return Header{}, false
	}
	return Header{
		Src: net.IP(pkt[12:16]).To4(),
		Dst: net.IP(pkt[16:20]).To4(),
	}, true
}
