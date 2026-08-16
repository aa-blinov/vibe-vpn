// Package tun provides a minimal tunnel interface for the tunnel data plane.
//
// On Linux this is a TUN device (/dev/net/tun); on Windows it is a Wintun
// adapter. Both implementations satisfy the Device interface, so the session
// and CLI layers are platform-independent.
package tun

// Device is a tunnel interface delivering and accepting whole IP packets.
type Device interface {
	Name() string
	Close() error
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
}
