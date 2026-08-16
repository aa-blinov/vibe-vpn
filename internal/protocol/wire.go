// Package protocol defines message types and the anti-replay sliding window.
//
// There is deliberately no fixed plaintext header in this protocol: handshake
// messages are raw Noise messages and session messages are opaque AEAD frames
// (random nonce + ciphertext) whose metadata lives inside the encrypted
// payload. This keeps the wire traffic free of an easily fingerprintable
// structure.
package protocol

import "fmt"

// Message types. Handshake messages (1..3) are raw Noise messages with no
// framing. Session messages (4..11) travel inside encrypted AEAD frames; the
// type byte is recovered only after decryption.
const (
	MsgHandshake1 byte = 0x01 // client -> server: first Noise XK message (carries session tag)
	MsgHandshake2 byte = 0x02 // server -> client: second Noise XK message
	MsgHandshake3 byte = 0x03 // client -> server: final Noise XK message
	MsgData       byte = 0x04 // encrypted IP packet
	MsgKeepalive  byte = 0x05 // encrypted RTT cookie / echo
	MsgClose      byte = 0x06 // encrypted close notification
	MsgRekey1     byte = 0x07 // client -> server: rekey handshake (inside AEAD)
	MsgRekey2     byte = 0x08 // server -> client: rekey handshake (inside AEAD)
	MsgRekey3     byte = 0x09 // client -> server: rekey handshake (inside AEAD)
	MsgAssign     byte = 0x0A // server -> client: encrypted address assignment
	MsgDecoy      byte = 0x0B // encrypted decoy traffic, discarded by the receiver
	MsgCookie     byte = 0x0C // server -> client: anti-DoS handshake cookie (raw)
)

// CookieLen is the size of an anti-DoS handshake cookie.
const CookieLen = 32

// MaxWire is the largest datagram body the protocol will produce.
const MaxWire = 65507

// MaxPayload is the largest message payload carried inside a frame.
const MaxPayload = 65535

// TypeName returns a human-readable name for a message type.
func TypeName(t byte) string {
	switch t {
	case MsgHandshake1:
		return "handshake1"
	case MsgHandshake2:
		return "handshake2"
	case MsgHandshake3:
		return "handshake3"
	case MsgData:
		return "data"
	case MsgKeepalive:
		return "keepalive"
	case MsgClose:
		return "close"
	case MsgRekey1:
		return "rekey1"
	case MsgRekey2:
		return "rekey2"
	case MsgRekey3:
		return "rekey3"
	case MsgAssign:
		return "assign"
	case MsgDecoy:
		return "decoy"
	case MsgCookie:
		return "cookie"
	}
	return fmt.Sprintf("unknown(%d)", t)
}

// IsHandshake reports whether a message type belongs to the initial (raw)
// Noise handshake. These messages are not encrypted with the data keys.
func IsHandshake(t byte) bool {
	switch t {
	case MsgHandshake1, MsgHandshake2, MsgHandshake3:
		return true
	}
	return false
}

// IsRekey reports whether a message type belongs to the in-session rekey
// handshake. Rekey messages travel inside AEAD frames but must be allowed to
// flow while a rekey is in progress.
func IsRekey(t byte) bool {
	switch t {
	case MsgRekey1, MsgRekey2, MsgRekey3:
		return true
	}
	return false
}
