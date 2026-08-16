package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/aa-blinov/vibe-vpn/internal/crypto"
)

// loadPrivateKey returns the X25519 private key from the config, decrypting it
// when stored encrypted. The passphrase is taken from VIBE_VPN_PASSPHRASE or,
// when stdin is a terminal, prompted without echo.
func loadPrivateKey(priv, encrypted string) ([]byte, error) {
	if encrypted == "" {
		return crypto.DecodeKey(priv)
	}
	passphrase := os.Getenv("VIBE_VPN_PASSPHRASE")
	if passphrase == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, errors.New("encrypted key requires a passphrase: set VIBE_VPN_PASSPHRASE or run from a terminal")
		}
		fmt.Fprint(os.Stderr, "passphrase: ")
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		passphrase = string(raw)
	}
	return crypto.DecryptKey(encrypted, passphrase)
}
