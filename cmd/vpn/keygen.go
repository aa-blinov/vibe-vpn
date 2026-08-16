package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/aa-blinov/vibe-vpn/internal/crypto"
)

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	encrypt := fs.Bool("encrypt", false, "encrypt the private key with a passphrase")
	passphrase := fs.String("passphrase", "", "passphrase (falls back to VIBE_VPN_PASSPHRASE or a prompt)")
	fs.Parse(args)

	kp, err := crypto.GenerateKeypair()
	if err != nil {
		return err
	}
	fmt.Printf("public_key: %s\n", crypto.EncodeKey(kp.Public))
	if !*encrypt {
		fmt.Printf("private_key: %s\n", crypto.EncodeKey(kp.Private))
		return nil
	}
	pass := *passphrase
	if pass == "" {
		pass = os.Getenv("VIBE_VPN_PASSPHRASE")
	}
	if pass == "" {
		fmt.Fprint(os.Stderr, "passphrase: ")
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		pass = string(raw)
	}
	blob, err := crypto.EncryptKey(kp.Private, pass)
	if err != nil {
		return err
	}
	fmt.Printf("private_key_encrypted: %s\n", blob)
	return nil
}
