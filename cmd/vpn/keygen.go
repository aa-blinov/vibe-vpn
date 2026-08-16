package main

import (
	"fmt"

	"github.com/aa-blinov/vibe-vpn/internal/crypto"
)

func runKeygen(_ []string) error {
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		return err
	}
	fmt.Printf("private_key: %s\n", crypto.EncodeKey(kp.Private))
	fmt.Printf("public_key:  %s\n", crypto.EncodeKey(kp.Public))
	return nil
}
