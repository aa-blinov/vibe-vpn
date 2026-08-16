package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aa-blinov/vibe-vpn/internal/transport/tlsx"
)

func runCertgen(args []string) error {
	fs := flag.NewFlagSet("certgen", flag.ExitOnError)
	out := fs.String("out", "server", "output prefix (writes <out>.crt and <out>.key)")
	cn := fs.String("cn", "localhost", "certificate common name (DNS name or IP address)")
	days := fs.Int("days", 825, "validity in days")
	_ = fs.Parse(args)

	certPEM, keyPEM, err := tlsx.GenerateSelfSigned(*cn, *days)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out+".crt", certPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(*out+".key", keyPEM, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s.crt and %s.key\n", *out, *out)
	fmt.Printf("server tls:\n  cert: %s.crt\n  key: %s.key\n", *out, *out)
	fmt.Printf("client tls:\n  server_name: %s\n  ca: %s.crt\n", *cn, *out)
	return nil
}
