package main

import (
	"fmt"
	"os"
)

//go:generate go-winres make --in ../../winres/winres.json --out rsrc

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: dfirmedic <command> [flags]

commands (victim host, Windows):
  stage        stage the host offline; ends at READY
  connect      wait for link-up, verify tunnel, start Velociraptor
  teardown     remove everything and restore the firewall baseline
  breakglass   local emergency rollback; requires the break-glass code

commands (responder workstation):
  keygen       create the responder ed25519 signing keypair
  build        assemble and sign a per-incident kit onto a USB
  verify       verify a kit's signature and payload hashes`)
}
