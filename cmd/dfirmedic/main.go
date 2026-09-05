package main

import (
	"fmt"
	"os"
)

// --arch is pinned: go generate exports the host GOARCH, and go-winres would
// otherwise emit only an arm64 resource on Apple Silicon, shipping an amd64
// exe with no manifest (no UAC prompt → E10).
//go:generate go-winres make --in ../../winres/winres.json --out rsrc --arch amd64

func main() {
	name, rest := resolveCommand(os.Args)
	switch name {
	case "stage":
		os.Exit(cmdStage(rest))
	case "connect":
		os.Exit(cmdConnect(rest))
	case "teardown":
		os.Exit(cmdTeardown(rest))
	case "breakglass":
		os.Exit(cmdBreakglass(rest))
	case "keygen":
		os.Exit(cmdKeygen(rest))
	case "build":
		os.Exit(cmdBuild(rest))
	case "verify":
		os.Exit(cmdVerify(rest))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", name)
		usage()
		os.Exit(2)
	}
}

// resolveCommand maps argv to a command name and its arguments. A bare launch
// (double-click on the victim host, per the field card) means `stage`.
func resolveCommand(argv []string) (string, []string) {
	if len(argv) < 2 {
		return "stage", nil
	}
	return argv[1], argv[2:]
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: dfirmedic <command> [flags]

commands (victim host, Windows):
  stage        stage the host offline; ends at READY (default when double-clicked)
  connect      wait for link-up, verify tunnel, start Velociraptor
  teardown     remove everything and restore the firewall baseline
  breakglass   local emergency rollback; requires the break-glass code

commands (responder workstation):
  keygen       create the responder ed25519 signing keypair
  build        assemble and sign a per-incident kit onto a USB
  verify       verify a kit's signature and payload hashes`)
}
