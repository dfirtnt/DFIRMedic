package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/build"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/connect"
	"github.com/dfirtnt/DFIRMedic/internal/manifest"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/sign"
	"github.com/dfirtnt/DFIRMedic/internal/stage"
	"github.com/dfirtnt/DFIRMedic/internal/tailscale"
	"github.com/dfirtnt/DFIRMedic/internal/teardown"
	"github.com/dfirtnt/DFIRMedic/internal/ui"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

// ---------- parsing ----------

type stageOpts struct {
	Kit, WorkDir string
	DryRun       bool
}

func parseStage(args []string, exePath string) (stageOpts, error) {
	var o stageOpts
	fs := flag.NewFlagSet("stage", flag.ContinueOnError)
	fs.StringVar(&o.Kit, "kit", exeDir(exePath), "kit directory (default: directory of this executable)")
	fs.StringVar(&o.WorkDir, "workdir", "", "working directory (default: C:\\ProgramData\\DFIRMedic\\<case_id>)")
	fs.BoolVar(&o.DryRun, "dry-run", false, "log every command without executing")
	return o, fs.Parse(args)
}

// exeDir returns the directory portion of an executable path. It splits on
// either '/' or '\' rather than deferring to filepath.Dir's host-OS-specific
// separator: the victim-host binary always runs on Windows and os.Executable
// there returns a backslash-separated path, but this package (and its tests)
// also builds and runs on darwin/linux for the responder-side commands and
// for `go test`, where filepath.Dir only recognizes '/'. Without this, a
// Windows-style path like `C:\usb\dfirmedic.exe` would resolve to "." when
// the test (or a cross-compiled tool) runs on a non-Windows host.
func exeDir(exePath string) string {
	if i := strings.LastIndexAny(exePath, `/\`); i > 0 {
		return exePath[:i]
	}
	return "."
}

func defaultWorkDir(caseID string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(`C:\ProgramData`, "DFIRMedic", caseID)
	}
	return filepath.Join(os.TempDir(), "DFIRMedic", caseID)
}

func parseBuild(args []string) (build.Options, error) {
	var o build.Options
	var dns, ttl string
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.StringVar(&o.CaseID, "case", "", "case id")
	fs.StringVar(&o.AuthKey, "authkey", "", "ephemeral tagged Tailscale auth key")
	fs.StringVar(&o.Hostname, "hostname", "", "tailnet hostname (default ir-<case>)")
	fs.StringVar(&o.ResponderNodeKey, "responder-node-key", "", "responder node public key (tailscale status --json --self)")
	fs.StringVar(&o.ResponderIP, "responder-ip", "", "responder tailnet IP")
	fs.StringVar(&o.ServerURL, "server-url", "", "Velociraptor server URL on the tailnet")
	fs.StringVar(&dns, "dns", "1.1.1.1,9.9.9.9", "comma-separated pinned DNS resolvers")
	fs.BoolVar(&o.AllowRDP, "rdp", false, "allow RDP from the responder")
	fs.BoolVar(&o.DNSFallbackDHCP, "dns-dhcp-fallback", false, "also allow the DHCP resolver")
	fs.IntVar(&o.TunnelTimeoutSec, "tunnel-timeout", 600, "seconds")
	fs.IntVar(&o.HeartbeatGraceSec, "heartbeat-grace", 300, "seconds")
	fs.StringVar(&o.ContactName, "name", "", "responder name shown on the beacon")
	fs.StringVar(&o.ContactPhone, "phone", "", "responder phone shown on the beacon")
	fs.StringVar(&o.BreakglassCode, "breakglass-code", "", "local rollback code")
	fs.StringVar(&ttl, "ttl", "24h", "incident.json validity")
	fs.StringVar(&o.PayloadDir, "payload", "payload", "payload source dir")
	fs.StringVar(&o.ExePath, "exe", filepath.Join("dist", "dfirmedic.exe"), "Windows orchestrator binary")
	fs.StringVar(&o.FieldCardPath, "card", "FIELD-CARD.md", "field card template")
	fs.StringVar(&o.OutDir, "out", "", "USB mount point")
	fs.StringVar(&o.PrivKeyPath, "key", defaultKeyPath(), "responder private key")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	var missing []string
	for name, v := range map[string]string{"case": o.CaseID, "authkey": o.AuthKey, "responder-node-key": o.ResponderNodeKey,
		"responder-ip": o.ResponderIP, "server-url": o.ServerURL, "phone": o.ContactPhone, "name": o.ContactName,
		"breakglass-code": o.BreakglassCode, "out": o.OutDir} {
		if v == "" {
			missing = append(missing, "--"+name)
		}
	}
	if len(missing) > 0 {
		return o, fmt.Errorf("missing required flags: %s", strings.Join(missing, " "))
	}
	for _, r := range strings.Split(dns, ",") {
		if r = strings.TrimSpace(r); r != "" {
			o.DNSResolvers = append(o.DNSResolvers, r)
		}
	}
	d, err := time.ParseDuration(ttl)
	if err != nil {
		return o, fmt.Errorf("--ttl: %w", err)
	}
	o.TTL = d
	return o, nil
}

func defaultKeyPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".dfirmedic", "responder.key")
}

// ---------- shared wiring ----------

type host struct {
	inc    *config.Incident
	raw    []byte
	sig    []byte
	pub    ed25519.PublicKey
	log    *audit.Log
	man    *audit.Manifest
	r      runner.Runner
	beacon *ui.Beacon
	fw     win.Firewall
	net    win.Net
	sys    win.Sys
	ts     tailscale.Client
	velo   velo.Client
}

// openHost loads config+sig from dir, opens the audit log in workDir, and wires the runner.
func openHost(dir, workDir string, dryRun bool) (*host, error) {
	inc, raw, err := config.Load(filepath.Join(dir, "incident.json"))
	if err != nil {
		return nil, err
	}
	sig, err := sign.ReadSig(filepath.Join(dir, "incident.json.sig"))
	if err != nil {
		return nil, err
	}
	pub, err := sign.EmbeddedPublicKey()
	if err != nil {
		return nil, err
	}
	if workDir == "" {
		workDir = defaultWorkDir(inc.CaseID)
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, err
	}
	log, err := audit.Open(filepath.Join(workDir, "audit.jsonl"), nil)
	if err != nil {
		return nil, err
	}
	man, err := audit.LoadManifest(filepath.Join(workDir, "manifest.json"))
	if err != nil {
		man = &audit.Manifest{CaseID: inc.CaseID, Phases: map[string]time.Time{}}
	}
	var r runner.Runner = runner.NewExec(log, man)
	if dryRun {
		r = runner.NewDryRun(log)
	}
	ui.EnableVT()
	payload := filepath.Join(workDir, "payload")
	return &host{
		inc: inc, raw: raw, sig: sig, pub: pub, log: log, man: man, r: r,
		beacon: ui.New(os.Stdout, inc.Contact),
		fw:     win.Firewall{R: r}, net: win.Net{R: r}, sys: win.Sys{R: r},
		ts:   tailscale.Client{R: r, MSIPath: filepath.Join(payload, "tailscale-setup.msi")},
		velo: velo.Client{R: r, ExePath: filepath.Join(payload, "velociraptor.exe"), ConfigPath: filepath.Join(payload, "velociraptor.client.yaml")},
	}, nil
}

func hold() {
	fmt.Fprintln(os.Stderr, "\nPress Ctrl-C to close this window.")
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}

func ctx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// ---------- commands ----------

func cmdStage(args []string) int {
	exe, _ := os.Executable()
	o, err := parseStage(args, exe)
	if err != nil {
		return 2
	}
	h, err := openHost(o.Kit, o.WorkDir, o.DryRun)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	workDir := o.WorkDir
	if workDir == "" {
		workDir = defaultWorkDir(h.inc.CaseID)
	}
	exeHash, _ := manifest.HashFile(exe)
	c, cancel := ctx()
	defer cancel()
	d := stage.Deps{
		Inc: h.inc, RawConfig: h.raw, Sig: h.sig, PubKey: h.pub, KitDir: o.Kit, WorkDir: workDir, ExeSHA256: exeHash,
		R: h.r, Log: h.log, Man: h.man, Beacon: h.beacon, FW: h.fw, Net: h.net, Sys: h.sys, TS: h.ts, Velo: h.velo,
		Now: time.Now, Elevated: win.IsElevated,
	}
	if err := stage.Run(c, d); err != nil {
		h.beacon.Set(ui.Error, firstWord(err.Error())+" — staging failed")
		_ = h.log.Record("error", map[string]string{"error": err.Error()})
		hold()
		return 1
	}
	return runConnect(c, h, workDir)
}

func runConnect(c context.Context, h *host, workDir string) int {
	d := connect.Deps{
		Inc: h.inc, WorkDir: workDir, R: h.r, Log: h.log, Man: h.man, Beacon: h.beacon,
		Net: h.net, TS: h.ts, Velo: h.velo,
	}
	if err := connect.Run(c, d); err != nil {
		_ = h.log.Record("error", map[string]string{"error": err.Error()})
		hold()
		return 1
	}
	return 0
}

func cmdConnect(args []string) int {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	workDir := fs.String("workdir", "", "working directory")
	dry := fs.Bool("dry-run", false, "")
	if err := fs.Parse(args); err != nil || *workDir == "" {
		fmt.Fprintln(os.Stderr, "connect: --workdir required")
		return 2
	}
	h, err := openHost(*workDir, *workDir, *dry)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	c, cancel := ctx()
	defer cancel()
	return runConnect(c, h, *workDir)
}

func teardownDeps(h *host, workDir string) teardown.Deps {
	return teardown.Deps{Inc: h.inc, WorkDir: workDir, R: h.r, Log: h.log, Man: h.man,
		FW: h.fw, Sys: h.sys, TS: h.ts, Velo: h.velo, Now: time.Now}
}

func cmdTeardown(args []string) int {
	fs := flag.NewFlagSet("teardown", flag.ContinueOnError)
	workDir := fs.String("workdir", "", "working directory")
	purge := fs.Bool("purge", false, "delete the working directory afterwards")
	dry := fs.Bool("dry-run", false, "")
	if err := fs.Parse(args); err != nil || *workDir == "" {
		fmt.Fprintln(os.Stderr, "teardown: --workdir required")
		return 2
	}
	h, err := openHost(*workDir, *workDir, *dry)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	c, cancel := ctx()
	defer cancel()
	err = teardown.Run(c, teardownDeps(h, *workDir))
	if err != nil {
		fmt.Fprintln(os.Stderr, "teardown completed with errors:\n", err)
	}
	if *purge && !*dry {
		h.log.Close()
		if rmErr := os.RemoveAll(*workDir); rmErr != nil {
			fmt.Fprintln(os.Stderr, rmErr)
			return 1
		}
	}
	if err != nil {
		return 1
	}
	fmt.Println("teardown complete")
	return 0
}

func cmdBreakglass(args []string) int {
	fs := flag.NewFlagSet("breakglass", flag.ContinueOnError)
	workDir := fs.String("workdir", "", "working directory")
	code := fs.String("code", "", "break-glass code from the responder")
	if err := fs.Parse(args); err != nil || *workDir == "" || *code == "" {
		fmt.Fprintln(os.Stderr, "breakglass: --workdir and --code required")
		return 2
	}
	h, err := openHost(*workDir, *workDir, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	c, cancel := ctx()
	defer cancel()
	if err := teardown.Breakglass(c, teardownDeps(h, *workDir), *code); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("rollback complete")
	return 0
}

func cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", defaultKeyPath(), "private key path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if _, err := os.Stat(*out); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists; refusing to overwrite\n", *out)
		return 1
	}
	pub, priv, err := sign.GenerateKeypair()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := sign.WritePrivateKey(*out, priv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	hexPub := fmt.Sprintf("%x", []byte(pub))
	fmt.Printf("private key: %s\npublic key:  %s\n\nBuild the orchestrator with this key embedded:\n\n  make build-windows LDFLAGS=\"-X github.com/dfirtnt/DFIRMedic/internal/sign.embeddedPubKeyHex=%s\"\n", *out, hexPub, hexPub)
	return 0
}

func cmdBuild(args []string) int {
	o, err := parseBuild(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	res, err := build.Build(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("kit written to %s (%d files)\nincident config: %s\n", o.OutDir, len(res.Files), res.IncidentPath)
	return 0
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	kit := fs.String("kit", "", "kit directory")
	keyPath := fs.String("key", defaultKeyPath(), "responder private key (public key derived)")
	if err := fs.Parse(args); err != nil || *kit == "" {
		fmt.Fprintln(os.Stderr, "verify: --kit required")
		return 2
	}
	pub, err := sign.EmbeddedPublicKey()
	if err != nil {
		priv, kerr := sign.ReadPrivateKey(*keyPath)
		if kerr != nil {
			fmt.Fprintln(os.Stderr, errors.Join(err, kerr))
			return 1
		}
		pub = priv.Public().(ed25519.PublicKey)
	}
	inc, err := build.Verify(*kit, pub, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "INVALID:", err)
		return 1
	}
	fmt.Printf("OK: case %s, expires %s\n", inc.CaseID, inc.ExpiresUTC.Format(time.RFC3339))
	return 0
}

func firstWord(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i]
	}
	return s
}
