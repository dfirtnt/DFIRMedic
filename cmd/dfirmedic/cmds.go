package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
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
	"github.com/dfirtnt/DFIRMedic/internal/probe"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/sign"
	"github.com/dfirtnt/DFIRMedic/internal/stage"
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
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if err := validateWorkDir(o.WorkDir); err != nil {
		return o, err
	}
	return o, nil
}

// validateWorkDir rejects a --workdir value that would break unquoted
// re-parsing of the scheduled task command line CreateStartupTask registers
// for reboot-resume (internal/win.Sys.CreateStartupTask builds /TR as
// `"<exe>" <args>` with args, including "--workdir <value>", left unquoted).
// A space would truncate the value when Windows re-parses that command line
// on reboot, and a quote would let the value break out of/interfere with
// argument boundaries; both are rejected up front so the failure is visible
// at install time instead of silently at reboot-resume time.
func validateWorkDir(v string) error {
	if strings.ContainsAny(v, " \"") {
		return fmt.Errorf("--workdir must not contain spaces or quotes: %q", v)
	}
	return nil
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
	i := strings.LastIndexAny(exePath, `/\`)
	switch {
	case i < 0:
		return "."
	case i == 0: // "/foo" -> "/"
		return exePath[:1]
	case i == 2 && exePath[1] == ':': // `E:\foo` -> `E:\`
		return exePath[:3]
	default:
		return exePath[:i]
	}
}

func defaultWorkDir(caseID string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(`C:\ProgramData`, "DFIRMedic", caseID)
	}
	return filepath.Join(os.TempDir(), "DFIRMedic", caseID)
}

func parseBuild(args []string) (build.Options, error) {
	var o build.Options
	var ttl string
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.StringVar(&o.CaseID, "case", "", "case id")
	fs.StringVar(&o.ServerURL, "server-url", "", "Velociraptor server URL, https://<public-ip>[:port]/ (IP literal; default port 443)")
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
	for name, v := range map[string]string{"case": o.CaseID, "server-url": o.ServerURL, "phone": o.ContactPhone,
		"name": o.ContactName, "breakglass-code": o.BreakglassCode, "out": o.OutDir} {
		if v == "" {
			missing = append(missing, "--"+name)
		}
	}
	if len(missing) > 0 {
		return o, fmt.Errorf("missing required flags: %s", strings.Join(missing, " "))
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
	caPEM  []byte
	caErr  error // why caPEM is empty; only connect cares
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
	// Best-effort: teardown and breakglass must open a host whose working
	// directory is damaged or half-written, so a missing or unparseable
	// client config is recorded here and only becomes fatal in
	// verifyKitForConnect, on the one path that needs the CA.
	caPEM, caErr := readClientCA(dir)
	return &host{
		inc: inc, raw: raw, sig: sig, pub: pub, log: log, man: man, r: r,
		beacon: ui.New(os.Stdout, inc.Contact),
		fw:     win.Firewall{R: r}, net: win.Net{R: r}, sys: win.Sys{R: r},
		caPEM: caPEM, caErr: caErr,
		velo: velo.Client{R: r, ExePath: filepath.Join(payload, "velociraptor.exe"), ConfigPath: filepath.Join(payload, "velociraptor.client.yaml")},
	}, nil
}

// readClientCA pulls the pinned CA out of the shipped
// payload/velociraptor.client.yaml. Everything downstream of it - the TLS
// probe that decides whether the host may stay online, and the E18 check
// that the kit was built against the signed server - is meaningless without
// it, so a missing or unparseable client config is an error with the reason
// attached rather than a silently nil CA that surfaces ten minutes later as
// a bare E50. openHost stores that error on the host; connect refuses it,
// teardown and breakglass ignore it.
func readClientCA(dir string) ([]byte, error) {
	p := filepath.Join(dir, "payload", "velociraptor.client.yaml")
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read Velociraptor client config: %w", err)
	}
	pem, err := velo.ExtractCA(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return pem, nil
}

// verifyKitForConnect re-runs, on the reboot-resume path, the two checks
// stage.Preflight makes before it touches the host: incident.json really is
// the responder's (E11), and the client config in the payload carries the CA
// that incident.json was signed with (E18). cmdStage reaches connect only
// after Preflight, but `dfirmedic connect --workdir ...` - which the startup
// task runs after a reboot - previously went straight to probing whatever
// files happened to be in the working directory. teardown and breakglass do
// not probe or start anything and are left alone.
func verifyKitForConnect(h *host) error {
	if h.caErr != nil {
		return fmt.Errorf("client config missing or unreadable: %w — cannot verify the server without its CA", h.caErr)
	}
	if len(h.caPEM) == 0 {
		return errors.New("client config missing or unreadable: no CA certificate — cannot verify the server without its CA")
	}
	if !sign.Verify(h.pub, h.raw, h.sig) {
		return errors.New("E11 incident.json signature invalid")
	}
	fp, err := velo.CAFingerprint(h.caPEM)
	if err != nil {
		return fmt.Errorf("E18 client config CA unreadable: %w", err)
	}
	if fp != h.inc.Server.CASHA256 {
		return fmt.Errorf("E18 client config CA %s does not match signed incident.json (%s) — "+
			"the working directory was assembled from a different server", fp, h.inc.Server.CASHA256)
	}
	return nil
}

// hold keeps the console open so the operator can read what went wrong; a
// variable so tests can stub the blocking wait.
var hold = func() {
	fmt.Fprintln(os.Stderr, "\nPress Ctrl-C to close this window.")
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}

// holdIfConsole is hold(), skipped when there is no interactive console.
// cmdConnect serves both the double-click path (a real console, inherited
// from the exec.Command in execConnect) and the reboot-resume path (a
// SYSTEM-owned scheduled task with no console at all) - hold() there would
// block forever waiting for a Ctrl-C nothing can ever send, instead of
// letting the process exit with its real status.
func holdIfConsole() {
	if hasConsole() {
		hold()
	}
}

func ctx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// ---------- commands ----------

func cmdStage(args []string) int {
	exe, _ := os.Executable()
	o, err := parseStage(args, exe)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		hold()
		return 2
	}
	h, err := openHost(o.Kit, o.WorkDir, o.DryRun)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		hold()
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
		R: h.r, Log: h.log, Man: h.man, Beacon: h.beacon, FW: h.fw, Net: h.net, Sys: h.sys, Velo: h.velo,
		Now: time.Now, Elevated: win.IsElevated,
	}
	if err := stage.Run(c, d); err != nil {
		h.beacon.Set(ui.Error, firstWord(err.Error())+" — staging failed")
		_ = h.log.Record("error", map[string]string{"error": err.Error()})
		hold()
		return 1
	}
	return execConnect(workDir)
}

// execConnect hands the connect phase to the dfirmedic.exe copy BASELINE
// placed in workDir, as a new process, instead of continuing in this one.
// The quarantine firewall rule's orchestrator-probe allow-rule (stage.go
// ServerRules) is scoped to that copy's path — Windows Firewall matches a
// program rule against the on-disk path of the running image, so if this
// process (launched from wherever the kit was extracted) probed the server
// itself, the rule would not cover it and the dial would fail closed
// (WSAEACCES). Running the copy also matches the reboot-resume path, which
// already invokes `connect` this same way via the scheduled task.
func execConnect(workDir string) int {
	exe := filepath.Join(workDir, "dfirmedic.exe")
	cmd := exec.Command(exe, "connect", "--workdir", workDir)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "connect handoff:", err)
		hold()
		return 1
	}
	return 0
}

func runConnect(c context.Context, h *host, workDir string) int {
	d := connect.Deps{
		Inc: h.inc, WorkDir: workDir, R: h.r, Log: h.log, Man: h.man, Beacon: h.beacon,
		Net: h.net, Velo: h.velo,
		Probe: probe.TLS{IP: h.inc.Server.IP, Port: h.inc.Server.Port, CAPEM: h.caPEM, Timeout: 10 * time.Second},
	}
	if err := connect.Run(c, d); err != nil {
		_ = h.log.Record("error", map[string]string{"error": err.Error()})
		holdIfConsole()
		return 1
	}
	return 0
}

type connectOpts struct {
	WorkDir string
	DryRun  bool
}

// parseConnect defaults --workdir to the directory of this executable, the
// same way parseStage defaults --kit: dfirmedic.exe is copied into workDir
// in BASELINE precisely so a copy running from there needs no flag at all.
func parseConnect(args []string, exePath string) (connectOpts, error) {
	var o connectOpts
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.StringVar(&o.WorkDir, "workdir", exeDir(exePath), "working directory (default: directory of this executable)")
	fs.BoolVar(&o.DryRun, "dry-run", false, "")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.WorkDir == "" {
		return o, errors.New("--workdir required (could not determine this executable's directory)")
	}
	if err := validateWorkDir(o.WorkDir); err != nil {
		return o, err
	}
	return o, nil
}

func cmdConnect(args []string) int {
	exe, _ := os.Executable()
	o, err := parseConnect(args, exe)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		return 2
	}
	h, err := openHost(o.WorkDir, o.WorkDir, o.DryRun)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		holdIfConsole()
		return 1
	}
	if err := verifyKitForConnect(h); err != nil {
		fmt.Fprintln(os.Stderr, err)
		_ = h.log.Record("error", map[string]string{"error": err.Error()})
		h.beacon.Set(ui.Error, firstWord(err.Error())+" — kit verification failed")
		holdIfConsole()
		return 1
	}
	c, cancel := ctx()
	defer cancel()
	return runConnect(c, h, o.WorkDir)
}

func teardownDeps(h *host, workDir string) teardown.Deps {
	return teardown.Deps{Inc: h.inc, WorkDir: workDir, R: h.r, Log: h.log, Man: h.man,
		FW: h.fw, Net: h.net, Sys: h.sys, Velo: h.velo, Now: time.Now}
}

type teardownOpts struct {
	WorkDir string
	Purge   bool
	DryRun  bool
}

// parseTeardown defaults --workdir the same way parseConnect does.
func parseTeardown(args []string, exePath string) (teardownOpts, error) {
	var o teardownOpts
	fs := flag.NewFlagSet("teardown", flag.ContinueOnError)
	fs.StringVar(&o.WorkDir, "workdir", exeDir(exePath), "working directory (default: directory of this executable)")
	fs.BoolVar(&o.Purge, "purge", false, "delete the working directory afterwards")
	fs.BoolVar(&o.DryRun, "dry-run", false, "")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.WorkDir == "" {
		return o, errors.New("--workdir required (could not determine this executable's directory)")
	}
	if err := validateWorkDir(o.WorkDir); err != nil {
		return o, err
	}
	return o, nil
}

func cmdTeardown(args []string) int {
	exe, _ := os.Executable()
	o, err := parseTeardown(args, exe)
	if err != nil {
		fmt.Fprintln(os.Stderr, "teardown:", err)
		return 2
	}
	h, err := openHost(o.WorkDir, o.WorkDir, o.DryRun)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	c, cancel := ctx()
	defer cancel()
	err = teardown.Run(c, teardownDeps(h, o.WorkDir))
	if err != nil {
		fmt.Fprintln(os.Stderr, "teardown completed with errors:\n", err)
	}
	if o.Purge && !o.DryRun {
		h.log.Close()
		if rmErr := os.RemoveAll(o.WorkDir); rmErr != nil {
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

type breakglassOpts struct {
	WorkDir string
	Code    string
}

// parseBreakglass defaults --workdir the same way parseConnect does.
func parseBreakglass(args []string, exePath string) (breakglassOpts, error) {
	var o breakglassOpts
	fs := flag.NewFlagSet("breakglass", flag.ContinueOnError)
	fs.StringVar(&o.WorkDir, "workdir", exeDir(exePath), "working directory (default: directory of this executable)")
	fs.StringVar(&o.Code, "code", "", "break-glass code from the responder")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.WorkDir == "" {
		return o, errors.New("--workdir (could not determine this executable's directory) and --code required")
	}
	if o.Code == "" {
		return o, errors.New("--code required")
	}
	if err := validateWorkDir(o.WorkDir); err != nil {
		return o, err
	}
	return o, nil
}

func cmdBreakglass(args []string) int {
	exe, _ := os.Executable()
	o, err := parseBreakglass(args, exe)
	if err != nil {
		fmt.Fprintln(os.Stderr, "breakglass:", err)
		return 2
	}
	h, err := openHost(o.WorkDir, o.WorkDir, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	c, cancel := ctx()
	defer cancel()
	if err := teardown.Breakglass(c, teardownDeps(h, o.WorkDir), o.Code); err != nil {
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
