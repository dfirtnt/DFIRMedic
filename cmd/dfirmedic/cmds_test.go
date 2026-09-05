package main

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseStageDefaultsKitToExeDir(t *testing.T) {
	o, err := parseStage([]string{}, `C:\usb\dfirmedic.exe`)
	if err != nil {
		t.Fatal(err)
	}
	if o.Kit != `C:\usb` {
		t.Fatal(o.Kit)
	}
	if o.DryRun {
		t.Fatal("dry-run must default off")
	}
}

func TestParseStageFlags(t *testing.T) {
	o, err := parseStage([]string{"--kit", "/k", "--workdir", "/w", "--dry-run"}, "/x/dfirmedic")
	if err != nil || o.Kit != "/k" || o.WorkDir != "/w" || !o.DryRun {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestExeDir(t *testing.T) {
	cases := []struct{ in, want string }{
		{`C:\usb\dfirmedic.exe`, `C:\usb`}, // existing multi-segment case
		{`E:\dfirmedic.exe`, `E:\`},        // drive root
		{`/dfirmedic`, `/`},                // POSIX root
		{`/x/dfirmedic`, `/x`},             // POSIX multi-segment
		{`dfirmedic`, `.`},                 // no separator
	}
	for _, c := range cases {
		if got := exeDir(c.in); got != c.want {
			t.Errorf("exeDir(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseStageRejectsWorkDirWithSpace(t *testing.T) {
	if _, err := parseStage([]string{"--workdir", `C:\IR Cases\x`}, "/x/dfirmedic"); err == nil {
		t.Fatal("expected error for --workdir containing a space")
	}
}

func TestParseStageRejectsWorkDirWithQuote(t *testing.T) {
	if _, err := parseStage([]string{"--workdir", `C:\IR"Cases\x`}, "/x/dfirmedic"); err == nil {
		t.Fatal("expected error for --workdir containing a quote")
	}
}

func TestDefaultWorkDir(t *testing.T) {
	got := defaultWorkDir("CASE-1")
	if runtime.GOOS == "windows" {
		if got != `C:\ProgramData\DFIRMedic\CASE-1` {
			t.Fatal(got)
		}
		return
	}
	if !strings.HasSuffix(got, filepath.Join("DFIRMedic", "CASE-1")) {
		t.Fatal(got)
	}
}

func TestParseBuildRequiresCore(t *testing.T) {
	if _, err := parseBuild([]string{"--case", "C"}); err == nil {
		t.Fatal("missing required flags must error")
	}
	o, err := parseBuild([]string{"--case", "C", "--authkey", "k", "--responder-node-key", "n", "--responder-ip", "100.64.0.1",
		"--server-url", "https://x/", "--phone", "+1", "--name", "A", "--breakglass-code", "z", "--out", "/usb", "--dns", "1.1.1.1,9.9.9.9", "--rdp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(o.DNSResolvers) != 2 || !o.AllowRDP || o.OutDir != "/usb" {
		t.Fatalf("%+v", o)
	}
}

// A double-click launches the exe with no arguments. The field card tells the
// on-site person to do exactly that, so a bare launch must mean `stage`.
func TestResolveCommandDefaultsToStageOnBareLaunch(t *testing.T) {
	name, rest := resolveCommand([]string{`E:\dfirmedic.exe`})
	if name != "stage" || len(rest) != 0 {
		t.Fatalf("bare launch → %q %v, want stage []", name, rest)
	}
	name, rest = resolveCommand([]string{"dfirmedic", "verify", "--kit", "x"})
	if name != "verify" || len(rest) != 2 || rest[1] != "x" {
		t.Fatalf("explicit command → %q %v", name, rest)
	}
}

// Early failures in stage (bad flags, kit not found) used to print to stderr
// and return, which closes the console before the operator can read it.
func TestStageHoldsWindowOnEarlyFailure(t *testing.T) {
	held := 0
	orig := hold
	hold = func() { held++ }
	defer func() { hold = orig }()
	if rc := cmdStage([]string{"--kit", filepath.Join(t.TempDir(), "missing")}); rc == 0 {
		t.Fatal("expected failure for a missing kit")
	}
	if held != 1 {
		t.Fatalf("hold called %d times, want 1", held)
	}
	held = 0
	if rc := cmdStage([]string{"--no-such-flag"}); rc == 0 {
		t.Fatal("expected failure for a bad flag")
	}
	if held != 1 {
		t.Fatalf("hold called %d times on bad flag, want 1", held)
	}
}
