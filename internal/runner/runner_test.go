package runner

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
)

func TestFakeRecordsAndMatchesPrefix(t *testing.T) {
	f := NewFake()
	f.Responses[f.Key("tailscale.exe", "status")] = Result{Stdout: `{"BackendState":"Running"}`}
	f.Responses[f.Key("tailscale.exe", "status", "--json")] = Result{Stdout: `{"BackendState":"NeedsLogin"}`}
	r, err := f.Run(context.Background(), "tailscale.exe", "status", "--json")
	if err != nil || r.Stdout != `{"BackendState":"NeedsLogin"}` {
		t.Fatalf("longest prefix should win: %+v %v", r, err)
	}
	if len(f.Calls) != 1 || f.Calls[0][0] != "tailscale.exe" {
		t.Fatalf("call not recorded: %v", f.Calls)
	}
}

func TestFakeReturnsConfiguredError(t *testing.T) {
	f := NewFake()
	f.Errors[f.Key("msiexec.exe")] = errors.New("boom")
	if _, err := f.Run(context.Background(), "msiexec.exe", "/i", "x.msi"); err == nil {
		t.Fatal("expected error")
	}
}

func TestExecRecordsToAudit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	log, _ := audit.Open(p, nil)
	m := &audit.Manifest{}
	r := NewExec(log, m)
	res, err := r.Run(context.Background(), "/bin/sh", "-c", "echo hi; exit 3")
	var ee *ExitError
	if !errors.As(err, &ee) || res.ExitCode != 3 || res.Stdout != "hi\n" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(m.Commands) != 1 || m.Commands[0].ExitCode != 3 {
		t.Fatalf("manifest not updated: %+v", m.Commands)
	}
	if n, err := audit.VerifyChain(p); err != nil || n != 1 {
		t.Fatalf("audit not written: n=%d err=%v", n, err)
	}
}

func TestDryRunNeverExecutes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	log, _ := audit.Open(p, nil)
	r := NewDryRun(log)
	res, err := r.Run(context.Background(), "definitely-not-a-binary", "--x")
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("dry run must succeed without executing: %+v %v", res, err)
	}
	if n, _ := audit.VerifyChain(p); n != 1 {
		t.Fatal("dry run must still audit")
	}
}

func TestPSHelperBuildsArgv(t *testing.T) {
	f := NewFake()
	PS(context.Background(), f, "Get-Date")
	want := []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Get-Date"}
	if len(f.Calls[0]) != len(want) {
		t.Fatalf("argv %v", f.Calls[0])
	}
	for i := range want {
		if f.Calls[0][i] != want[i] {
			t.Fatalf("argv %v", f.Calls[0])
		}
	}
}

func TestFakeDoesNotMatchAcrossWordBoundary(t *testing.T) {
	f := NewFake()
	f.Responses[f.Key("tailscale.exe", "status")] = Result{Stdout: "SHORT"}
	res, _ := f.Run(context.Background(), "tailscale.exe", "statusjson-report")
	if res.Stdout == "SHORT" {
		t.Fatal("must not match across a word boundary")
	}
}

func TestExecWrapsSignalKilledProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	log, _ := audit.Open(p, nil)
	r := NewExec(log, &audit.Manifest{})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := r.Run(ctx, "/bin/sh", "-c", "sleep 5")
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("signal-killed process must still be wrapped in *ExitError, got %T: %v", err, err)
	}
}
