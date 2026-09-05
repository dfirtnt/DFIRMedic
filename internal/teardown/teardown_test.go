package teardown

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

func deps(t *testing.T, f *runner.Fake) Deps {
	t.Helper()
	work := t.TempDir()
	base := map[string]any{"profiles": []map[string]any{{"Name": "Domain", "Enabled": true, "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"}}}
	raw, _ := json.Marshal(base)
	os.WriteFile(filepath.Join(work, "baseline.json"), raw, 0o600)
	os.WriteFile(filepath.Join(work, "firewall-original.wfw"), []byte("wfw"), 0o600)
	log, _ := audit.Open(filepath.Join(work, "audit.jsonl"), nil)
	inc := &config.Incident{CaseID: "C1", BreakglassCodeHash: CodeHash("hunter2")}
	inc.Velociraptor = config.Velo{InstallPath: `C:\Program Files\Velociraptor\Velociraptor.exe`}
	return Deps{
		Inc: inc, WorkDir: work, R: f, Log: log, Man: &audit.Manifest{Phases: map[string]time.Time{}},
		FW: win.Firewall{R: f}, Net: win.Net{R: f}, Sys: win.Sys{R: f},
		Velo: velo.Client{R: f, ExePath: "v.exe", ConfigPath: "c.yaml"},
		Now: func() time.Time { return time.Unix(2000, 0) },
	}
}

func all(f *runner.Fake) string {
	var b strings.Builder
	for _, c := range f.Calls {
		b.WriteString(strings.Join(c, " ") + "\n")
	}
	return b.String()
}

func TestRunOrder(t *testing.T) {
	f := runner.NewFake()
	d := deps(t, f)
	if err := Run(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	a := all(f)
	order := []string{
		"sc.exe stop Velociraptor",
		"v.exe --config c.yaml service remove",
		`cmd.exe /c if exist C:\Program Files\Velociraptor rmdir /s /q C:\Program Files\Velociraptor`,
		"schtasks.exe /Delete /TN DFIRMedic-C1 /F",
		"Remove-NetFirewallRule -Group 'DFIRMedic-C1'",
		"netsh.exe advfirewall import " + filepath.Join(d.WorkDir, "firewall-original.wfw"),
		"Get-NetAdapter -Physical",
		"Set-NetFirewallProfile -Profile 'Domain' -Enabled 'True' -DefaultInboundAction 'Block' -DefaultOutboundAction 'Allow'",
	}
	last := -1
	for _, want := range order {
		i := strings.Index(a, want)
		if i < 0 {
			t.Fatalf("missing %q in:\n%s", want, a)
		}
		if i < last {
			t.Fatalf("%q out of order in:\n%s", want, a)
		}
		last = i
	}
	iRemove := strings.Index(a, "service remove")
	iDir := strings.Index(a, `cmd.exe /c if exist C:\Program Files\Velociraptor rmdir /s /q C:\Program Files\Velociraptor`)
	iTask := strings.Index(a, "schtasks.exe /Delete")
	if !(iRemove < iDir && iDir < iTask) {
		t.Fatalf("install dir must be removed after the service and before the task:\n%s", a)
	}
	if strings.Contains(a, "tailscale") || strings.Contains(a, "msiexec") {
		t.Fatalf("no Tailscale steps:\n%s", a)
	}
	for _, p := range []string{"TEARDOWN", "TEARDOWN_COMPLETE"} {
		if _, ok := d.Man.Phases[p]; !ok {
			t.Fatalf("missing phase %s", p)
		}
	}
	if _, err := os.Stat(filepath.Join(d.WorkDir, "manifest.json")); err != nil {
		t.Fatal("manifest must be saved")
	}
}

func TestRunContinuesPastFailures(t *testing.T) {
	f := runner.NewFake()
	f.Responses[f.Key("cmd.exe", "/c")] = runner.Result{ExitCode: 1, Stderr: "fatal"}
	d := deps(t, f)
	err := Run(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "delete Velociraptor install directory") {
		t.Fatalf("expected joined error naming the failed step, got %v", err)
	}
	a := all(f)
	if !strings.Contains(a, "Remove-NetFirewallRule") || !strings.Contains(a, "advfirewall import") {
		t.Fatal("firewall restore must still run after an earlier failure")
	}
}

func TestBreakglassRejectsWrongCode(t *testing.T) {
	f := runner.NewFake()
	d := deps(t, f)
	err := Breakglass(context.Background(), d, "wrong")
	if err == nil || !strings.Contains(err.Error(), "E60") {
		t.Fatalf("want E60, got %v", err)
	}
	if len(f.Calls) != 0 {
		t.Fatal("nothing may run on a rejected code")
	}
	n, _ := audit.VerifyChain(filepath.Join(d.WorkDir, "audit.jsonl"))
	if n != 1 {
		t.Fatal("the rejected attempt must be logged")
	}
}

func TestBreakglassAcceptsRightCode(t *testing.T) {
	f := runner.NewFake()
	d := deps(t, f)
	if err := Breakglass(context.Background(), d, "hunter2"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(all(f), "advfirewall import") {
		t.Fatal("teardown must run")
	}
}

func TestCodeHashFormat(t *testing.T) {
	h := CodeHash("x")
	if !strings.HasPrefix(h, "sha256:") || len(h) != 7+64 {
		t.Fatal(h)
	}
}
