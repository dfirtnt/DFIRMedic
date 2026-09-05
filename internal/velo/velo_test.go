package velo

import (
	"context"
	"strings"
	"testing"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

func joined(f *runner.Fake) string {
	var b strings.Builder
	for _, c := range f.Calls {
		b.WriteString(strings.Join(c, " ") + "\n")
	}
	return b.String()
}

func TestInstallServiceStopsAndSetsManual(t *testing.T) {
	f := runner.NewFake()
	c := Client{R: f, ExePath: `C:\w\payload\velociraptor.exe`, ConfigPath: `C:\w\payload\velociraptor.client.yaml`}
	if err := c.InstallService(context.Background()); err != nil {
		t.Fatal(err)
	}
	all := joined(f)
	for i, want := range []string{
		`C:\w\payload\velociraptor.exe --config C:\w\payload\velociraptor.client.yaml service install`,
		`sc.exe stop Velociraptor`,
		`sc.exe config Velociraptor start= demand`,
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("step %d missing %q in:\n%s", i, want, all)
		}
	}
	if strings.Index(all, "service install") > strings.Index(all, "sc.exe stop") {
		t.Fatal("must install before stopping")
	}
}

func TestStopToleratesNotRunning(t *testing.T) {
	f := runner.NewFake()
	f.Responses[f.Key("sc.exe", "stop", ServiceName)] = runner.Result{ExitCode: 1062, Stderr: "The service has not been started."}
	if err := (Client{R: f}).Stop(context.Background()); err != nil {
		t.Fatalf("1062 must be tolerated: %v", err)
	}
	f.Responses[f.Key("sc.exe", "stop", ServiceName)] = runner.Result{ExitCode: 5, Stderr: "Access is denied."}
	if err := (Client{R: f}).Stop(context.Background()); err == nil {
		t.Fatal("other errors must propagate")
	}
}

func TestStartAndRemove(t *testing.T) {
	f := runner.NewFake()
	c := Client{R: f, ExePath: "v.exe", ConfigPath: "c.yaml"}
	c.Start(context.Background())
	c.RemoveService(context.Background())
	all := joined(f)
	if !strings.Contains(all, "sc.exe start Velociraptor") || !strings.Contains(all, "v.exe --config c.yaml service remove") {
		t.Fatal(all)
	}
}
