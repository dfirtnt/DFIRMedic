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

func TestParseBinaryPathQuoted(t *testing.T) {
	out := "[SC] QueryServiceConfig SUCCESS\r\n\r\nSERVICE_NAME: Velociraptor\r\n        TYPE               : 10  WIN32_OWN_PROCESS\r\n        BINARY_PATH_NAME   : \"C:\\Program Files\\Velociraptor\\Velociraptor.exe\" --config \"C:\\Program Files\\Velociraptor\\client.config.yaml\" service run\r\n        DISPLAY_NAME       : Velociraptor\r\n"
	got, err := ParseBinaryPath(out)
	if err != nil {
		t.Fatal(err)
	}
	if got != `C:\Program Files\Velociraptor\Velociraptor.exe` {
		t.Fatalf("got %q", got)
	}
}

func TestParseBinaryPathUnquoted(t *testing.T) {
	got, err := ParseBinaryPath("        BINARY_PATH_NAME   : C:\\Velo\\Velociraptor.exe --config c.yaml service run\r\n")
	if err != nil || got != `C:\Velo\Velociraptor.exe` {
		t.Fatalf("got %q err %v", got, err)
	}
	if _, err := ParseBinaryPath("SERVICE_NAME: x\r\n"); err == nil {
		t.Fatal("expected error when BINARY_PATH_NAME absent")
	}
}

func TestInstalledBinaryPathRunsScQc(t *testing.T) {
	f := runner.NewFake()
	f.Responses[f.Key("sc.exe", "qc", "Velociraptor")] = runner.Result{Stdout: "        BINARY_PATH_NAME   : \"C:\\P\\Velociraptor.exe\" service run\r\n"}
	got, err := Client{R: f}.InstalledBinaryPath(context.Background())
	if err != nil || got != `C:\P\Velociraptor.exe` {
		t.Fatalf("got %q err %v", got, err)
	}
}
