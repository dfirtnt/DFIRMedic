package win

import (
	"context"
	"strings"
	"testing"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

func TestEditionID(t *testing.T) {
	f := runner.NewFake()
	f.Responses["reg.exe"] = runner.Result{Stdout: "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\r\n    EditionID    REG_SZ    Professional\r\n\r\n"}
	id, err := Sys{R: f}.EditionID(context.Background())
	if err != nil || id != "Professional" {
		t.Fatalf("%q %v", id, err)
	}
	if IsHomeEdition("Professional") || !IsHomeEdition("Core") || !IsHomeEdition("CoreSingleLanguage") {
		t.Fatal("home detection wrong")
	}
}

func TestEnableRDPAndTasks(t *testing.T) {
	f := runner.NewFake()
	s := Sys{R: f}
	s.EnableRDP(context.Background())
	s.CreateStartupTask(context.Background(), "DFIRMedic-C1", `C:\w\dfirmedic.exe`, `connect --workdir C:\w`)
	s.DeleteStartupTask(context.Background(), "DFIRMedic-C1")
	all := ""
	for _, c := range f.Calls {
		all += strings.Join(c, " ") + "\n"
	}
	for _, want := range []string{
		`reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 0 /f`,
		`schtasks.exe /Create /TN DFIRMedic-C1 /SC ONSTART /RU SYSTEM /RL HIGHEST /F /TR "C:\w\dfirmedic.exe" connect --workdir C:\w`,
		`schtasks.exe /Delete /TN DFIRMedic-C1 /F`,
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing %q in:\n%s", want, all)
		}
	}
}

func TestServiceExists(t *testing.T) {
	f := runner.NewFake()
	f.Responses[f.Key("sc.exe", "query", "Velociraptor")] = runner.Result{Stdout: "SERVICE_NAME: Velociraptor\r\n        STATE : 1  STOPPED"}
	f.Responses[f.Key("sc.exe", "query", "Nope")] = runner.Result{ExitCode: 1060, Stderr: "The specified service does not exist"}
	s := Sys{R: f}
	if ok, err := s.ServiceExists(context.Background(), "Velociraptor"); err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if ok, err := s.ServiceExists(context.Background(), "Nope"); err != nil || ok {
		t.Fatalf("%v %v", ok, err)
	}
}

func TestIsElevatedCompiles(t *testing.T) { _ = IsElevated() }
