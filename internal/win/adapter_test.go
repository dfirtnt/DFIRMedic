package win

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

func TestAnyPhysicalUp(t *testing.T) {
	f := runner.NewFake()
	f.Responses["powershell.exe"] = runner.Result{Stdout: `[{"Name":"Wi-Fi","InterfaceDescription":"Intel","Status":"Up"},{"Name":"Ethernet","InterfaceDescription":"Realtek","Status":"Disconnected"}]`}
	up, ads, err := Net{R: f}.AnyPhysicalUp(context.Background())
	if err != nil || !up || len(ads) != 1 || ads[0].Name != "Wi-Fi" {
		t.Fatalf("up=%v ads=%+v err=%v", up, ads, err)
	}
}

func TestAnyPhysicalUpSingleObject(t *testing.T) {
	f := runner.NewFake()
	f.Responses["powershell.exe"] = runner.Result{Stdout: `{"Name":"Wi-Fi","InterfaceDescription":"Intel","Status":"Disconnected"}`}
	up, _, err := Net{R: f}.AnyPhysicalUp(context.Background())
	if err != nil || up {
		t.Fatalf("up=%v err=%v", up, err)
	}
}

func TestDisableAll(t *testing.T) {
	f := runner.NewFake()
	err := Net{R: f}.DisableAll(context.Background(), []Adapter{{Name: "Wi-Fi"}, {Name: "Ethernet 2"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Calls) != 2 || f.Calls[1][len(f.Calls[1])-1] != "Disable-NetAdapter -Name 'Ethernet 2' -Confirm:$false" {
		t.Fatalf("%v", f.Calls)
	}
}

func TestEnableAll(t *testing.T) {
	f := runner.NewFake()
	err := Net{R: f}.EnableAll(context.Background(), []Adapter{{Name: "Wi-Fi"}, {Name: "Ethernet 2"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Calls) != 2 || f.Calls[0][len(f.Calls[0])-1] != "Enable-NetAdapter -Name 'Wi-Fi' -Confirm:$false" ||
		f.Calls[1][len(f.Calls[1])-1] != "Enable-NetAdapter -Name 'Ethernet 2' -Confirm:$false" {
		t.Fatalf("%v", f.Calls)
	}
}

// TestEnableAllSkipsPhantomAdapterButReturnsOtherErrors pins the real-host
// fix (2026-09-05: "enable Wi-Fi 5: ... Requested operation not supported on
// adapter", a name that no longer resolved to a live device): that specific
// error must not abort the batch or surface as a failure, but a genuinely
// different error on another adapter still must, and every adapter is still
// attempted regardless of an earlier one's outcome.
func TestEnableAllSkipsPhantomAdapterButReturnsOtherErrors(t *testing.T) {
	f := runner.NewFake()
	f.Errors[f.Key("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"Enable-NetAdapter -Name 'Phantom' -Confirm:$false")] = &runner.ExitError{Result: runner.Result{
		ExitCode: 1, Stderr: "Enable-NetAdapter : Requested operation not supported on adapter",
	}}
	f.Errors[f.Key("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"Enable-NetAdapter -Name 'Broken' -Confirm:$false")] = errors.New("some other real failure")

	err := Net{R: f}.EnableAll(context.Background(), []Adapter{{Name: "Phantom"}, {Name: "Wi-Fi"}, {Name: "Broken"}})
	if err == nil || !strings.Contains(err.Error(), "some other real failure") {
		t.Fatalf("a non-phantom error must still be reported, got %v", err)
	}
	if strings.Contains(err.Error(), "not supported on adapter") {
		t.Fatalf("a phantom-adapter error must be swallowed, got %v", err)
	}
	if len(f.Calls) != 3 {
		t.Fatalf("every adapter must still be attempted despite the phantom failure, got %d calls: %v", len(f.Calls), f.Calls)
	}
}
