package win

import (
	"context"
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
