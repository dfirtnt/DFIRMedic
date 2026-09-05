package win

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

type Adapter struct {
	Name                 string
	InterfaceDescription string
	Status               string
}

type Net struct{ R runner.Runner }

func (n Net) PhysicalAdapters(ctx context.Context) ([]Adapter, error) {
	res, err := runner.PS(ctx, n.R, "Get-NetAdapter -Physical | Select-Object Name,InterfaceDescription,Status | ConvertTo-Json -Compress")
	if err != nil {
		return nil, err
	}
	txt := strings.TrimSpace(res.Stdout)
	if txt == "" {
		return nil, nil
	}
	if strings.HasPrefix(txt, "{") {
		txt = "[" + txt + "]"
	}
	var out []Adapter
	if err := json.Unmarshal([]byte(txt), &out); err != nil {
		return nil, fmt.Errorf("parse Get-NetAdapter: %w", err)
	}
	return out, nil
}

// AnyPhysicalUp returns true and the list of adapters whose Status is "Up".
func (n Net) AnyPhysicalUp(ctx context.Context) (bool, []Adapter, error) {
	all, err := n.PhysicalAdapters(ctx)
	if err != nil {
		return false, nil, err
	}
	var up []Adapter
	for _, a := range all {
		if strings.EqualFold(a.Status, "Up") {
			up = append(up, a)
		}
	}
	return len(up) > 0, up, nil
}

func (n Net) DisableAll(ctx context.Context, adapters []Adapter) error {
	for _, a := range adapters {
		if _, err := runner.PS(ctx, n.R, fmt.Sprintf("Disable-NetAdapter -Name %s -Confirm:$false", psq(a.Name))); err != nil {
			return fmt.Errorf("disable %s: %w", a.Name, err)
		}
	}
	return nil
}
