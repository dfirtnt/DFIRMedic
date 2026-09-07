package win

import (
	"context"
	"encoding/json"
	"errors"
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

// isPhantomAdapterError reports whether err is Enable-NetAdapter's response
// to a name that no longer corresponds to a live device (Windows error 87,
// "Requested operation not supported on adapter") - seen on a real host
// 2026-09-05 when the recorded adapter list included one that had since
// disappeared. Enabling an already-Up adapter does not error at all, so
// this only ever matches the phantom case, and nothing can reach a device
// that no longer exists - it is not a rollback failure.
func isPhantomAdapterError(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "not supported on adapter")
}

// EnableAll is the counterpart to DisableAll: teardown/breakglass call it to
// give the host its connectivity back after a fail-closed watchdog trip,
// passing only the adapters FailClosed actually disabled (or, for an older
// manifest predating that record, the baseline's Up adapters) - never every
// currently-present physical adapter, since a name from either list can be
// stale by the time teardown runs. It keeps going past a phantom-adapter
// error instead of aborting the rest of the batch on the first one.
func (n Net) EnableAll(ctx context.Context, adapters []Adapter) error {
	var errs []error
	for _, a := range adapters {
		if _, err := runner.PS(ctx, n.R, fmt.Sprintf("Enable-NetAdapter -Name %s -Confirm:$false", psq(a.Name))); err != nil {
			if isPhantomAdapterError(err) {
				continue
			}
			errs = append(errs, fmt.Errorf("enable %s: %w", a.Name, err))
		}
	}
	return errors.Join(errs...)
}
