// Package velo manages the Velociraptor client as a Windows service using
// the stock, unmodified velociraptor.exe and an external config file.
package velo

import (
	"context"
	"errors"
	"fmt"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

const ServiceName = "Velociraptor"

type Client struct {
	R          runner.Runner
	ExePath    string
	ConfigPath string
}

// InstallService registers the service (which also starts it), then stops it
// and sets Manual start so it stays down until the tunnel is verified.
func (c Client) InstallService(ctx context.Context) error {
	if _, err := c.R.Run(ctx, c.ExePath, "--config", c.ConfigPath, "service", "install"); err != nil {
		return fmt.Errorf("velociraptor service install: %w", err)
	}
	if err := c.Stop(ctx); err != nil {
		return err
	}
	if _, err := c.R.Run(ctx, "sc.exe", "config", ServiceName, "start=", "demand"); err != nil {
		return fmt.Errorf("set Velociraptor to manual start: %w", err)
	}
	return nil
}

func (c Client) Start(ctx context.Context) error {
	_, err := c.R.Run(ctx, "sc.exe", "start", ServiceName)
	return err
}

// Stop tolerates 1062 (ERROR_SERVICE_NOT_ACTIVE).
func (c Client) Stop(ctx context.Context) error {
	res, err := c.R.Run(ctx, "sc.exe", "stop", ServiceName)
	var ee *runner.ExitError
	if errors.As(err, &ee) && res.ExitCode == 1062 {
		return nil
	}
	return err
}

func (c Client) RemoveService(ctx context.Context) error {
	_, err := c.R.Run(ctx, c.ExePath, "--config", c.ConfigPath, "service", "remove")
	return err
}
