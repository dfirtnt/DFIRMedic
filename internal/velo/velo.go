// Package velo manages the Velociraptor client as a Windows service using
// the stock, unmodified velociraptor.exe and an external config file.
package velo

import (
	"context"
	"errors"
	"fmt"
	"strings"

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

// InstalledBinaryPath returns the executable the Velociraptor service is
// registered to run from. `service install` copies the binary to the client
// config's install_path and registers *that*; the firewall egress rule must
// name the same path or the client is silently blocked (seen 2026-09-05).
func (c Client) InstalledBinaryPath(ctx context.Context) (string, error) {
	res, err := c.R.Run(ctx, "sc.exe", "qc", ServiceName)
	if err != nil {
		return "", err
	}
	return ParseBinaryPath(res.Stdout)
}

// ParseBinaryPath pulls the executable out of `sc qc` output. The value is
// either "quoted path" args... or an unquoted path followed by " --args".
func ParseBinaryPath(scqc string) (string, error) {
	for _, l := range strings.Split(scqc, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(k) != "BINARY_PATH_NAME" {
			continue
		}
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, `"`) {
			if end := strings.Index(v[1:], `"`); end >= 0 {
				return v[1 : end+1], nil
			}
			return "", errors.New("unterminated quoted BINARY_PATH_NAME")
		}
		if i := strings.Index(v, " --"); i >= 0 {
			return v[:i], nil
		}
		return v, nil
	}
	return "", errors.New("BINARY_PATH_NAME not found in sc qc output")
}
