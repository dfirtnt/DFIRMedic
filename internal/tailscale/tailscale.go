// Package tailscale drives the stock Tailscale Windows install through its CLI.
package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

const ExePath = `C:\Program Files\Tailscale\tailscale.exe`

type Client struct {
	R       runner.Runner
	MSIPath string
}

func (c Client) InstallMSI(ctx context.Context) error {
	_, err := c.R.Run(ctx, "msiexec.exe", "/i", c.MSIPath, "/quiet", "/norestart")
	return err
}

func (c Client) UninstallMSI(ctx context.Context) error {
	_, err := c.R.Run(ctx, "msiexec.exe", "/x", c.MSIPath, "/quiet", "/norestart")
	return err
}

// Up applies prefs and the auth key. While the host is offline the daemon
// cannot reach the control plane, so the CLI exits with a timeout; the prefs
// are persisted and the daemon will connect once a link is up. Any other
// failure (bad key, expired key) is fatal.
func (c Client) Up(ctx context.Context, authkey, hostname string) error {
	res, err := c.R.Run(ctx, ExePath, "up",
		"--authkey="+authkey, "--hostname="+hostname,
		"--accept-routes=false", "--accept-dns=false", "--timeout=15s")
	if err == nil {
		return nil
	}
	var ee *runner.ExitError
	if errors.As(err, &ee) && strings.Contains(strings.ToLower(res.Stderr), "timeout") {
		return nil
	}
	return fmt.Errorf("tailscale up: %w", err)
}

type Peer struct {
	PublicKey    string   `json:"PublicKey"`
	HostName     string   `json:"HostName"`
	Online       bool     `json:"Online"`
	TailscaleIPs []string `json:"TailscaleIPs"`
}

type Status struct {
	BackendState string
	Self         Peer
	Peers        []Peer
}

func ParseStatus(jsonText string) (Status, error) {
	var raw struct {
		BackendState string          `json:"BackendState"`
		Self         Peer            `json:"Self"`
		Peer         map[string]Peer `json:"Peer"`
	}
	if err := json.Unmarshal([]byte(jsonText), &raw); err != nil {
		return Status{}, fmt.Errorf("parse tailscale status: %w", err)
	}
	s := Status{BackendState: raw.BackendState, Self: raw.Self}
	for _, p := range raw.Peer {
		s.Peers = append(s.Peers, p)
	}
	return s, nil
}

func (c Client) Status(ctx context.Context) (Status, error) {
	res, err := c.R.Run(ctx, ExePath, "status", "--json")
	if err != nil {
		return Status{}, err
	}
	return ParseStatus(res.Stdout)
}

// ResponderOnline is the tunnel-verified condition from spec §9 step 3.
func (s Status) ResponderOnline(nodeKey string) bool {
	if nodeKey == "" {
		return false
	}
	if s.BackendState != "Running" {
		return false
	}
	for _, p := range s.Peers {
		if p.PublicKey == nodeKey && p.Online {
			return true
		}
	}
	return false
}

func (c Client) Logout(ctx context.Context) error {
	_, err := c.R.Run(ctx, ExePath, "logout")
	return err
}
