package stage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

// volatileTimeout bounds each capture command. netstat -b is the slow one.
const volatileTimeout = 60 * time.Second

// VolatileCapture describes one file under <workdir>\volatile\. Error is set
// when the command failed; whatever output it produced is written regardless.
type VolatileCapture struct {
	SHA256 string `json:"sha256"`
	Error  string `json:"error,omitempty"`
}

type volatileCmd struct {
	File string
	Argv []string
}

const processScript = "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate,SessionId | ConvertTo-Json -Compress"

// volatileCommands is the pre-staging evidence dump (spec §8.2): state that
// staging destroys or pollutes, from Windows built-ins only, so it works even
// if Defender has eaten a payload tool. Persistent artifacts (autoruns,
// prefetch, tasks) are deliberately absent — they survive staging and are
// collected over the tunnel.
var volatileCommands = []volatileCmd{
	{"processes.json", []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", processScript}},
	{"tasklist.csv", []string{"tasklist.exe", "/v", "/fo", "csv"}},
	{"netstat.txt", []string{"netstat.exe", "-anob"}},
	{"dnscache.txt", []string{"ipconfig.exe", "/displaydns"}},
	{"ipconfig.txt", []string{"ipconfig.exe", "/all"}},
	{"arp.txt", []string{"arp.exe", "-a"}},
	{"routes.txt", []string{"route.exe", "print"}},
	{"sessions.txt", []string{"query.exe", "user"}},
	{"drivers.csv", []string{"driverquery.exe", "/v", "/fo", "csv"}},
}

// CaptureVolatile runs every volatileCommands entry and writes its stdout to
// dir. A failing command is recorded, not fatal: `query user` is absent on
// Home editions and netstat -b can time out, and neither is a reason to halt
// an incident. Only filesystem failures return an error.
func CaptureVolatile(ctx context.Context, r runner.Runner, dir string) (map[string]VolatileCapture, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	out := make(map[string]VolatileCapture, len(volatileCommands))
	for _, c := range volatileCommands {
		cctx, cancel := context.WithTimeout(ctx, volatileTimeout)
		res, runErr := r.Run(cctx, c.Argv[0], c.Argv[1:]...)
		cancel()
		if err := os.WriteFile(filepath.Join(dir, c.File), []byte(res.Stdout), 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", c.File, err)
		}
		sum := sha256.Sum256([]byte(res.Stdout))
		entry := VolatileCapture{SHA256: hex.EncodeToString(sum[:])}
		if runErr != nil {
			entry.Error = runErr.Error()
		}
		out[c.File] = entry
	}
	return out, nil
}
