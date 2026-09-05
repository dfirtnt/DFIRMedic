package win

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

type Sys struct{ R runner.Runner }

func (s Sys) EditionID(ctx context.Context) (string, error) {
	res, err := s.R.Run(ctx, "reg.exe", "query", `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "/v", "EditionID")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "EditionID" {
			return fields[2], nil
		}
	}
	return "", errors.New("EditionID not found in reg output")
}

func IsHomeEdition(editionID string) bool {
	return strings.HasPrefix(editionID, "Core")
}

func (s Sys) EnableRDP(ctx context.Context) error {
	_, err := s.R.Run(ctx, "reg.exe", "add", `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "0", "/f")
	return err
}

func (s Sys) CreateStartupTask(ctx context.Context, name, exe, args string) error {
	_, err := s.R.Run(ctx, "schtasks.exe", "/Create", "/TN", name, "/SC", "ONSTART", "/RU", "SYSTEM", "/RL", "HIGHEST", "/F", "/TR", fmt.Sprintf(`"%s" %s`, exe, args))
	return err
}

func (s Sys) DeleteStartupTask(ctx context.Context, name string) error {
	_, err := s.R.Run(ctx, "schtasks.exe", "/Delete", "/TN", name, "/F")
	return err
}

// ServiceExists: sc query exits 1060 when the service is not installed.
func (s Sys) ServiceExists(ctx context.Context, name string) (bool, error) {
	res, err := s.R.Run(ctx, "sc.exe", "query", name)
	var ee *runner.ExitError
	if errors.As(err, &ee) && res.ExitCode == 1060 {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
