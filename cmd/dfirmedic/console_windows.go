//go:build windows

package main

import "golang.org/x/sys/windows"

// hasConsole reports whether stdout is attached to an interactive console.
// The reboot-resume path runs `connect` from a SYSTEM-owned scheduled task
// with no console at all; hold()'s "press Ctrl-C" prompt would then block
// forever instead of letting the process exit with its real status.
func hasConsole() bool {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return false
	}
	var mode uint32
	return windows.GetConsoleMode(h, &mode) == nil
}
