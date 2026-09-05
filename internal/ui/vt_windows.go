//go:build windows

package ui

import "golang.org/x/sys/windows"

// EnableVT turns on ANSI escape processing for the console so colours and
// box-drawing render on Windows 10+.
func EnableVT() {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return
	}
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return
	}
	_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}
