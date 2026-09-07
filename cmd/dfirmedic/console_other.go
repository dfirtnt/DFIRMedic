//go:build !windows

package main

// hasConsole always reports true off Windows. dfirmedic only ships as a
// Windows binary (see internal/win.SvchostPath and the rest of internal/win);
// this stub exists solely so cmd/dfirmedic builds and its tests run on the
// darwin/linux dev host, where a console is always present anyway.
func hasConsole() bool { return true }
