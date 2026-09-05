//go:build !windows

package win

// IsElevated is always true off Windows so tests and dry runs proceed.
func IsElevated() bool { return true }
