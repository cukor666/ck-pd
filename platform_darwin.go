//go:build darwin

package main

func isWindows() bool      { return false }
func isDarwin() bool       { return true }
func isLinux() bool        { return false }
func platformName() string { return "macOS" }
