//go:build linux

package main

func isWindows() bool      { return false }
func isDarwin() bool       { return false }
func isLinux() bool        { return true }
func platformName() string { return "Linux" }
