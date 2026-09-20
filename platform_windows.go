//go:build windows

package main

func isWindows() bool  { return true }
func isDarwin() bool   { return false }
func isLinux() bool    { return false }
func platformName() string { return "Windows" }
