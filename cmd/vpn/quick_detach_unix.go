//go:build !windows

package main

import "syscall"

// detachAttr returns process attributes that detach the daemon from the
// controlling terminal so it keeps running after the quick command exits.
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
