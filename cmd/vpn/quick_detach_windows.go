//go:build windows

package main

import "syscall"

// detachAttr returns process attributes that detach the daemon so it keeps
// running after the quick command exits (DETACHED_PROCESS + new process group).
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008, // DETACHED_PROCESS
	}
}
