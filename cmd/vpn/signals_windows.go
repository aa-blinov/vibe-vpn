//go:build windows

package main

import "os"

// Windows does not deliver POSIX user signals; these channels never fire.
func statsSignals() <-chan os.Signal  { return make(chan os.Signal) }
func reloadSignals() <-chan os.Signal { return make(chan os.Signal) }
