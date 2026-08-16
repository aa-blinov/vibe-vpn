//go:build linux

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// statsSignals returns a channel that fires on SIGUSR1 (on-demand stats dump).
func statsSignals() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	return ch
}

// reloadSignals returns a channel that fires on SIGHUP (config reload).
func reloadSignals() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	return ch
}
