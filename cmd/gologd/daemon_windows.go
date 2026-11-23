//go:build windows

package main

import (
	"errors"
	"os"
)

// daemonize is not available on Windows: run golog as a service (for example
// with sc.exe, NSSM or the Task Scheduler) instead of using -D.
func daemonize() error {
	return errors.New("-D is not supported on Windows; run golog as a service")
}

// pidAlive reports whether a process with this id exists. On Windows
// os.FindProcess opens the process and fails when it does not exist.
func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	p.Release()
	return true
}
