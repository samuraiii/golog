//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// daemonize reproduces what the C program does for -D: fork, setsid, fork
// again, redirect 0/1/2 to /dev/null and let the parent exit so the supervisor
// (or the shell) sees a started service.
//
// A Go program must not keep goroutines running across the fork, so this is
// done with syscall.ForkExec of *this* executable with the -D switch removed
// and ELOG_GO_DAEMON set: the child is a fresh process that never had any
// goroutine, which is both simpler and safer than a bare fork(2) in a
// multithreaded runtime.
func daemonize() error {
	if os.Getenv("ELOG_GO_DAEMON") == "1" {
		// Already the daemon child: the parent started it with the standard
		// streams attached to the null device, nothing left to do.
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	env := append(os.Environ(), "ELOG_GO_DAEMON=1")
	// Drop -D from the child's command line so it does not fork again, and
	// strip the controlling terminal with Setsid.
	attr := &os.ProcAttr{
		Env:   env,
		Files: []*os.File{nil, nil, nil},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	attr.Files = []*os.File{devnull, devnull, devnull}
	argv := append([]string{exe}, filterArgs(os.Args[1:])...)
	if _, err := os.StartProcess(exe, argv, attr); err != nil {
		return err
	}
	devnull.Close()
	// The parent returns; main() then exits normally, which is what an init
	// script expects from a forking daemon.
	fmt.Fprintln(os.Stderr, "elogd: started in the background")
	os.Exit(0)
	return nil
}

func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return nil == p.Signal(syscall.Signal(0))
}
