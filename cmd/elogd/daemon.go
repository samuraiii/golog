package main

import (
	"fmt"
	"os"
	"strconv"
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
		// Already the daemon child: just detach the standard streams.
		return redirectStdioToNull()
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

// filterArgs drops -D from the argument list.
func filterArgs(argv []string) []string {
	out := make([]string, 0, len(argv))
	for _, a := range argv {
		if a == "-D" {
			continue
		}
		out = append(out, a)
	}
	return out
}

func redirectStdioToNull() error {
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	for fd := 0; fd < 3; fd++ {
		if err := syscall.Dup2(int(devnull.Fd()), fd); err != nil {
			return err
		}
	}
	devnull.Close()
	return nil
}

// writePID stores the process id, and refuses to start when another elogd is
// already running - the C program only writes the file and removes it at exit
// (cleanup()), which lets two daemons fight over the same port; here a stale
// file from a dead process is overwritten, a live one is an error.
func writePID(path string) error {
	if b, err := os.ReadFile(path); err == nil {
		if pid, err := strconv.Atoi(trimSpace(string(b))); err == nil && pid > 0 && pidAlive(pid) {
			return fmt.Errorf("pid file %q belongs to running process %d", path, pid)
		}
	}
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644)
}

func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
