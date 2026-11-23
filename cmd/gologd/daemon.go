package main

import (
	"fmt"
	"os"
	"strconv"
)

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

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
