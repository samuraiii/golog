//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
)

func serviceMode() bool { return false }

func runAsService() error { return errors.New("not a Windows service") }

func serviceCommand(argv []string) int {
	fmt.Fprintln(os.Stderr, "gologd: the service command exists on Windows only; see docs/service/ for systemd, OpenRC and sysv files")
	return 2
}
