//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samuraiii/golog/internal/golog"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName = "golog"
	serviceDesc = "golog logbook server (ELOG compatible)"
)

// serviceMode reports whether the process was started by the Service Control
// Manager, in which case main must hand control to svc.Run immediately.
func serviceMode() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type serviceHandler struct{ done chan error }

// Execute is the service body: it starts the daemon, reports RUNNING and stops
// the daemon on a Stop or Shutdown request.
func (h *serviceHandler) Execute(args []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	st <- svc.Status{State: svc.StartPending, WaitHint: 30000}
	h.done = make(chan error, 1)
	go func() { h.done <- run(os.Args[1:]) }()
	st <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case err := <-h.done:
			if nil != err {
				golog_log("service: daemon ended: %v", err)
				return false, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending, WaitHint: 20000}
				stopCurrent()
				select {
				case <-h.done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		}
	}
}

func golog_log(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }

// runAsService enters the service dispatcher; it returns when the service ends.
func runAsService() error { return svc.Run(serviceName, &serviceHandler{}) }

// serviceCommand handles "gologd service install|remove|start|stop|status [args]".
// Arguments after "install" are the command line the service will be started
// with (for example: -c C:\golog\golog.cfg -l C:\golog\golog.log).
func serviceCommand(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gologd service install [daemon args]|remove|start|stop|status")
		return 2
	}
	m, err := mgr.Connect()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gologd: cannot reach the service manager (run as Administrator):", err)
		return 1
	}
	defer m.Disconnect()
	switch strings.ToLower(argv[0]) {
	case "install":
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, "gologd:", err)
			return 1
		}
		exe, _ = filepath.Abs(exe)
		s, err := m.CreateService(serviceName, exe, mgr.Config{
			DisplayName:  "golog",
			Description:  serviceDesc,
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
		}, argv[1:]...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gologd: install:", err)
			return 1
		}
		defer s.Close()
		// Restart after a crash: 5 s, 30 s, then 5 min; reset the counter after a day.
		_ = s.SetRecoveryActions([]mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 5 * time.Minute},
		}, 86400)
		if err := golog.InstallEventSource(); err != nil {
			fmt.Fprintln(os.Stderr, "gologd: warning: event log source not registered:", err)
		}
		fmt.Println("service installed; start it with: gologd service start")
		return 0
	case "remove":
		s, err := m.OpenService(serviceName)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gologd:", err)
			return 1
		}
		defer s.Close()
		if err := s.Delete(); err != nil {
			fmt.Fprintln(os.Stderr, "gologd: remove:", err)
			return 1
		}
		_ = golog.RemoveEventSource()
		fmt.Println("service removed")
		return 0
	case "start", "stop", "status":
		s, err := m.OpenService(serviceName)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gologd:", err)
			return 1
		}
		defer s.Close()
		switch strings.ToLower(argv[0]) {
		case "start":
			if err := s.Start(); err != nil {
				fmt.Fprintln(os.Stderr, "gologd: start:", err)
				return 1
			}
			fmt.Println("started")
		case "stop":
			if _, err := s.Control(svc.Stop); err != nil {
				fmt.Fprintln(os.Stderr, "gologd: stop:", err)
				return 1
			}
			fmt.Println("stop requested")
		default:
			q, err := s.Query()
			if err != nil {
				fmt.Fprintln(os.Stderr, "gologd:", err)
				return 1
			}
			names := map[svc.State]string{svc.Stopped: "stopped", svc.StartPending: "start pending", svc.StopPending: "stop pending", svc.Running: "running"}
			fmt.Println(names[q.State])
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "gologd: unknown service command", argv[0])
	return 2
}
