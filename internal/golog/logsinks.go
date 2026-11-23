// golog - log targets: stderr, a file, the system log (syslog / systemd journal
// / Windows Event Log).
//
// golog is a Go rewrite of ELOG (https://elog.psi.ch/elog) by Stefan Ritt (PSI).
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 2 or later; see COPYING.
//
// Configuration, [global]:
//
//	Log target = stderr, journal      comma separated, any of:
//	    stderr          standard error (the default; under systemd this already
//	                    ends up in the journal, without priorities)
//	    file            the file named by "Log file"
//	    syslog          syslog(3) through the local socket (unix)
//	    journal         the systemd journal, native protocol with priorities;
//	                    falls back to syslog when there is no journal (unix)
//	    eventlog        the Windows Event Log, source "golog" (Windows)
//	    system          journal on Linux with systemd, syslog on the other unix
//	                    systems, eventlog on Windows
//	Log file = <path>                 for the "file" target; reopened on SIGHUP
//	Syslog facility = daemon          daemon (default), local0 ... local7, auth, user
//
// A line is written to every target; the priority of the system log entry is
// derived from the words in the line (error/failed/cannot = error, warning/
// banned/refused = warning, everything else = info).
package golog

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Syslog priorities (the numbers are the same in the journal).
const (
	prioErr     = 3
	prioWarning = 4
	prioInfo    = 6
)

// logPriority classifies one log line.
func logPriority(line string) int {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "error"), strings.Contains(l, "failed"), strings.Contains(l, "cannot"), strings.Contains(l, "panic"):
		return prioErr
	case strings.Contains(l, "warning"), strings.Contains(l, "banned"), strings.Contains(l, "refused"), strings.Contains(l, "denied"):
		return prioWarning
	}
	return prioInfo
}

// logMessage strips the "2006-01-02 15:04:05: " / "gologd: 2006/01/02 15:04:05 "
// prefixes the stderr format carries: the system log adds its own time stamp.
func logMessage(line string) string {
	line = strings.TrimRight(line, "\r\n")
	line = strings.TrimPrefix(line, "gologd: ")
	if len(line) > 20 {
		if (line[4] == '-' && line[7] == '-' && line[10] == ' ' && line[13] == ':') ||
			(line[4] == '/' && line[7] == '/' && line[10] == ' ' && line[13] == ':') {
			line = strings.TrimLeft(strings.TrimPrefix(line[19:], ":"), " ")
		}
	}
	return line
}

// systemLogger is a log target that wants one parsed line at a time.
type systemLogger interface {
	WriteEntry(prio int, msg string)
	Close() error
}

// sysWriter adapts a systemLogger to io.Writer (one Write = one or more lines).
type sysWriter struct{ l systemLogger }

func (w sysWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if m := logMessage(line); "" != m {
			w.l.WriteEntry(logPriority(m), m)
		}
	}
	return len(p), nil
}

// reopenFile is an append-only log file that can be reopened (logrotate).
type reopenFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func openLogFile(path string) (*reopenFile, error) {
	r := &reopenFile{path: path}
	return r, r.Reopen()
}

func (r *reopenFile) Reopen() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	if r.f != nil {
		r.f.Close()
	}
	r.f = f
	return nil
}

func (r *reopenFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Write(p)
}

// fanOut writes to every target; one failing target does not stop the others.
type fanOut struct {
	mu      sync.RWMutex
	targets []io.Writer
	files   []*reopenFile
	closers []io.Closer
}

func (f *fanOut) Write(p []byte) (int, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, w := range f.targets {
		_, _ = w.Write(p)
	}
	return len(p), nil
}

var (
	logOutMu sync.RWMutex
	logOut   *fanOut
)

// configuredLogOut is the fan-out set up by SetLogTargets, nil before.
func configuredLogOut() io.Writer {
	logOutMu.RLock()
	defer logOutMu.RUnlock()
	if nil == logOut {
		return nil
	}
	return logOut
}

// ReopenLogs reopens the log file target (call on SIGHUP after logrotate).
func ReopenLogs() {
	logOutMu.RLock()
	f := logOut
	logOutMu.RUnlock()
	if nil == f {
		return
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, r := range f.files {
		if err := r.Reopen(); err != nil {
			fmt.Fprintf(os.Stderr, "golog: cannot reopen the log file %s: %v\n", r.path, err)
		}
	}
}

// CloseLogs closes the system log connections (at exit).
func CloseLogs() {
	logOutMu.Lock()
	f := logOut
	logOut = nil
	logOutMu.Unlock()
	if nil == f {
		return
	}
	for _, c := range f.closers {
		_ = c.Close()
	}
}

// SetLogTargets builds the log fan-out from a "Log target" list. file is the
// "Log file" value and facility the "Syslog facility". An empty spec keeps the
// default (standard error). A target that cannot be opened is reported and
// skipped; if none remains, standard error is used, so a log line is never lost
// to a configuration mistake.
func SetLogTargets(spec, file, facility string) error {
	spec = strings.TrimSpace(spec)
	if "" == spec {
		return nil
	}
	f := &fanOut{}
	var errs []string
	for _, name := range strings.FieldsFunc(strings.ToLower(spec), func(r rune) bool { return ',' == r || ' ' == r || ';' == r }) {
		switch name {
		case "stderr":
			f.targets = append(f.targets, os.Stderr)
		case "file":
			if "" == file {
				errs = append(errs, `"Log target = file" needs "Log file"`)
				continue
			}
			r, err := openLogFile(file)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			f.targets = append(f.targets, r)
			f.files = append(f.files, r)
			f.closers = append(f.closers, r.f)
		case "syslog", "journal", "eventlog", "system":
			l, err := openSystemLog(name, facility)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", name, err))
				continue
			}
			f.targets = append(f.targets, sysWriter{l})
			f.closers = append(f.closers, l)
		default:
			errs = append(errs, fmt.Sprintf("unknown log target %q", name))
		}
	}
	if 0 == len(f.targets) {
		f.targets = append(f.targets, os.Stderr)
	}
	logOutMu.Lock()
	old := logOut
	logOut = f
	logOutMu.Unlock()
	if old != nil {
		for _, c := range old.closers {
			_ = c.Close()
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
