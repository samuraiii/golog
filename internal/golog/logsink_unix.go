//go:build !windows

package golog

import (
	"fmt"
	"log/syslog"
	"net"
	"os"
	"strings"
	"sync"
)

const journalSocket = "/run/systemd/journal/socket"

// journalLogger speaks the native journal protocol, which carries the priority
// and the identifier as fields.
type journalLogger struct {
	mu   sync.Mutex
	conn net.Conn
}

func (j *journalLogger) WriteEntry(prio int, msg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	// A single-line message needs no binary framing: FIELD=value\n.
	msg = strings.ReplaceAll(msg, "\n", " ")
	_, _ = fmt.Fprintf(j.conn, "PRIORITY=%d\nSYSLOG_IDENTIFIER=gologd\nMESSAGE=%s\n", prio, msg)
}

func (j *journalLogger) Close() error { return j.conn.Close() }

// syslogLogger is the classic syslog(3) route.
type syslogLogger struct{ w *syslog.Writer }

func (s syslogLogger) WriteEntry(prio int, msg string) {
	switch prio {
	case prioErr:
		_ = s.w.Err(msg)
	case prioWarning:
		_ = s.w.Warning(msg)
	default:
		_ = s.w.Info(msg)
	}
}

func (s syslogLogger) Close() error { return s.w.Close() }

func syslogFacility(name string) syslog.Priority {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "auth":
		return syslog.LOG_AUTH
	case "user":
		return syslog.LOG_USER
	case "local0":
		return syslog.LOG_LOCAL0
	case "local1":
		return syslog.LOG_LOCAL1
	case "local2":
		return syslog.LOG_LOCAL2
	case "local3":
		return syslog.LOG_LOCAL3
	case "local4":
		return syslog.LOG_LOCAL4
	case "local5":
		return syslog.LOG_LOCAL5
	case "local6":
		return syslog.LOG_LOCAL6
	case "local7":
		return syslog.LOG_LOCAL7
	}
	return syslog.LOG_DAEMON
}

func openSyslog(facility string) (systemLogger, error) {
	w, err := syslog.New(syslogFacility(facility)|syslog.LOG_INFO, "gologd")
	if err != nil {
		return nil, err
	}
	return syslogLogger{w}, nil
}

func openJournal() (systemLogger, error) {
	if _, err := os.Stat(journalSocket); err != nil {
		return nil, err
	}
	c, err := net.Dial("unixgram", journalSocket)
	if err != nil {
		return nil, err
	}
	return &journalLogger{conn: c}, nil
}

// openSystemLog opens the named system log target.
func openSystemLog(name, facility string) (systemLogger, error) {
	switch name {
	case "journal":
		if l, err := openJournal(); err == nil {
			return l, nil
		}
		return openSyslog(facility) // no journal: syslog
	case "syslog":
		return openSyslog(facility)
	case "system":
		if l, err := openJournal(); err == nil {
			return l, nil
		}
		return openSyslog(facility)
	}
	return nil, fmt.Errorf("log target %q exists on Windows only", name)
}
