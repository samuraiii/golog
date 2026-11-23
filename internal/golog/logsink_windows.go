//go:build windows

package golog

import (
	"fmt"

	"golang.org/x/sys/windows/svc/eventlog"
)

// EventSource is the Windows Event Log source name golog writes under.
const EventSource = "golog"

type eventLogger struct{ l *eventlog.Log }

func (e eventLogger) WriteEntry(prio int, msg string) {
	// Event id 1 = information, 2 = warning, 3 = error; the generic message
	// resource of eventcreate.exe (registered by InstallEventSource) carries it.
	switch prio {
	case prioErr:
		_ = e.l.Error(3, msg)
	case prioWarning:
		_ = e.l.Warning(2, msg)
	default:
		_ = e.l.Info(1, msg)
	}
}

func (e eventLogger) Close() error { return e.l.Close() }

// InstallEventSource registers "golog" as an Event Log source (needs
// Administrator; "gologd service install" calls it).
func InstallEventSource() error {
	return eventlog.InstallAsEventCreate(EventSource, eventlog.Error|eventlog.Warning|eventlog.Info)
}

// RemoveEventSource undoes InstallEventSource.
func RemoveEventSource() error { return eventlog.Remove(EventSource) }

// openSystemLog opens the Windows Event Log; "system", "eventlog" and
// "journal" all mean it here, "syslog" is not available.
func openSystemLog(name, facility string) (systemLogger, error) {
	switch name {
	case "eventlog", "system", "journal":
		l, err := eventlog.Open(EventSource)
		if err != nil {
			return nil, fmt.Errorf("event source %q is not registered (run \"gologd service install\" as Administrator): %w", EventSource, err)
		}
		return eventLogger{l}, nil
	}
	return nil, fmt.Errorf("log target %q is not available on Windows", name)
}
