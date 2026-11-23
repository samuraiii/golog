//go:build unix

package main

import (
	"net"
	"os"
	"strconv"
	"time"

	"github.com/samuraiii/golog/internal/golog"
)

// sdNotify sends a message to systemd's notification socket (NOTIFY_SOCKET)
// and does nothing when the daemon was not started by systemd.
func sdNotify(msg string) {
	path := os.Getenv("NOTIFY_SOCKET")
	if "" == path {
		return
	}
	if '@' == path[0] {
		path = "\x00" + path[1:] // abstract socket
	}
	c, err := net.Dial("unixgram", path)
	if err != nil {
		return
	}
	defer c.Close()
	_, _ = c.Write([]byte(msg))
}

// setupSystemd makes golog a Type=notify service: READY=1 when listening,
// STOPPING=1 at shutdown and WATCHDOG=1 pings when WatchdogSec is configured.
func setupSystemd() {
	if "" == os.Getenv("NOTIFY_SOCKET") {
		return
	}
	golog.ReadyHook = func() {
		sdNotify("READY=1\nSTATUS=serving")
		if us, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64); err == nil && us > 0 {
			go func() {
				t := time.NewTicker(time.Duration(us) * time.Microsecond / 2)
				defer t.Stop()
				for range t.C {
					sdNotify("WATCHDOG=1")
				}
			}()
		}
	}
}
