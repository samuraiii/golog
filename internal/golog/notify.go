//go:build unix

package golog

// ---------------------------------------------------------------------------
// systemd socket activation and the Type=notify readiness protocol.
// ---------------------------------------------------------------------------
//
// The C elogd knows systemd in exactly one place: under HAVE_SYSTEMD it calls
// sd_notify(0, "READY=1") from the accept loop and sd_notify(0, "STOPPING=1")
// when it is killed. gologd does the same without linking libsystemd: the
// protocol is one datagram to the socket named by NOTIFY_SOCKET, which the
// standard library can send.
//
// Socket activation (LISTEN_FDS/LISTEN_PID) is supported as well, so a unit can
// own the socket and keep the port open across a restart of the binary - the
// closest analogue of the "the daemon is never down" property that the C
// version tries to get from a reload.

import (
	"net"
	"os"
	"strconv"
	"strings"
)

// The three environment variables of the systemd(5) interface.
const (
	NotifySocketEnv = "NOTIFY_SOCKET"
	ListenPIDEnv    = "LISTEN_PID"
	ListenFDsEnv    = "LISTEN_FDS"
)

// SdNotify sends one notification datagram to the socket of the calling service.
// It returns nil when NOTIFY_SOCKET is unset, because a daemon started from a
// shell simply has nobody to notify; a real write error is reported so that a
// unit with a wrong Type= shows something in the log.
func SdNotify(state string) error {
	addr := os.Getenv(NotifySocketEnv)
	if addr == "" {
		return nil
	}
	// systemd passes an abstract socket name as "@name" and, in newer
	// versions, a file system path (optionally with a "file:" prefix). The
	// vsock form of a container inside a VM cannot be reached from here and is
	// ignored rather than treated as a failure.
	switch {
	case strings.HasPrefix(addr, "@"):
		addr = "\x00" + addr[1:] // abstract namespace
	case strings.HasPrefix(addr, "file:"):
		addr = addr[len("file:"):]
	case strings.HasPrefix(addr, "/"):
	default:
		return nil
	}
	c, err := net.Dial("unix", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte(state))
	return err
}

// NotifyReady announces that the daemon is accepting requests
// (systemd Type=notify).
func NotifyReady() { notifyQuiet("READY=1") }

// NotifyStopping announces that the daemon is about to exit.
func NotifyStopping() { notifyQuiet("STOPPING=1") }

// NotifyReloading announces a configuration reload in progress.
func NotifyReloading() { notifyQuiet("RELOADING=1") }

// NotifyStatus publishes one status line, which "systemctl status" shows.
func NotifyStatus(text string) { notifyQuiet("STATUS=" + oneLine(text)) }

// NotifyWatchdog answers the watchdog of a unit with WatchdogSec= set. A unit
// without one just gets an unused datagram, which systemd ignores.
func NotifyWatchdog() { notifyQuiet("WATCHDOG=1") }

// notifyQuiet logs instead of returning an error: readiness and status messages
// are cosmetic, a daemon must not fail because systemd was not listening.
func notifyQuiet(state string) {
	if err := SdNotify(state); err != nil {
		Logf("systemd notify %q: %v", state, err)
	}
}

// oneLine flattens a status message: the protocol is line oriented.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// ActivatedListeners returns the sockets systemd passed over exec(3) when the
// unit uses Socket= with Accept=no; the first becomes the main listener, any
// further one an additional listener. It returns nil when the process was not
// socket-activated.
//
// The descriptors arrive as fd 3, 4, ... with LISTEN_FDS counting them and
// LISTEN_PID naming the process they belong to; checking the pid is what stops a
// re-executed child (the -D mode re-executes itself) from taking over sockets it
// was not meant to own.
func ActivatedListeners() []net.Listener {
	if os.Getpid() != envInt(ListenPIDEnv, 0) {
		return nil
	}
	n := envInt(ListenFDsEnv, 0)
	if n <= 0 {
		return nil
	}
	const fdBase = 3
	var out []net.Listener
	for i := 0; i < n; i++ {
		f := os.NewFile(uintptr(fdBase+i), "golog-listen")
		if f == nil {
			continue
		}
		// FileListener dups the descriptor, so the File can be closed right
		// after and the listener keeps its own copy.
		ln, err := net.FileListener(f)
		f.Close()
		if err != nil {
			Logf("socket activation: fd %d: %v", fdBase+i, err)
			continue
		}
		out = append(out, ln)
	}
	if len(out) > 0 {
		Logf("socket activation: %d socket(s) taken over from the service manager", len(out))
	}
	return out
}

// envInt reads one decimal environment variable.
func envInt(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// IsSocketActivated reports whether the process was started by socket
// activation, which the start-up banner uses.
func IsSocketActivated() bool {
	return os.Getenv(ListenFDsEnv) != "" && os.Getpid() == envInt(ListenPIDEnv, 0)
}
