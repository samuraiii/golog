//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/samuraiii/golog/internal/golog"
)

// handleSignals stops the daemon gracefully on SIGTERM/SIGINT and re-reads the
// TLS certificate on SIGHUP.
func handleSignals(s *golog.Server) {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for sig := range ch {
			if syscall.SIGHUP == sig {
				_ = s.ReloadTLS()
				golog.ReopenLogs()
				continue
			}
			golog.Logf("golog: %v received, shutting down", sig)
			sdNotify("STOPPING=1")
			s.Shutdown()
			return
		}
	}()
}
